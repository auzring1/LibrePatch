package inventory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// Persistent state keys.
const (
	snapSoftware = "software"
	metaSWRev    = "sw_rev"
	metaUsersRev = "users_rev"
	metaUsersFP  = "users_fp"
)

// Store is the slice of the agent's state database the manager needs.
type Store interface {
	LoadSnapshot(name string) (map[string][]byte, error)
	SaveSnapshot(name string, snap map[string][]byte) error
	GetUint(key string) uint64
	SetUint(key string, v uint64) error
	GetMeta(key string) []byte
	SetMeta(key string, val []byte) error
	NextSeq() (uint64, error)
}

// Sender sends messages on the agent stream.
type Sender interface {
	Send(*agentv1.ConnectRequest) error
}

// ErrBusy means a report is still awaiting acknowledgement.
var ErrBusy = errors.New("inventory report awaiting acknowledgement")

// Manager turns scans into acknowledged, revisioned reports for the server.
//
// Protocol (PROTOCOL §6): the agent persists, per section, the revision and
// snapshot the server last acknowledged. A delta is computed against that
// snapshot and carries base_rev = acknowledged rev, rev = base_rev + 1. The
// persisted state only advances when the server's Ack arrives, so a lost
// connection can never leave agent and server disagreeing silently: after
// reconnect the revisions in Hello differ and the server asks for a resync.
type Manager struct {
	Collector Collector
	Store     Store
	Log       *slog.Logger

	pending map[uint64]func() // ack seq -> commit
}

// SyncOptions selects full snapshots.
type SyncOptions struct {
	FullSoftware bool
	FullUsers    bool
}

// SoftwareRev / UsersRev are the acknowledged revisions, sent in Hello.
func (m *Manager) SoftwareRev() uint64 { return m.Store.GetUint(metaSWRev) }
func (m *Manager) UsersRev() uint64    { return m.Store.GetUint(metaUsersRev) }

// ResetPending forgets unacknowledged reports (call at the start of a stream:
// their acks can no longer arrive).
func (m *Manager) ResetPending() { m.pending = map[uint64]func(){} }

// Busy reports whether a report is awaiting its Ack.
func (m *Manager) Busy() bool { return len(m.pending) > 0 }

// Ack commits the report with the given sequence number, if it is ours.
func (m *Manager) Ack(seq uint64) bool {
	commit, ok := m.pending[seq]
	if !ok {
		return false
	}
	delete(m.pending, seq)
	commit()
	return true
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

// Sync scans and sends whatever changed.
func (m *Manager) Sync(ctx context.Context, snd Sender, opt SyncOptions) error {
	if m.pending == nil {
		m.pending = map[uint64]func(){}
	}
	if m.Busy() {
		return ErrBusy
	}
	scan, err := m.Collector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collect: %w", err)
	}
	for _, w := range scan.Warnings {
		m.log().Warn("inventory scan warning", "detail", w)
	}
	if err := m.syncUsers(snd, scan, opt.FullUsers); err != nil {
		return err
	}
	return m.syncSoftware(snd, scan, opt.FullSoftware)
}

func (m *Manager) syncUsers(snd Sender, scan *Scan, force bool) error {
	for _, g := range scan.Failed {
		if g.Scope == scopeUser && g.SID == "" && g.Source == 0 {
			return nil // profile list unreadable: keep the previous users
		}
	}
	msg := &agentv1.UsersInventory{Users: scan.Users}
	fp := hashMsg(msg)
	if !force && bytes.Equal(fp, m.Store.GetMeta(metaUsersFP)) {
		return nil
	}
	seq, err := m.Store.NextSeq()
	if err != nil {
		return err
	}
	rev := m.Store.GetUint(metaUsersRev) + 1
	if err := snd.Send(&agentv1.ConnectRequest{Msg: &agentv1.ConnectRequest_Inventory{Inventory: &agentv1.InventoryReport{
		Seq: seq, Section: agentv1.InventorySection_INVENTORY_SECTION_USERS, Rev: rev,
		Body: &agentv1.InventoryReport_Users{Users: msg}}}}); err != nil {
		return err
	}
	m.pending[seq] = func() {
		_ = m.Store.SetUint(metaUsersRev, rev)
		_ = m.Store.SetMeta(metaUsersFP, fp)
	}
	return nil
}

func (m *Manager) syncSoftware(snd Sender, scan *Scan, forceFull bool) error {
	prev, err := m.Store.LoadSnapshot(snapSoftware)
	if err != nil {
		return err
	}
	rev := m.Store.GetUint(metaSWRev)
	upserts, removes, next := Diff(prev, scan)

	full := forceFull || (rev == 0 && len(prev) == 0)
	if !full && len(upserts)+len(removes) == 0 {
		return nil
	}
	if !full && len(upserts)+len(removes) > MaxDeltaItems {
		full = true
	}

	newRev := rev + 1
	if full {
		next = SnapshotOf(scan.Items) // a full snapshot replaces everything
		return m.sendFull(snd, scan, newRev, next)
	}
	seq, err := m.Store.NextSeq()
	if err != nil {
		return err
	}
	if err := snd.Send(&agentv1.ConnectRequest{Msg: &agentv1.ConnectRequest_Inventory{Inventory: &agentv1.InventoryReport{
		Seq: seq, Section: agentv1.InventorySection_INVENTORY_SECTION_SOFTWARE, Rev: newRev, Truncated: scan.Truncated,
		Body: &agentv1.InventoryReport_SoftwareDelta{SoftwareDelta: &agentv1.SoftwareDelta{
			BaseRev: rev, Upserts: upserts, Removes: removes}}}}}); err != nil {
		return err
	}
	m.log().Info("software delta sent", "upserts", len(upserts), "removes", len(removes), "rev", newRev)
	m.pending[seq] = m.commitSoftware(newRev, next)
	return nil
}

func (m *Manager) sendFull(snd Sender, scan *Scan, newRev uint64, next Snapshot) error {
	items := scan.Items
	total := (len(items) + ChunkSize - 1) / ChunkSize
	if total == 0 {
		total = 1 // an empty snapshot is still one (empty) chunk
	}
	var lastSeq uint64
	for i := 0; i < total; i++ {
		lo, hi := i*ChunkSize, min((i+1)*ChunkSize, len(items))
		seq, err := m.Store.NextSeq()
		if err != nil {
			return err
		}
		if err := snd.Send(&agentv1.ConnectRequest{Msg: &agentv1.ConnectRequest_Inventory{Inventory: &agentv1.InventoryReport{
			Seq: seq, Section: agentv1.InventorySection_INVENTORY_SECTION_SOFTWARE, Rev: newRev, Truncated: scan.Truncated,
			Body: &agentv1.InventoryReport_SoftwareChunk{SoftwareChunk: &agentv1.SoftwareChunk{
				Index: uint32(i), Total: uint32(total), Items: items[lo:hi]}}}}}); err != nil { // #nosec G115 -- bounded by MaxItems/ChunkSize
			return err
		}
		lastSeq = seq
	}
	m.log().Info("full software inventory sent", "items", len(items), "chunks", total, "rev", newRev)
	m.pending[lastSeq] = m.commitSoftware(newRev, next)
	return nil
}

func (m *Manager) commitSoftware(rev uint64, next Snapshot) func() {
	return func() {
		if err := m.Store.SaveSnapshot(snapSoftware, next); err != nil {
			m.log().Error("persist software snapshot", "err", err)
			return
		}
		_ = m.Store.SetUint(metaSWRev, rev)
	}
}
