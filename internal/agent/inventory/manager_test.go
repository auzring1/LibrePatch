package inventory

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/store"
)

type captureSender struct {
	msgs []*agentv1.InventoryReport
	err  error
}

func (c *captureSender) Send(m *agentv1.ConnectRequest) error {
	if c.err != nil {
		return c.err
	}
	c.msgs = append(c.msgs, m.GetInventory())
	return nil
}

func (c *captureSender) reset() { c.msgs = nil }

type fakeCollector struct{ scan *Scan }

func (f *fakeCollector) Collect(context.Context) (*Scan, error) { return f.scan, nil }

func mkItem(key, name, version string) *agentv1.SoftwareItem {
	return &agentv1.SoftwareItem{Key: &agentv1.SoftwareItemKey{Source: srcReg64, Scope: scopeMach, ItemKey: key}, Name: name, Version: version}
}

func newManager(t *testing.T, scan *Scan) (*Manager, *fakeCollector, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	fc := &fakeCollector{scan: scan}
	return &Manager{Collector: fc, Store: st}, fc, st
}

func lastSeq(c *captureSender) uint64 { return c.msgs[len(c.msgs)-1].Seq }

func TestDiff(t *testing.T) {
	a, b, c := mkItem("a", "A", "1"), mkItem("b", "B", "1"), mkItem("c", "C", "1")
	prev := SnapshotOf([]*agentv1.SoftwareItem{a, b, c})

	// unchanged
	up, rm, _ := Diff(prev, &Scan{Items: []*agentv1.SoftwareItem{a, b, c}})
	if len(up)+len(rm) != 0 {
		t.Fatalf("unchanged produced delta: %d %d", len(up), len(rm))
	}
	// b changes version, c removed, d added
	b2, d := mkItem("b", "B", "2"), mkItem("d", "D", "1")
	up, rm, next := Diff(prev, &Scan{Items: []*agentv1.SoftwareItem{a, b2, d}})
	if len(up) != 2 || len(rm) != 1 || rm[0].ItemKey != "c" || len(next) != 3 {
		t.Fatalf("up=%d rm=%v next=%d", len(up), rm, len(next))
	}
	// failed group: c is NOT reported removed and stays in the next snapshot
	up, rm, next = Diff(prev, &Scan{Items: []*agentv1.SoftwareItem{a, b}, Failed: []Group{{Source: srcReg64, Scope: scopeMach}}})
	if len(rm) != 0 || len(up) != 0 || len(next) != 3 {
		t.Fatalf("failed group must retain: rm=%v next=%d", rm, len(next))
	}
	// failed group for a different SID does not protect machine items
	_, rm, _ = Diff(prev, &Scan{Items: []*agentv1.SoftwareItem{a, b}, Failed: []Group{{Scope: scopeUser, SID: sidAlice}}})
	if len(rm) != 1 {
		t.Fatalf("unrelated failure must not retain: %v", rm)
	}
}

func TestManagerFullThenDelta(t *testing.T) {
	var items []*agentv1.SoftwareItem
	for i := 0; i < 600; i++ { // 3 chunks of 250
		items = append(items, mkItem("k"+itoa(i), "App "+itoa(i), "1.0"))
	}
	m, fc, st := newManager(t, &Scan{Items: items})
	snd := &captureSender{}

	// First sync: full snapshot in 3 chunks, one revision.
	if err := m.Sync(context.Background(), snd, SyncOptions{}); err != nil {
		t.Fatal(err)
	}
	var chunks []*agentv1.InventoryReport
	for _, r := range snd.msgs {
		if r.Section == agentv1.InventorySection_INVENTORY_SECTION_SOFTWARE {
			chunks = append(chunks, r)
		}
	}
	if len(chunks) != 3 {
		t.Fatalf("chunks: %d", len(chunks))
	}
	for i, c := range chunks {
		ch := c.GetSoftwareChunk()
		if ch == nil || int(ch.Index) != i || ch.Total != 3 || c.Rev != 1 {
			t.Fatalf("chunk %d: %+v rev=%d", i, ch, c.Rev)
		}
	}
	// Nothing is committed until the final chunk is acknowledged.
	if st.GetUint(metaSWRev) != 0 {
		t.Fatal("rev advanced before ack")
	}
	if err := m.Sync(context.Background(), snd, SyncOptions{}); !errors.Is(err, ErrBusy) {
		t.Fatalf("expected ErrBusy, got %v", err)
	}
	if m.Ack(chunks[0].Seq) { // intermediate chunks have no commit
		t.Fatal("intermediate chunk acked a commit")
	}
	if !m.Ack(chunks[2].Seq) || st.GetUint(metaSWRev) != 1 {
		t.Fatal("final ack must commit rev 1")
	}
	// Users were reported too (empty list is still a revision-1 baseline).
	for _, r := range snd.msgs {
		if r.Section == agentv1.InventorySection_INVENTORY_SECTION_USERS {
			m.Ack(r.Seq)
		}
	}
	snd.reset()

	// No change: nothing is sent.
	if err := m.Sync(context.Background(), snd, SyncOptions{}); err != nil || len(snd.msgs) != 0 {
		t.Fatalf("unchanged sync sent %d msgs: %v", len(snd.msgs), err)
	}

	// One app updated, one removed, one added: a small delta with base_rev 1.
	fc.scan = &Scan{Items: append([]*agentv1.SoftwareItem{mkItem("k5", "App 5", "2.0"), mkItem("new", "New", "1")}, items[10:]...)}
	if err := m.Sync(context.Background(), snd, SyncOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(snd.msgs) != 1 {
		t.Fatalf("expected one delta, got %d msgs", len(snd.msgs))
	}
	d := snd.msgs[0].GetSoftwareDelta()
	if d == nil || d.BaseRev != 1 || snd.msgs[0].Rev != 2 {
		t.Fatalf("delta: %+v rev=%d", d, snd.msgs[0].Rev)
	}
	// k5 changed (in the first 10 items, then replaced), k0-k4,k6-k9 removed, "new" added.
	if len(d.Upserts) != 2 || len(d.Removes) != 9 {
		t.Fatalf("upserts=%d removes=%d", len(d.Upserts), len(d.Removes))
	}
	m.Ack(lastSeq(snd))
	if st.GetUint(metaSWRev) != 2 {
		t.Fatal("delta ack must commit rev 2")
	}
}

func TestManagerLostAckLeavesStateUntouched(t *testing.T) {
	items := []*agentv1.SoftwareItem{mkItem("a", "A", "1"), mkItem("b", "B", "1")}
	m, fc, st := newManager(t, &Scan{Items: items})
	snd := &captureSender{}
	_ = m.Sync(context.Background(), snd, SyncOptions{})
	for _, r := range snd.msgs {
		m.Ack(r.Seq)
	}
	snd.reset()

	fc.scan = &Scan{Items: []*agentv1.SoftwareItem{mkItem("a", "A", "2"), mkItem("b", "B", "1")}}
	_ = m.Sync(context.Background(), snd, SyncOptions{})
	if len(snd.msgs) != 1 {
		t.Fatal("expected a delta")
	}
	// The stream dies before the ack: pending is forgotten, nothing persisted.
	m.ResetPending()
	if st.GetUint(metaSWRev) != 1 {
		t.Fatal("rev must stay at the acknowledged value")
	}
	snd.reset()
	// After reconnect the same change is computed again against the OLD snapshot.
	_ = m.Sync(context.Background(), snd, SyncOptions{})
	d := snd.msgs[0].GetSoftwareDelta()
	if d == nil || d.BaseRev != 1 || len(d.Upserts) != 1 || d.Upserts[0].Version != "2" {
		t.Fatalf("redelivery: %+v", d)
	}
}

func TestManagerResyncAndEmptyAndFailures(t *testing.T) {
	m, fc, _ := newManager(t, &Scan{})
	snd := &captureSender{}
	// Empty device: a full snapshot of zero items is still one empty chunk.
	_ = m.Sync(context.Background(), snd, SyncOptions{})
	var sw *agentv1.InventoryReport
	for _, r := range snd.msgs {
		if r.Section == agentv1.InventorySection_INVENTORY_SECTION_SOFTWARE {
			sw = r
		}
	}
	if sw == nil || sw.GetSoftwareChunk() == nil || len(sw.GetSoftwareChunk().Items) != 0 || sw.GetSoftwareChunk().Total != 1 {
		t.Fatalf("empty snapshot: %+v", sw)
	}
	for _, r := range snd.msgs {
		m.Ack(r.Seq)
	}
	snd.reset()

	// Server asked for a resync: full snapshot even though nothing changed.
	fc.scan = &Scan{Items: []*agentv1.SoftwareItem{mkItem("a", "A", "1")}}
	_ = m.Sync(context.Background(), snd, SyncOptions{FullSoftware: true})
	if sw = snd.msgs[len(snd.msgs)-1]; sw.GetSoftwareChunk() == nil || sw.Rev != 2 {
		t.Fatalf("resync: %+v", sw)
	}
	m.ResetPending()

	// Send errors surface to the caller.
	bad := &captureSender{err: errors.New("stream closed")}
	if err := m.Sync(context.Background(), bad, SyncOptions{FullSoftware: true}); err == nil {
		t.Fatal("send error swallowed")
	}
	// Profile-list failure keeps the previous users (nothing sent for users).
	m.ResetPending()
	fc.scan = &Scan{Items: []*agentv1.SoftwareItem{mkItem("a", "A", "1")}, Failed: []Group{{Scope: scopeUser}}}
	snd.reset()
	_ = m.Sync(context.Background(), snd, SyncOptions{})
	for _, r := range snd.msgs {
		if r.Section == agentv1.InventorySection_INVENTORY_SECTION_USERS {
			t.Fatal("users sent although the profile list failed")
		}
	}
}

func TestManagerLargeDeltaFallsBackToFull(t *testing.T) {
	var items []*agentv1.SoftwareItem
	for i := 0; i < MaxDeltaItems+10; i++ {
		items = append(items, mkItem("k"+itoa(i), "A", "1"))
	}
	m, fc, _ := newManager(t, &Scan{Items: items[:5]})
	snd := &captureSender{}
	_ = m.Sync(context.Background(), snd, SyncOptions{})
	for _, r := range snd.msgs {
		m.Ack(r.Seq)
	}
	snd.reset()
	fc.scan = &Scan{Items: items}
	_ = m.Sync(context.Background(), snd, SyncOptions{})
	if snd.msgs[0].GetSoftwareChunk() == nil {
		t.Fatal("an oversized delta must be sent as a full snapshot")
	}
}
