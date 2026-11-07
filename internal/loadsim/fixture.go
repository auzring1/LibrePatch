package loadsim

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"strconv"
	"sync"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/inventory"
)

// Fixture is the inventory every simulated agent starts from. It is built once and shared, read
// only, by all agents, so 10,000 agents do not hold 10,000 copies of it.
type Fixture struct {
	Items    []*agentv1.SoftwareItem
	Snapshot inventory.Snapshot // the acknowledged snapshot of an unchanged agent, shared
	Users    []*agentv1.DeviceUser
}

var (
	fixtureVendors = []string{"Microsoft Corporation", "Google LLC", "Mozilla", "Adobe Inc.", "Oracle Corporation",
		"Igor Pavlov", "Notepad++ Team", "VideoLAN", "Zoom Video Communications, Inc.", "Dropbox, Inc.", "Cisco Systems, Inc.",
		"Citrix Systems, Inc.", "Intel Corporation", "NVIDIA Corporation", "Realtek Semiconductor Corp."}
	fixtureNames = []string{"Visual C++ Redistributable", "Chrome", "Firefox", "Acrobat Reader", "Java Runtime Environment",
		"7-Zip", "Notepad++", "VLC media player", "Zoom", "Dropbox", "AnyConnect Secure Mobility Client", "Receiver",
		"Graphics Driver", "Display Driver", "Audio Driver", ".NET Runtime", "Office Click-to-Run", "Teams", "OneDrive", "Edge"}
)

// NewFixture builds n software items (machine scope, mostly Add/Remove Programs entries) and two users.
func NewFixture(n int) *Fixture {
	r := rand.New(rand.NewPCG(7, 11)) // #nosec G404 -- deterministic fixture data, not security
	f := &Fixture{}
	for i := 0; i < n; i++ {
		src := agentv1.SoftwareSource_SOFTWARE_SOURCE_REG64
		switch {
		case i%5 == 3:
			src = agentv1.SoftwareSource_SOFTWARE_SOURCE_REG32
		case i%17 == 4:
			src = agentv1.SoftwareSource_SOFTWARE_SOURCE_MSI
		}
		name := fmt.Sprintf("%s %d", fixtureNames[i%len(fixtureNames)], 2000+i/len(fixtureNames))
		it := &agentv1.SoftwareItem{
			Key:  &agentv1.SoftwareItemKey{Source: src, Scope: agentv1.SoftwareScope_SOFTWARE_SCOPE_MACHINE, ItemKey: fmt.Sprintf("{%08X-0000-4000-8000-%012X}", 0xA0000000+uint32(i), i)},
			Name: name, Version: fmt.Sprintf("%d.%d.%d.%d", 1+r.IntN(30), r.IntN(20), r.IntN(500), r.IntN(9000)),
			Publisher:       fixtureVendors[i%len(fixtureVendors)],
			InstallDate:     fmt.Sprintf("202%d-%02d-%02d", 3+r.IntN(3), 1+r.IntN(12), 1+r.IntN(28)),
			InstallLocation: `C:\Program Files\` + fixtureVendors[i%len(fixtureVendors)] + `\` + fixtureNames[i%len(fixtureNames)],
			UninstallString: `MsiExec.exe /X` + fmt.Sprintf("{%08X-0000-4000-8000-%012X}", 0xA0000000+uint32(i), i),
		}
		if src == agentv1.SoftwareSource_SOFTWARE_SOURCE_MSI {
			it.ProductCode = it.Key.ItemKey
		}
		f.Items = append(f.Items, it)
	}
	f.Snapshot = inventory.SnapshotOf(f.Items)
	f.Users = []*agentv1.DeviceUser{
		{Sid: "S-1-5-21-1111111111-2222222222-3333333333-1001", Username: "user", Domain: "LOADSIM", ProfilePath: `C:\Users\user`, Loaded: true, SignedIn: true},
		{Sid: "S-1-5-21-1111111111-2222222222-3333333333-500", Username: "Administrator", Domain: "LOADSIM", ProfilePath: `C:\Users\Administrator`, IsAdmin: true},
	}
	return f
}

// memStore is the agent's state database in memory (inventory.Store). The acknowledged software
// snapshot is shared with the fixture's while the agent's inventory is unchanged.
type memStore struct {
	mu    sync.Mutex
	base  inventory.Snapshot
	snaps map[string]map[string][]byte
	uints map[string]uint64
	meta  map[string][]byte
	seq   uint64
}

func newMemStore(base inventory.Snapshot) *memStore {
	return &memStore{base: base, snaps: map[string]map[string][]byte{}, uints: map[string]uint64{}, meta: map[string][]byte{}}
}

func (s *memStore) LoadSnapshot(name string) (map[string][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snaps[name], nil
}

func (s *memStore) SaveSnapshot(name string, snap map[string][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sameSnapshot(snap, s.base) {
		snap = s.base
	}
	s.snaps[name] = snap
	return nil
}

func sameSnapshot(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || !bytes.Equal(v, w) {
			return false
		}
	}
	return true
}

func (s *memStore) GetUint(k string) uint64 { s.mu.Lock(); defer s.mu.Unlock(); return s.uints[k] }
func (s *memStore) SetUint(k string, v uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uints[k] = v
	return nil
}
func (s *memStore) GetMeta(k string) []byte { s.mu.Lock(); defer s.mu.Unlock(); return s.meta[k] }
func (s *memStore) SetMeta(k string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.meta[k] = v
	return nil
}
func (s *memStore) NextSeq() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	return s.seq, nil
}

// collector implements inventory.Collector from the shared fixture plus this agent's own changes.
type collector struct {
	fx      *Fixture
	mu      sync.Mutex
	changes map[int]*agentv1.SoftwareItem
	n       int
}

func (c *collector) Collect(context.Context) (*inventory.Scan, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.changes) == 0 {
		return &inventory.Scan{Items: c.fx.Items, Users: c.fx.Users}, nil
	}
	items := make([]*agentv1.SoftwareItem, len(c.fx.Items))
	copy(items, c.fx.Items)
	for i, it := range c.changes {
		items[i] = it
	}
	return &inventory.Scan{Items: items, Users: c.fx.Users}, nil
}

// change upgrades k random items, as if the user had installed updates.
func (c *collector) change(k int, r *rand.Rand) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.changes == nil {
		c.changes = map[int]*agentv1.SoftwareItem{}
	}
	for j := 0; j < k && len(c.fx.Items) > 0; j++ {
		i := r.IntN(len(c.fx.Items))
		cur := c.fx.Items[i]
		if o := c.changes[i]; o != nil {
			cur = o
		}
		c.n++
		next := proto.Clone(cur).(*agentv1.SoftwareItem) // never copy a message by value; the original is shared
		next.Version = cur.Version + "." + strconv.Itoa(c.n)
		c.changes[i] = next
	}
}

func hardwareFor(host, serial, uuid string) *agentv1.HardwareInventory {
	return &agentv1.HardwareInventory{Hostname: host, OsCaption: "Windows 11 Pro", OsBuild: 26100, OsUbr: 2033,
		Arch: "amd64", Manufacturer: "Contoso", Model: "Loadsim 9", Serial: serial, SmbiosUuid: uuid,
		Chassis: "notebook", CpuModel: "Simulated CPU", CpuLogicalCores: 8, RamBytes: 16 << 30,
		Disks:      []*agentv1.Disk{{Mount: "C:", Filesystem: "NTFS", SizeBytes: 512 << 30, FreeBytes: 100 << 30}},
		Interfaces: []*agentv1.NetInterface{{Name: "Ethernet", Mac: "00:11:22:33:44:55", Addresses: []string{"10.0.0.5"}}}} // NOSONAR: a simulated device
}
