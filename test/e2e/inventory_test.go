package e2e

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/core"
	"github.com/auzring1/librepatch/internal/agent/inventory"
	"github.com/auzring1/librepatch/internal/agent/store"
)

// fakeCollector is a scripted endpoint: tests mutate its software list.
type fakeCollector struct {
	mu    sync.Mutex
	items map[string]*agentv1.SoftwareItem
	users []*agentv1.DeviceUser
}

func sw(key, name, ver string) *agentv1.SoftwareItem {
	return &agentv1.SoftwareItem{Key: &agentv1.SoftwareItemKey{Source: agentv1.SoftwareSource_SOFTWARE_SOURCE_REG64,
		Scope: agentv1.SoftwareScope_SOFTWARE_SCOPE_MACHINE, ItemKey: key}, Name: name, Version: ver, Publisher: "Acme Inc."}
}

func (f *fakeCollector) set(it *agentv1.SoftwareItem) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[it.Key.ItemKey] = it
}

func (f *fakeCollector) remove(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.items, key)
}

func (f *fakeCollector) Collect(context.Context) (*inventory.Scan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := &inventory.Scan{Users: f.users}
	for _, it := range f.items {
		s.Items = append(s.Items, it)
	}
	return s, nil
}

func (h *harness) get(path string) (int, http.Header, string) {
	h.t.Helper()
	req, _ := http.NewRequest("GET", h.base+path, nil)
	req.Header.Set("Origin", h.origin)
	resp, err := h.http.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func items(b map[string]any) []map[string]any {
	var out []map[string]any
	for _, x := range b["items"].([]any) {
		out = append(out, x.(map[string]any))
	}
	return out
}

func (h *harness) softwareOf(id string) map[string]string { // name -> version
	st, b := h.do("GET", "/api/v1/devices/"+id+"/software", nil, nil)
	if st != 200 {
		h.t.Fatalf("device software: %d %v", st, b)
	}
	out := map[string]string{}
	for _, it := range items(b) {
		out[it["name"].(string)] = it["version"].(string)
	}
	return out
}

func TestInventoryEndToEnd(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()

	fc := &fakeCollector{items: map[string]*agentv1.SoftwareItem{}}
	fc.set(sw("chrome", "Google Chrome", "129.0.1"))
	fc.set(sw("sevenzip", "7-Zip 23.01 (x64)", "23.01"))
	fc.set(sw("evil", `=HYPERLINK("http://evil.example","click")`, "1.0"))
	fc.users = []*agentv1.DeviceUser{{Sid: "S-1-5-21-1-2-3-1001", Username: "ada", Domain: "ACME", Loaded: true, SignedIn: true, IsAdmin: true}}
	changes := make(chan struct{}, 4)
	wire := func(a *core.Agent, st *store.Store) {
		a.Inv = &inventory.Manager{Collector: fc, Store: st, Log: a.Log}
		a.Changes, a.InvQuiet = changes, 50*time.Millisecond
	}

	enr := h.createToken("inv", 5, false)
	hw := &fakeHW{host: "LAP-001", serial: "SN-1", uuid: "U-1"}
	ta := h.startAgent(enr, hw, nil, wire)
	waitFor(t, agentConnectWait, "agent connected", func() bool { return ta.state() == "connected" })
	id := h.devices()[0]["id"].(string)

	// Baseline snapshot arrives; the normalized product groups "7-Zip 23.01 (x64)" as "7-Zip".
	waitFor(t, 10*time.Second, "initial inventory", func() bool { return len(h.softwareOf(id)) == 3 })
	st, b := h.do("GET", "/api/v1/software?q=7-zip", nil, nil)
	if st != 200 || len(items(b)) != 1 || items(b)[0]["name"] != "7-Zip" || items(b)[0]["device_count"] != float64(1) {
		t.Fatalf("software search: %d %v", st, b)
	}
	if _, users := h.do("GET", "/api/v1/devices/"+id+"/users", nil, nil); len(items(users)) != 1 || items(users)[0]["username"] != "ada" {
		t.Fatalf("users: %v", users)
	}
	if st, hist := h.do("GET", "/api/v1/devices/"+id+"/software/history", nil, nil); st != 200 || len(items(hist)) != 0 {
		t.Fatalf("baseline must not create history: %v", hist)
	}
	if d := h.device(id); d["software_count"] != float64(3) {
		t.Fatalf("software_count: %v", d["software_count"])
	}

	// Change detection: upgrade Chrome, install Firefox, remove 7-Zip -> one delta.
	fc.set(sw("chrome", "Google Chrome", "130.0.2"))
	fc.set(sw("firefox", "Mozilla Firefox", "131.0"))
	fc.remove("sevenzip")
	changes <- struct{}{}
	waitFor(t, 10*time.Second, "delta applied", func() bool {
		s := h.softwareOf(id)
		return s["Google Chrome"] == "130.0.2" && s["Mozilla Firefox"] == "131.0" && s["7-Zip"] == "" && len(s) == 3
	})
	_, hist := h.do("GET", "/api/v1/devices/"+id+"/software/history", nil, nil)
	got := map[string]string{}
	for _, e := range items(hist) {
		got[e["name"].(string)] = e["change"].(string)
	}
	if got["Google Chrome"] != "version" || got["Mozilla Firefox"] != "added" || got["7-Zip 23.01 (x64)"] != "removed" {
		t.Fatalf("history: %v", got)
	}

	// Fleet queries: which devices have Chrome older than 130.5?
	_, s := h.do("GET", "/api/v1/software?q=chrome", nil, nil)
	titleID := items(s)[0]["id"].(string)
	_, vs := h.do("GET", "/api/v1/software/"+titleID, nil, nil)
	if v := vs["versions"].([]any); len(v) != 1 || v[0].(map[string]any)["version"] != "130.0.2" {
		t.Fatalf("versions: %v", vs)
	}
	_, ins := h.do("GET", "/api/v1/software/"+titleID+"/installs?older_than=130.5", nil, nil)
	if len(items(ins)) != 1 {
		t.Fatalf("installs older than 130.5: %v", ins)
	}
	_, ins = h.do("GET", "/api/v1/software/"+titleID+"/installs?older_than=130", nil, nil)
	if len(items(ins)) != 0 {
		t.Fatalf("130.0.2 is not older than 130: %v", ins)
	}

	// Resync: the server forgets the agent's revision (restored backup); the next
	// delta is refused with a ResyncRequest and the agent repairs it with a full snapshot.
	if _, err := h.db.Pool.Exec(context.Background(), "UPDATE devices SET software_rev = 999, software_count = 0"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Pool.Exec(context.Background(), "DELETE FROM software_installs"); err != nil {
		t.Fatal(err)
	}
	fc.set(sw("vlc", "VLC media player", "3.0.21"))
	changes <- struct{}{}
	waitFor(t, 15*time.Second, "resync after revision mismatch", func() bool {
		s := h.softwareOf(id)
		return len(s) == 4 && s["VLC media player"] == "3.0.21"
	})

	// A dynamic group: devices with Chrome below 131.
	filter := map[string]any{"op": "and", "children": []any{
		map[string]any{"op": "device", "field": "hostname", "cmp": "prefix", "value": "lap-"},
		map[string]any{"op": "software", "title": "chrome", "version": map[string]any{"cmp": "lt", "value": "131"}}}}
	if st, pv := h.do("POST", "/api/v1/groups/preview", map[string]any{"filter": filter}, nil); st != 200 || pv["total"] != float64(1) {
		t.Fatalf("preview: %d %v", st, pv)
	}
	st, grp := h.do("POST", "/api/v1/groups", map[string]any{"name": "Old Chrome", "filter": filter}, nil)
	if st != 201 {
		t.Fatalf("create group: %d %v", st, grp)
	}
	if st, m := h.do("GET", "/api/v1/groups/"+grp["id"].(string)+"/devices", nil, nil); st != 200 || len(items(m)) != 1 {
		t.Fatalf("members: %d %v", st, m)
	}
	if st, _ := h.do("POST", "/api/v1/groups", map[string]any{"name": "Old Chrome", "filter": filter}, nil); st != 409 {
		t.Fatalf("duplicate name: %d", st)
	}
	bad := map[string]any{"op": "device", "field": "hostname; DROP TABLE devices", "cmp": "eq", "value": "x"}
	if st, e := h.do("POST", "/api/v1/groups/preview", map[string]any{"filter": bad}, nil); st != 422 {
		t.Fatalf("hostile filter: %d %v", st, e)
	}

	// CSV export: formulas are neutralized and the export is audited.
	code, hdr, body := h.get("/api/v1/reports/software.csv")
	if code != 200 || !strings.HasPrefix(hdr.Get("Content-Type"), "text/csv") || !strings.Contains(hdr.Get("Content-Disposition"), "attachment") {
		t.Fatalf("csv: %d %v", code, hdr)
	}
	if strings.Contains(body, `,=HYPERLINK`) || strings.Contains(body, "\n=HYPERLINK") || !strings.Contains(body, `'=HYPERLINK`) {
		t.Fatalf("formula not neutralized:\n%s", body)
	}
	if !strings.Contains(body, "LAP-001") || !strings.Contains(body, "VLC media player") {
		t.Fatalf("csv content:\n%s", body)
	}
	code, _, dev := h.get("/api/v1/reports/devices.csv?group_id=" + url.QueryEscape(grp["id"].(string)))
	if code != 200 || !strings.Contains(dev, "LAP-001") {
		t.Fatalf("devices csv: %d %s", code, dev)
	}
	st, au := h.do("GET", "/api/v1/audit?limit=50", nil, nil)
	exports := 0
	for _, e := range items(au) {
		if e["action"] == "inventory.export" {
			exports++
		}
	}
	if st != 200 || exports != 2 {
		t.Fatalf("expected 2 audited exports, saw %d (%d)", exports, st)
	}
}

// TestInventoryHelloResync: the server loses its copy (restore from an old
// backup) while the agent is offline; reconnecting repairs it from Hello revisions alone.
func TestInventoryHelloResync(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()
	fc := &fakeCollector{items: map[string]*agentv1.SoftwareItem{}}
	fc.set(sw("a", "Alpha", "1.0"))
	fc.set(sw("b", "Beta", "2.0"))
	wire := func(a *core.Agent, st *store.Store) { a.Inv = &inventory.Manager{Collector: fc, Store: st, Log: a.Log} }
	ta := h.startAgent(h.createToken("t", 1, false), &fakeHW{host: "PC-9", serial: "S9", uuid: "U9"}, nil, wire)
	waitFor(t, agentConnectWait, "agent connected", func() bool { return ta.state() == "connected" })
	id := h.devices()[0]["id"].(string)
	waitFor(t, 10*time.Second, "inventory", func() bool { return len(h.softwareOf(id)) == 2 })
	ta.stop()

	if _, err := h.db.Pool.Exec(context.Background(), "UPDATE devices SET software_rev = 0, software_count = 0"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Pool.Exec(context.Background(), "DELETE FROM software_installs"); err != nil {
		t.Fatal(err)
	}
	h.restartAgent(ta, wire)
	waitFor(t, 15*time.Second, "full resync from hello", func() bool { return len(h.softwareOf(id)) == 2 })
	var rev int64
	if err := h.db.Pool.QueryRow(context.Background(), "SELECT software_rev FROM devices WHERE id=$1", id).Scan(&rev); err != nil || rev < 1 {
		t.Fatalf("rev=%d err=%v", rev, err)
	}
}
