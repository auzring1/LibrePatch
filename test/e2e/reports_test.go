package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/core"
	"github.com/auzring1/librepatch/internal/agent/inventory"
	"github.com/auzring1/librepatch/internal/agent/store"
)

func TestReportBuilderEndToEnd(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()

	fc := &fakeCollector{items: map[string]*agentv1.SoftwareItem{}}
	fc.set(sw("chrome", "Google Chrome", "129.0.1"))
	fc.set(sw("evil", `=HYPERLINK("http://evil.example","click")`, "1.0"))
	wire := func(a *core.Agent, st *store.Store) { a.Inv = &inventory.Manager{Collector: fc, Store: st, Log: a.Log} }
	ta := h.startAgent(h.createToken("rep", 5, false), &fakeHW{host: "LAP-001", serial: "SN-1", uuid: "U-1"}, nil, wire)
	waitFor(t, agentConnectWait, "agent connected", func() bool { return ta.state() == "connected" })
	id := h.devices()[0]["id"].(string)
	waitFor(t, 10*time.Second, "inventory", func() bool { return len(h.softwareOf(id)) == 2 })

	// The catalog lists the data, the ready-made reports and no saved ones yet.
	st, cat := h.do("GET", "/api/v1/reports/catalog", nil, nil)
	if st != 200 || len(cat["datasets"].([]any)) != 6 || len(cat["builtins"].([]any)) < 10 || len(cat["saved"].([]any)) != 0 {
		t.Fatalf("catalog: %d %v", st, cat)
	}
	devices := map[string]any{"dataset": "devices", "columns": []string{"hostname", "model", "ram_gb", "cores", "cpu"}}

	// A preview is JSON with cells as text, numbers written as numbers.
	st, res := h.do("POST", "/api/v1/reports/run", map[string]any{"spec": devices, "format": "json"}, nil)
	if st != 200 || res["total"] != float64(1) {
		t.Fatalf("preview: %d %v", st, res)
	}
	row := res["rows"].([]any)[0].([]any)
	if row[0] != "LAP-001" || row[1] != "Laptop 9" || row[2] != "16.0" || row[3] != "8" || row[4] != "Test CPU" {
		t.Fatalf("hardware row: %v", row)
	}
	// Disks come out of the hardware snapshot, one row per drive.
	st, res = h.do("POST", "/api/v1/reports/run", map[string]any{"spec": map[string]any{"dataset": "disks", "columns": []string{"hostname", "drive", "size_gb", "free_pct"}}}, nil)
	if st != 200 || res["total"] != float64(1) || res["rows"].([]any)[0].([]any)[2] != "512.0" || res["rows"].([]any)[0].([]any)[3] != "19.5" {
		t.Fatalf("disks: %d %v", st, res)
	}
	// Scope: another site or an empty filter result gives no rows; a filter that matches keeps the row.
	nothing := map[string]any{"dataset": "devices", "columns": []string{"hostname"}, "filters": []map[string]any{{"column": "ram_gb", "op": "gt", "value": "64"}}}
	if st, res := h.do("POST", "/api/v1/reports/run", map[string]any{"spec": nothing}, nil); st != 200 || res["total"] != float64(0) {
		t.Fatalf("filter: %d %v", st, res)
	}

	// CSV: formula-safe, byte-order mark, a file name, audited.
	before := h.auditCount("inventory.export")
	soft := map[string]any{"dataset": "software", "columns": []string{"hostname", "name", "version"}, "filters": []map[string]any{{"column": "system_component", "op": "is", "value": "false"}}}
	st2, hdr, body := h.raw("POST", "/api/v1/reports/run", "application/json", mustJSON(t, map[string]any{"spec": soft, "format": "csv", "title": "My software / 2026"}))
	if st2 != 200 || !strings.HasPrefix(hdr.Get("Content-Type"), "text/csv") || !strings.Contains(hdr.Get("Content-Disposition"), "-my-software-2026-") || !strings.HasSuffix(strings.Split(hdr.Get("Content-Disposition"), `"`)[1], ".csv") {
		t.Fatalf("csv headers: %d %v", st2, hdr)
	}
	csv := string(body)
	for _, want := range []string{"\xef\xbb\xbfDevice,Program,Version\n", "LAP-001,Google Chrome,129.0.1", `'=HYPERLINK`} {
		if !strings.Contains(strings.ReplaceAll(csv, "\r\n", "\n"), want) {
			t.Errorf("csv lacks %q: %q", want, csv)
		}
	}
	if strings.Contains(strings.ReplaceAll(csv, "\r\n", "\n"), "\n=HYPERLINK") || strings.Contains(csv, ",=HYPERLINK") {
		t.Errorf("a formula must not start a cell: %q", csv)
	}
	// PDF.
	st2, hdr, body = h.raw("POST", "/api/v1/reports/run", "application/json", mustJSON(t, map[string]any{"spec": devices, "format": "pdf", "title": "Hardware"}))
	if st2 != 200 || hdr.Get("Content-Type") != "application/pdf" || !strings.HasPrefix(string(body), "%PDF-1.4") || !strings.Contains(string(body), "LAP-001") {
		t.Fatalf("pdf: %d %v %.20q", st2, hdr, body)
	}
	if n := h.auditCount("inventory.export") - before; n != 2 {
		t.Fatalf("both exports are audited: %d", n)
	}
	if d := h.auditDetails("inventory.export"); d["format"] != "pdf" || d["rows"] != float64(1) || d["kind"] != "custom-devices" {
		t.Fatalf("export audit: %v", d)
	}

	// Bad definitions are refused with a sentence, never run.
	for name, spec := range map[string]map[string]any{
		"unknown column": {"dataset": "devices", "columns": []string{"hostname; DROP TABLE devices"}},
		"unknown data":   {"dataset": "users", "columns": []string{"hostname"}},
		"no columns":     {"dataset": "devices", "columns": []string{}},
		"bad number":     {"dataset": "devices", "columns": []string{"hostname"}, "filters": []map[string]any{{"column": "ram_gb", "op": "gt", "value": "lots"}}},
		"unknown group":  {"dataset": "devices", "columns": []string{"hostname"}, "group_id": "6f9619ff-8b86-d011-b42d-00c04fc964ff"},
	} {
		if st, b := h.do("POST", "/api/v1/reports/run", map[string]any{"spec": spec}, nil); st != 400 {
			t.Errorf("%s: %d %v", name, st, b)
		}
	}
	if st, _ := h.do("POST", "/api/v1/reports/run", map[string]any{"spec": devices, "format": "xlsx"}, nil); st != 400 {
		t.Errorf("format: %d", st)
	}

	// Saved reports: created, listed, changed, name kept unique, deleted, audited.
	st, saved := h.do("POST", "/api/v1/reports/saved", map[string]any{"name": "Laptops", "description": "d", "spec": devices}, nil)
	if st != 201 || saved["name"] != "Laptops" {
		t.Fatalf("save: %d %v", st, saved)
	}
	sid := saved["id"].(string)
	if st, _ := h.do("POST", "/api/v1/reports/saved", map[string]any{"name": "LAPTOPS", "spec": devices}, nil); st != 409 {
		t.Fatalf("duplicate name: %d", st)
	}
	if st, _ := h.do("POST", "/api/v1/reports/saved", map[string]any{"name": " ", "spec": devices}, nil); st != 400 {
		t.Fatalf("empty name: %d", st)
	}
	if st, _ := h.do("POST", "/api/v1/reports/saved", map[string]any{"name": "Bad", "spec": nothingColumns()}, nil); st != 400 {
		t.Fatalf("bad spec is not saved: %d", st)
	}
	if st, up := h.do("PUT", "/api/v1/reports/saved/"+sid, map[string]any{"name": "Laptops 2", "spec": soft}, nil); st != 200 || up["name"] != "Laptops 2" || up["spec"].(map[string]any)["dataset"] != "software" {
		t.Fatalf("update: %d %v", st, up)
	}
	if st, cat := h.do("GET", "/api/v1/reports/catalog", nil, nil); st != 200 || len(cat["saved"].([]any)) != 1 {
		t.Fatalf("saved listed: %d %v", st, cat["saved"])
	}

	// Who may do what. A read-only user can look but not export, save or delete; an operator can build.
	ro := h.orgUser("ro@example.com", "readonly")
	if st, _ := ro.do("POST", "/api/v1/reports/run", map[string]any{"spec": devices}, nil); st != 200 {
		t.Fatalf("read-only preview: %d", st)
	}
	if st, _, _ := ro.raw("POST", "/api/v1/reports/run", "application/json", mustJSON(t, map[string]any{"spec": devices, "format": "csv"})); st != 403 {
		t.Fatalf("read-only export: %d", st)
	}
	if st, _ := ro.do("POST", "/api/v1/reports/saved", map[string]any{"name": "x", "spec": devices}, nil); st != 403 {
		t.Fatalf("read-only save: %d", st)
	}
	if st, _ := ro.do("DELETE", "/api/v1/reports/saved/"+sid, nil, nil); st != 403 {
		t.Fatalf("read-only delete: %d", st)
	}
	if st, cat := ro.do("GET", "/api/v1/reports/catalog", nil, nil); st != 200 || len(cat["saved"].([]any)) != 1 {
		t.Fatalf("read-only sees saved reports: %d", st)
	}
	op := h.orgUser("op@example.com", "operator")
	if st, _ := op.do("POST", "/api/v1/reports/saved", map[string]any{"name": "Operator's", "spec": devices}, nil); st != 201 {
		t.Fatalf("operator save: %d", st)
	}
	if st, _ := h.otherClient().do("GET", "/api/v1/reports/catalog", nil, nil); st != 401 {
		t.Fatalf("anonymous: %d", st)
	}
	// API tokens carry reports:read (and so can preview), but not what they were not given.
	_, tok := h.do("POST", "/api/v1/me/api-tokens", map[string]any{"name": "t", "scopes": []string{"reports:read"}, "expires_in_days": 5}, nil)
	if st, _ := h.bearer(tok["token"].(string), "POST", "/api/v1/reports/run", map[string]any{"spec": devices}); st != 200 {
		t.Fatalf("token preview: %d", st)
	}
	if st, _ := h.bearer(tok["token"].(string), "POST", "/api/v1/reports/saved", map[string]any{"name": "t", "spec": devices}); st != 403 {
		t.Fatalf("token save without reports:write: %d", st)
	}

	if st, _ := h.do("DELETE", "/api/v1/reports/saved/"+sid, nil, nil); st != 204 {
		t.Fatalf("delete: %d", st)
	}
	if st, _ := h.do("DELETE", "/api/v1/reports/saved/"+sid, nil, nil); st != 404 {
		t.Fatalf("delete twice: %d", st)
	}
	if st, _ := h.do("PUT", "/api/v1/reports/saved/"+sid, map[string]any{"name": "x", "spec": devices}, nil); st != 404 {
		t.Fatalf("update a deleted report: %d", st)
	}
	if h.auditCount("report.create") != 2 || h.auditCount("report.update") != 1 || h.auditCount("report.delete") != 1 {
		t.Fatalf("audit: create %d update %d delete %d", h.auditCount("report.create"), h.auditCount("report.update"), h.auditCount("report.delete"))
	}
}

func nothingColumns() map[string]any {
	return map[string]any{"dataset": "devices", "columns": []string{}}
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
