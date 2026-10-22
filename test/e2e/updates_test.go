//go:build !windows

// The scripted Windows Update client exists only in non-Windows builds (internal/agent/wu).
package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/wu"
)

const (
	kbSecurity = "aaaaaaaa-0000-0000-0000-000000000001"
	kbOptional = "aaaaaaaa-0000-0000-0000-000000000002"
)

func writeWU(t *testing.T, dir string, f wu.DevFile) {
	t.Helper()
	b, _ := json.Marshal(f)
	if err := os.WriteFile(filepath.Join(dir, "wu-dev.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) waitJobByID(id, want string) map[string]any {
	h.t.Helper()
	var got map[string]any
	waitFor(h.t, 30*time.Second, "job "+id+" "+want, func() bool {
		_, got = h.do("GET", "/api/v1/jobs/"+id, nil, nil)
		return got["status"] == want
	})
	return got
}

func (h *harness) windowsUpdates(dev string) map[string]map[string]any {
	_, b := h.do("GET", "/api/v1/devices/"+dev+"/windows-updates", nil, nil)
	out := map[string]map[string]any{}
	for _, it := range items(b) {
		out[it["update_id"].(string)] = it
	}
	return out
}

func TestWindowsUpdateEndToEnd(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()
	ta := h.startAgent(h.createToken("wu", 5, false), &fakeHW{host: "LAP-W1", serial: "SW1", uuid: "UW1"}, nil, withJobs)
	writeWU(t, ta.dir, wu.DevFile{Updates: []wu.DevUpdate{
		{ID: kbSecurity, Revision: 7, Title: "2026-03 Cumulative Update for Windows 11 (KB5000001)", KB: []string{"5000001"}, Classification: "Security Updates",
			Severity: "Critical", NeedsReboot: true, ReleaseDate: time.Now().Add(-72 * time.Hour).Unix()},
		{ID: kbOptional, Revision: 1, Title: "Optional preview update (KB5000002)", KB: []string{"5000002"}, Classification: "Updates"},
	}, Policy: nil})
	waitFor(t, 15*time.Second, "agent connected", func() bool { return ta.state() == "connected" })
	dev := h.devices()[0]["id"].(string)
	ctx := context.Background()

	// The server sends the source settings; the agent scans and reports without anyone asking.
	h.app.Updates.Tick(ctx)
	waitFor(t, 20*time.Second, "first scan reported", func() bool { return len(h.windowsUpdates(dev)) == 2 })
	ups := h.windowsUpdates(dev)
	if ups[kbSecurity]["state"] != "missing" || ups[kbSecurity]["severity"] != "Critical" || ups[kbSecurity]["classification"] != "Security Updates" {
		t.Fatalf("scan result: %v", ups[kbSecurity])
	}
	_, cat := h.do("GET", "/api/v1/updates?decision=pending", nil, nil)
	if len(items(cat)) != 2 || items(cat)[0]["devices_missing"] != float64(1) {
		t.Fatalf("catalog: %v", cat)
	}

	// Who manages updates: a WSUS policy shows up as a conflict.
	writeWU(t, ta.dir, wu.DevFile{Updates: []wu.DevUpdate{
		{ID: kbSecurity, Revision: 7, Title: "2026-03 Cumulative Update for Windows 11 (KB5000001)", KB: []string{"5000001"}, Classification: "Security Updates", Severity: "Critical", NeedsReboot: true},
		{ID: kbOptional, Revision: 1, Title: "Optional preview update (KB5000002)", KB: []string{"5000002"}, Classification: "Updates"},
	}, Policy: &agentv1.WuPolicyInfo{WsusConfigured: true, WsusServer: "http://wsus.example:8530", EffectiveSource: "wsus"}})
	st, sc := h.do("POST", "/api/v1/devices/"+dev+"/windows-updates/scan", map[string]any{}, nil)
	if st != 202 {
		t.Fatalf("scan: %d %v", st, sc)
	}
	h.waitJobByID(sc["job_id"].(string), "succeeded")
	waitFor(t, 15*time.Second, "policy conflict reported", func() bool {
		_, c := h.do("GET", "/api/v1/update-conflicts", nil, nil)
		return len(items(c)) == 1
	})

	// Approve one update and put the device in a ring that restarts at once when needed.
	_, g := h.do("POST", "/api/v1/groups", map[string]any{"kind": "static", "name": "Pilot PCs"}, nil)
	if st, _ := h.do("POST", "/api/v1/groups/"+g["id"].(string)+"/members", map[string]any{"add": []string{dev}}, nil); st != 204 {
		t.Fatalf("add member: %d", st)
	}
	st, ring := h.do("POST", "/api/v1/update-rings", map[string]any{"name": "Pilot", "ordinal": 1, "group_ids": []string{g["id"].(string)},
		"success_threshold": 90, "enabled": true, "restart": map[string]any{"allow": "outside_active_hours", "notify_minutes": 1}}, nil)
	if st != 201 {
		t.Fatalf("ring: %d %v", st, ring)
	}
	st, dec := h.do("POST", "/api/v1/updates/decision", map[string]any{"update_ids": []string{kbSecurity}, "decision": "approved", "note": "pilot"}, nil)
	if st != 200 || dec["changed"] != float64(1) {
		t.Fatalf("approve: %d %v", st, dec)
	}
	// The ring job is created by the scheduler, not by the approval.
	h.app.Updates.Tick(ctx)
	var jobID string
	waitFor(t, 10*time.Second, "install job", func() bool {
		_, js := h.do("GET", "/api/v1/devices/"+dev+"/jobs", nil, nil)
		for _, j := range items(js) {
			if j["type"] == "wu_install" {
				jobID = j["id"].(string)
			}
		}
		return jobID != ""
	})
	j := h.waitJobByID(jobID, "succeeded_reboot")
	_, detail := h.do("GET", "/api/v1/jobs/"+jobID, nil, nil)
	res := detail["result"].(map[string]any)
	wr := res["wu_results"].([]any)
	if j["reboot_required"] != true || len(wr) != 1 || wr[0].(map[string]any)["result"] != "WU_RESULT_INSTALLED_REBOOT" {
		t.Fatalf("job result: %v", detail["result"])
	}
	// The unapproved update was left alone; the restart policy fired (dev machine records it).
	if len(h.windowsUpdates(dev)) != 1 {
		waitFor(t, 15*time.Second, "rescan after the install", func() bool { return len(h.windowsUpdates(dev)) == 1 })
	}
	waitFor(t, 10*time.Second, "restart requested", func() bool {
		_, err := os.Stat(filepath.Join(ta.dir, "reboot-requested.json"))
		return err == nil
	})
	_, cat = h.do("GET", "/api/v1/updates?decision=approved", nil, nil)
	if len(items(cat)) != 1 || items(cat)[0]["devices_installed"] != float64(1) || items(cat)[0]["decision_source"] != "manual" {
		t.Fatalf("approved update: %v", cat)
	}
	// Running the scheduler again installs nothing new.
	h.app.Updates.Tick(ctx)
	_, js := h.do("GET", "/api/v1/devices/"+dev+"/jobs", nil, nil)
	n := 0
	for _, x := range items(js) {
		if x["type"] == "wu_install" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d install jobs", n)
	}

	// Hide the other update everywhere; the device reports it hidden after the job.
	st, dec = h.do("POST", "/api/v1/updates/decision", map[string]any{"update_ids": []string{kbOptional}, "decision": "hidden"}, nil)
	if st != 200 || dec["hide_jobs"] != float64(1) {
		t.Fatalf("hide: %d %v", st, dec)
	}
	waitFor(t, 20*time.Second, "update reported hidden", func() bool { return h.windowsUpdates(dev)[kbOptional]["state"] == "hidden" })

	// Manual restart with a countdown.
	_ = os.Remove(filepath.Join(ta.dir, "reboot-requested.json"))
	st, rb := h.do("POST", "/api/v1/devices/"+dev+"/reboot", map[string]any{"minutes": 5, "reason": "maintenance"}, nil)
	if st != 202 {
		t.Fatalf("reboot: %d %v", st, rb)
	}
	h.waitJobByID(rb["job_id"].(string), "succeeded")
	b, err := os.ReadFile(filepath.Join(ta.dir, "reboot-requested.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rq struct {
		DelayS  int    `json:"delay_s"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(b, &rq)
	if rq.DelayS != 300 || rq.Message == "" {
		t.Fatalf("restart request: %+v", rq)
	}

	// Audit trail.
	_, au := h.do("GET", "/api/v1/audit?limit=200", nil, nil)
	seen := map[string]bool{}
	for _, e := range items(au) {
		seen[e["action"].(string)] = true
	}
	for _, a := range []string{"wu.scan", "wu.ring_create", "wu.decision", "device.reboot"} {
		if !seen[a] {
			t.Errorf("audit log lacks %s", a)
		}
	}
}

// A device that Group Policy sends to WSUS can still be checked against Windows Update on the
// internet, once, by an administrator (D105). Operators cannot; the device forgets the source.
func TestOnlineWindowsUpdateCheck(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()
	operator := h.orgUser("op@example.com", "operator")
	ta := h.startAgent(h.createToken("wu-online", 5, false), &fakeHW{host: "LAP-W2", serial: "SW2", uuid: "UW2"}, nil, withJobs)
	writeWU(t, ta.dir, wu.DevFile{Updates: []wu.DevUpdate{
		{ID: kbSecurity, Revision: 7, Title: "2026-03 Cumulative Update for Windows 11 (KB5000001)", KB: []string{"5000001"}, Classification: "Security Updates", Severity: "Critical"},
	}, Policy: &agentv1.WuPolicyInfo{WsusConfigured: true, WsusServer: "http://wsus.example:8530", EffectiveSource: "wsus"}})
	waitFor(t, 15*time.Second, "agent connected", func() bool { return ta.state() == "connected" })
	dev := h.devices()[0]["id"].(string)

	// Going around WSUS needs the update-policy permission.
	for _, p := range []string{"scan-online", "install-online"} {
		if st, _, _ := operator.raw("POST", "/api/v1/devices/"+dev+"/windows-updates/"+p, "application/json", []byte(`{"update_ids":["`+kbSecurity+`"]}`)); st != 403 {
			t.Errorf("operator %s: %d, want 403", p, st)
		}
	}
	var jobs int
	_ = h.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM jobs WHERE type IN ('wu_scan','wu_install') AND title LIKE '%online%'`).Scan(&jobs)
	if jobs != 0 {
		t.Fatalf("a refused request queued %d job(s)", jobs)
	}

	// An administrator's one-time check reaches the device, which reports the source it used.
	st, sc := h.do("POST", "/api/v1/devices/"+dev+"/windows-updates/scan-online", map[string]any{}, nil)
	if st != 202 {
		t.Fatalf("scan-online: %d %v", st, sc)
	}
	h.waitJobByID(sc["job_id"].(string), "succeeded")
	waitFor(t, 15*time.Second, "online scan reported", func() bool {
		_, b := h.do("GET", "/api/v1/devices/"+dev+"/windows-updates", nil, nil)
		return b["service"] == float64(agentv1.WuService_WU_SERVICE_WINDOWS_UPDATE) && len(items(b)) == 1
	})
	if h.auditDetails("wu.scan_online")["hostname"] != "LAP-W2" {
		t.Fatal("the online check must be audited with the device")
	}

	// The next normal scan goes back to the organization's source: the device did not keep the override.
	st, sc = h.do("POST", "/api/v1/devices/"+dev+"/windows-updates/scan", map[string]any{}, nil)
	if st != 202 {
		t.Fatalf("scan: %d %v", st, sc)
	}
	h.waitJobByID(sc["job_id"].(string), "succeeded")
	waitFor(t, 15*time.Second, "normal scan reported", func() bool {
		_, b := h.do("GET", "/api/v1/devices/"+dev+"/windows-updates", nil, nil)
		return b["service"] == float64(agentv1.WuService_WU_SERVICE_DEFAULT)
	})

	// The restart banner follows the live flag from the heartbeat, not the flag saved with the last scan.
	if _, err := h.db.Pool.Exec(context.Background(), `UPDATE devices SET pending_reboot = false, wu_reboot_required = true WHERE id = $1`, dev); err != nil {
		t.Fatal(err)
	}
	if _, b := h.do("GET", "/api/v1/devices/"+dev+"/windows-updates", nil, nil); b["reboot_required"] != false {
		t.Fatalf("a restart since the last scan must clear the banner: %v", b["reboot_required"])
	}
	if _, err := h.db.Pool.Exec(context.Background(), `UPDATE devices SET pending_reboot = true, wu_reboot_required = false WHERE id = $1`, dev); err != nil {
		t.Fatal(err)
	}
	if _, b := h.do("GET", "/api/v1/devices/"+dev+"/windows-updates", nil, nil); b["reboot_required"] != true {
		t.Fatalf("a pending restart must show: %v", b["reboot_required"])
	}
}

// Settings > Update defaults > "Manage Windows updates" off: every Windows update feature answers 404 with a clear code,
// the rings (which software policies use) and a restart keep working, and switching it on again restores everything.
func TestWindowsUpdatesCanBeSwitchedOff(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()
	ta := h.startAgent(h.createToken("wu-off", 5, false), &fakeHW{host: "LAP-W2", serial: "SW2", uuid: "UW2"}, nil, withJobs)
	waitFor(t, 15*time.Second, "agent connected", func() bool { return ta.state() == "connected" })
	dev := h.devices()[0]["id"].(string)

	windows := []string{
		"GET /api/v1/updates", "GET /api/v1/update-settings", "GET /api/v1/update-rules", "GET /api/v1/update-holds",
		"GET /api/v1/update-conflicts", "GET /api/v1/devices/" + dev + "/windows-updates", "GET /api/v1/reports/compliance",
	}
	status := func(call string) int {
		var method, path string
		for i := range call {
			if call[i] == ' ' {
				method, path = call[:i], call[i+1:]
				break
			}
		}
		st, _ := h.do(method, path, nil, nil)
		return st
	}
	for _, c := range windows {
		if st := status(c); st != 200 {
			t.Fatalf("%s with Windows updates on: %d", c, st)
		}
	}

	_, cur := h.do("GET", "/api/v1/settings/sections/updates", nil, nil)
	if cur["values"].(map[string]any)["windows_updates_enabled"] != true {
		t.Fatalf("Windows updates must be on by default: %v", cur["values"])
	}
	put := func(on bool) {
		t.Helper()
		_, d := h.do("GET", "/api/v1/settings/sections/updates", nil, nil)
		st, b := h.do("PUT", "/api/v1/settings/sections/updates", map[string]any{"revision": d["revision"], "values": map[string]any{"windows_updates_enabled": on}}, nil)
		if st != 200 {
			t.Fatalf("save: %d %v", st, b)
		}
	}
	put(false)
	for _, c := range windows {
		var method, path string
		for i := range c {
			if c[i] == ' ' {
				method, path = c[:i], c[i+1:]
				break
			}
		}
		st, b := h.do(method, path, nil, nil)
		if st != 404 || (b["error"] != nil && b["error"].(map[string]any)["code"] != "windows_updates_off") {
			t.Fatalf("%s with Windows updates off: %d %v", c, st, b)
		}
	}
	if st, _ := h.do("POST", "/api/v1/devices/"+dev+"/windows-updates/scan", nil, nil); st != 404 {
		t.Fatalf("scan with Windows updates off: %d", st)
	}
	// The dashboard leaves out its Windows update numbers, and keeps the rest.
	_, dash := h.do("GET", "/api/v1/dashboard", nil, nil)
	for _, k := range []string{"compliance", "missing_critical_devices", "held_updates"} {
		if dash[k] != nil {
			t.Fatalf("the dashboard still shows %s with Windows updates off: %v", k, dash[k])
		}
	}
	if len(dash["top_missing"].([]any)) != 0 || dash["devices"] == nil {
		t.Fatalf("dashboard: %v", dash)
	}
	// What stays: the rings (software policies use them), software updates and restarts.
	for _, c := range []string{"GET /api/v1/update-rings", "GET /api/v1/software/updates", "GET /api/v1/policies"} {
		if st := status(c); st != 200 {
			t.Fatalf("%s must keep working with Windows updates off: %d", c, st)
		}
	}
	if st, b := h.do("POST", "/api/v1/devices/"+dev+"/reboot", map[string]any{"minutes": 5}, nil); st >= 400 && st != 409 {
		t.Fatalf("restart with Windows updates off: %d %v", st, b)
	}

	put(true)
	for _, c := range windows {
		if st := status(c); st != 200 {
			t.Fatalf("%s after switching back on: %d", c, st)
		}
	}
}
