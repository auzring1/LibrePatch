package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/core"
	"github.com/auzring1/librepatch/internal/agent/inventory"
	"github.com/auzring1/librepatch/internal/agent/jobs"
	"github.com/auzring1/librepatch/internal/agent/store"
)

// upload sends an installer as the raw request body.
func (h *harness) upload(name string, body []byte) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest("POST", h.base+"/api/v1/catalog/content", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-File-Name", name)
	req.Header.Set("Origin", h.origin)
	req.Header.Set("X-CSRF-Token", h.csrf)
	resp, err := h.http.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func withJobs(a *core.Agent, st *store.Store) {
	a.Jobs = &jobs.Engine{P: jobs.NewPlatform(a.DataDir), Store: st, Log: a.Log}
}

// customPackage uploads a shell script as the "installer" and registers it. The Linux
// dev platform runs it directly; it drops a marker under the fake Program Files.
func (h *harness) customPackage(ident, version, script string, detect bool) (pkgID string) {
	h.t.Helper()
	st, up := h.upload("install.sh", []byte(script))
	if st != 201 {
		h.t.Fatalf("upload: %d %v", st, up)
	}
	spec := map[string]any{"identifier": ident, "name": "Acme Tool", "publisher": "Acme", "version": version, "sha256": up["sha256"],
		"file_name": "install.sh", "type": "exe", "arch": "neutral", "scope": "machine", "args": []string{"/silent"}}
	if detect {
		spec["detection"] = []map[string]any{{"kind": "file", "key": "%ProgramFiles%/Acme/tool.txt"}}
	}
	st, res := h.do("POST", "/api/v1/catalog/custom", spec, nil)
	if st != 201 {
		h.t.Fatalf("custom package: %d %v", st, res)
	}
	return res["package_id"].(string)
}

const goodInstaller = `#!/bin/sh
pf="$(dirname "$0")/../../pf"
mkdir -p "$pf/Acme"
echo "installed $1" > "$pf/Acme/tool.txt"
exit 0
`

func (h *harness) jobsOf(dep string) []map[string]any {
	st, b := h.do("GET", "/api/v1/deployments/"+dep+"/jobs", nil, nil)
	if st != 200 {
		h.t.Fatalf("deployment jobs: %d %v", st, b)
	}
	return items(b)
}

func (h *harness) waitJob(dep, want string) map[string]any {
	h.t.Helper()
	var got map[string]any
	waitFor(h.t, 30*time.Second, "job "+want, func() bool {
		js := h.jobsOf(dep)
		if len(js) == 1 {
			got = js[0]
			return got["status"] == want
		}
		return false
	})
	return got
}

func TestDeploymentEndToEnd(t *testing.T) {
	skipOnWindows(t)
	h := newHarness(t)
	h.setupAndLogin()
	ta := h.startAgent(h.createToken("dep", 5, false), &fakeHW{host: "LAP-D1", serial: "SD1", uuid: "UD1"}, nil, withJobs)
	waitFor(t, agentConnectWait, "agent connected", func() bool { return ta.state() == "connected" })
	devID := h.devices()[0]["id"].(string)
	pf := filepath.Join(ta.dir, "pf", "Acme", "tool.txt")

	pkg := h.customPackage("AcmeTool", "1.0.0", goodInstaller, true)

	// Install: signed job -> agent verifies -> downloads from the server by hash -> runs -> detects.
	st, plan := h.do("POST", "/api/v1/deployments", map[string]any{"name": "Install Acme", "action": "install", "package_id": pkg,
		"scope": "machine", "device_ids": []string{devID}}, nil)
	if st != 201 || plan["jobs"] != float64(1) {
		t.Fatalf("create deployment: %d %v", st, plan)
	}
	dep := plan["deployment_id"].(string)
	j := h.waitJob(dep, "succeeded")
	if j["detection_passed"] != true || j["exit_code"] != float64(0) {
		t.Fatalf("job: %v", j)
	}
	if b, err := os.ReadFile(pf); err != nil || !strings.Contains(string(b), "installed /silent") {
		t.Fatalf("installer did not run with the silent argument: %q %v", b, err)
	}
	_, detail := h.do("GET", "/api/v1/jobs/"+j["id"].(string), nil, nil)
	if detail["result"] == nil || len(detail["events"].([]any)) < 2 {
		t.Fatalf("job detail: %v", detail)
	}
	waitFor(t, 10*time.Second, "deployment completed", func() bool {
		_, d := h.do("GET", "/api/v1/deployments/"+dep, nil, nil)
		return d["status"] == "completed"
	})

	// Same package again: detection says it is already installed, nothing runs.
	_ = os.WriteFile(pf, []byte("sentinel"), 0o600)
	_, plan = h.do("POST", "/api/v1/deployments", map[string]any{"name": "Again", "action": "install", "package_id": pkg, "scope": "machine", "device_ids": []string{devID}}, nil)
	j = h.waitJob(plan["deployment_id"].(string), "succeeded")
	_, d2 := h.do("GET", "/api/v1/jobs/"+j["id"].(string), nil, nil)
	if d2["result"].(map[string]any)["already_satisfied"] != true {
		t.Fatalf("expected already_satisfied: %v", d2["result"])
	}
	if b, _ := os.ReadFile(pf); string(b) != "sentinel" {
		t.Fatal("the installer ran although the product was already detected")
	}

	// Audit trail.
	_, au := h.do("GET", "/api/v1/audit?limit=100", nil, nil)
	seen := map[string]bool{}
	for _, e := range items(au) {
		seen[e["action"].(string)] = true
	}
	for _, a := range []string{"catalog.upload", "catalog.custom", "deployment.create"} {
		if !seen[a] {
			t.Errorf("audit log lacks %s", a)
		}
	}
}

func TestDeploymentFailureRetryAndCancel(t *testing.T) {
	skipOnWindows(t)
	h := newHarness(t)
	h.setupAndLogin()
	ta := h.startAgent(h.createToken("dep2", 5, false), &fakeHW{host: "LAP-D2", serial: "SD2", uuid: "UD2"}, nil, withJobs)
	waitFor(t, agentConnectWait, "agent connected", func() bool { return ta.state() == "connected" })
	devID := h.devices()[0]["id"].(string)

	pkg := h.customPackage("FailTool", "1.0", "#!/bin/sh\necho boom >&2\nexit 7\n", true)
	_, plan := h.do("POST", "/api/v1/deployments", map[string]any{"name": "Fails", "action": "install", "package_id": pkg, "scope": "machine", "device_ids": []string{devID}}, nil)
	dep := plan["deployment_id"].(string)
	j := h.waitJob(dep, "failed")
	_, d := h.do("GET", "/api/v1/jobs/"+j["id"].(string), nil, nil)
	res := d["result"].(map[string]any)
	if res["exit_code"] != float64(7) || !strings.Contains(res["log_tail"].(string), "boom") {
		t.Fatalf("failure details missing: %v", res)
	}
	// Retry creates a new attempt that fails the same way.
	st, rj := h.do("POST", "/api/v1/jobs/"+j["id"].(string)+"/retry", map[string]any{}, nil)
	if st != 201 {
		t.Fatalf("retry: %d %v", st, rj)
	}
	waitFor(t, 20*time.Second, "second attempt failed", func() bool {
		n := 0
		for _, x := range h.jobsOf(dep) {
			if x["status"] == "failed" {
				n++
			}
		}
		return n == 2
	})
	if st, _ := h.do("POST", "/api/v1/jobs/"+j["id"].(string)+"/retry", map[string]any{}, map[string]string{}); st != 201 {
		t.Fatalf("a failed job can be retried again: %d", st)
	}

	// Cancel: a job scheduled for later never runs.
	pkg2 := h.customPackage("LaterTool", "1.0", goodInstaller, true)
	_, plan = h.do("POST", "/api/v1/deployments", map[string]any{"name": "Later", "action": "install", "package_id": pkg2, "scope": "machine",
		"device_ids": []string{devID}, "starts_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, nil)
	dep2 := plan["deployment_id"].(string)
	waitFor(t, 15*time.Second, "job accepted by the agent", func() bool {
		js := h.jobsOf(dep2)
		return len(js) == 1 && (js[0]["status"] == "accepted" || js[0]["status"] == "waiting")
	})
	if st, _ := h.do("POST", "/api/v1/deployments/"+dep2+"/cancel", map[string]any{}, nil); st != 204 {
		t.Fatalf("cancel: %d", st)
	}
	if st, _ := h.do("POST", "/api/v1/deployments/"+dep2+"/cancel", map[string]any{}, nil); st != 409 {
		t.Fatalf("second cancel: %d", st)
	}
	if js := h.jobsOf(dep2); js[0]["status"] != "cancelled" {
		t.Fatalf("status %v", js[0]["status"])
	}
	// The agent drops the job: even when its start time arrives it must not run.
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(ta.dir, "pf", "Acme", "tool.txt")); err == nil {
		t.Fatal("a cancelled job ran")
	}
}

func TestOfflineDeviceReceivesJobOnConnect(t *testing.T) {
	skipOnWindows(t)
	h := newHarness(t)
	h.setupAndLogin()
	ta := h.startAgent(h.createToken("dep3", 5, false), &fakeHW{host: "LAP-D3", serial: "SD3", uuid: "UD3"}, nil, withJobs)
	waitFor(t, agentConnectWait, "agent connected", func() bool { return ta.state() == "connected" })
	devID := h.devices()[0]["id"].(string)
	ta.stop()
	waitFor(t, 10*time.Second, "device offline", func() bool { return h.device(devID)["online"] == false })

	pkg := h.customPackage("OfflineTool", "1.0", goodInstaller, true)
	_, plan := h.do("POST", "/api/v1/deployments", map[string]any{"name": "Offline", "action": "install", "package_id": pkg, "scope": "machine", "device_ids": []string{devID}}, nil)
	dep := plan["deployment_id"].(string)
	if js := h.jobsOf(dep); js[0]["status"] != "queued" {
		t.Fatalf("an offline device's job must stay queued: %v", js[0]["status"])
	}
	h.restartAgent(ta, withJobs)
	h.waitJob(dep, "succeeded")
}

func TestDeploymentValidation(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()
	ta := h.startAgent(h.createToken("dep4", 5, false), &fakeHW{host: "LAP-D4", serial: "SD4", uuid: "UD4"}, nil, withJobs)
	waitFor(t, agentConnectWait, "agent connected", func() bool { return ta.state() == "connected" })
	devID := h.devices()[0]["id"].(string)
	pkg := h.customPackage("ValTool", "1.0", goodInstaller, true)
	base := func() map[string]any {
		return map[string]any{"name": "x", "action": "install", "package_id": pkg, "scope": "machine", "device_ids": []string{devID}}
	}
	cases := map[string]func(map[string]any){
		"no targets":  func(m map[string]any) { delete(m, "device_ids") },
		"bad action":  func(m map[string]any) { m["action"] = "format" },
		"bad scope":   func(m map[string]any) { m["scope"] = "root" },
		"empty name":  func(m map[string]any) { m["name"] = " " },
		"huge expiry": func(m map[string]any) { m["expires_in_hours"] = 5000 },
		"unknown pkg": func(m map[string]any) { m["package_id"] = "00000000-0000-0000-0000-000000000000" },
		"bad window":  func(m map[string]any) { m["window"] = map[string]any{"start_minute": 2000, "duration_minutes": 60} },
		"bad version": func(m map[string]any) { m["version"] = "9.9.9" },
		"foreign dev": func(m map[string]any) { m["device_ids"] = []string{"11111111-1111-1111-1111-111111111111"} },
	}
	for name, mut := range cases {
		m := base()
		mut(m)
		if st, b := h.do("POST", "/api/v1/deployments", m, nil); st < 400 || st >= 500 {
			t.Errorf("%s accepted: %d %v", name, st, b)
		}
	}
	// A pin below the package version blocks it; an exclusion blocks everything.
	if st, b := h.do("PUT", "/api/v1/catalog/packages/"+pkg+"/overrides", map[string]any{"pin": "< 1.0"}, nil); st != 204 {
		t.Fatalf("override: %d %v", st, b)
	}
	if st, _ := h.do("POST", "/api/v1/deployments", base(), nil); st != 422 {
		t.Fatalf("pinned-out version accepted: %d", st)
	}
	_, _ = h.do("PUT", "/api/v1/catalog/packages/"+pkg+"/overrides", map[string]any{"excluded": true}, nil)
	if st, _ := h.do("POST", "/api/v1/deployments", base(), nil); st != 409 {
		t.Fatalf("excluded package accepted: %d", st)
	}
	// Hostile arguments in an override are refused.
	if st, _ := h.do("PUT", "/api/v1/catalog/packages/"+pkg+"/overrides", map[string]any{"silent_args": []string{"/S & calc"}}, nil); st != 422 {
		t.Fatalf("hostile override accepted: %d", st)
	}
	_ = context.Background
}

func TestDeviceRefreshAndUninstallFromInventory(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()
	fc := &fakeCollector{items: map[string]*agentv1.SoftwareItem{}}
	fc.set(sw("sevenzip", "7-Zip", "23.01"))
	wire := func(a *core.Agent, st *store.Store) { a.Inv = &inventory.Manager{Collector: fc, Store: st, Log: a.Log} }
	ta := h.startAgent(h.createToken("dep4", 5, false), &fakeHW{host: "LAP-D4", serial: "SD4", uuid: "UD4"}, nil, withJobs, wire)
	waitFor(t, agentConnectWait, "agent connected", func() bool { return ta.state() == "connected" })
	devID := h.devices()[0]["id"].(string)
	waitFor(t, 15*time.Second, "first inventory", func() bool { return len(h.softwareOf(devID)) == 1 })

	// Refresh: one job, reused while it is still fresh, and the agent completes it. Software that
	// appeared since the last report (nothing watched the registry here) shows up without waiting.
	fc.set(sw("chrome", "Google Chrome", "129.0.1"))
	st, r1 := h.do("POST", "/api/v1/devices/"+devID+"/refresh", map[string]any{}, nil)
	if st != 202 {
		t.Fatalf("refresh: %d %v", st, r1)
	}
	st, r2 := h.do("POST", "/api/v1/devices/"+devID+"/refresh", map[string]any{}, nil)
	if st != 202 {
		t.Fatalf("second refresh: %d %v", st, r2)
	}
	if r2["job_id"] != r1["job_id"] {
		// A fast agent may already have finished the first job; only a job still in flight is reused.
		if _, d := h.do("GET", "/api/v1/jobs/"+r1["job_id"].(string), nil, nil); d["status"] != "succeeded" {
			t.Fatalf("a second refresh within two minutes should reuse the unfinished first: %v %v (first is %v)", r1, r2, d["status"])
		}
		r1 = r2
	}
	waitFor(t, 20*time.Second, "refresh job succeeded", func() bool {
		_, d := h.do("GET", "/api/v1/jobs/"+r1["job_id"].(string), nil, nil)
		return d["status"] == "succeeded"
	})
	waitFor(t, 15*time.Second, "refreshed inventory", func() bool { return len(h.softwareOf(devID)) == 2 })

	// Uninstall straight from the device's inventory (no catalog package involved).
	var row map[string]any
	waitFor(t, 20*time.Second, "software inventory", func() bool {
		_, sw := h.do("GET", "/api/v1/devices/"+devID+"/software", nil, nil)
		for _, it := range items(sw) {
			if it["system_component"] == false && it["item_key"] != "" && it["source"] != "appx" && it["source"] != "portable" {
				row = it
				return true
			}
		}
		return false
	})
	ref := map[string]any{"source": row["source"], "scope": row["scope"], "user_sid": row["user_sid"], "item_key": row["item_key"]}
	st, res := h.do("POST", "/api/v1/devices/"+devID+"/software/uninstall", map[string]any{"items": []any{ref}}, nil)
	if st != 201 || len(res["job_ids"].([]any)) != 1 {
		t.Fatalf("uninstall: %d %v", st, res)
	}
	id := res["job_ids"].([]any)[0].(string)
	waitFor(t, 20*time.Second, "uninstall job finished", func() bool {
		_, d := h.do("GET", "/api/v1/jobs/"+id, nil, nil)
		return d["status"] == "succeeded" || d["status"] == "failed"
	})
	// A row the device never reported is skipped, a malformed request refused.
	ghost := map[string]any{"source": "reg64", "scope": "machine", "user_sid": "", "item_key": "NoSuchProgram"}
	st, res = h.do("POST", "/api/v1/devices/"+devID+"/software/uninstall", map[string]any{"items": []any{ghost}}, nil)
	if st != 201 || len(res["job_ids"].([]any)) != 0 || len(res["skipped"].([]any)) != 1 {
		t.Fatalf("unknown program: %d %v", st, res)
	}
	bad := map[string]any{"source": "reg64", "scope": "user", "user_sid": "", "item_key": "x"}
	if st, _ := h.do("POST", "/api/v1/devices/"+devID+"/software/uninstall", map[string]any{"items": []any{bad}}, nil); st != 422 {
		t.Fatalf("scope/user mismatch accepted: %d", st)
	}

	// An offline device cannot be refreshed.
	ta.stop()
	waitFor(t, 10*time.Second, "device offline", func() bool { return h.device(devID)["online"] == false })
	if st, _ := h.do("POST", "/api/v1/devices/"+devID+"/refresh", map[string]any{}, nil); st != 409 {
		t.Fatalf("refresh of an offline device: %d", st)
	}
}
