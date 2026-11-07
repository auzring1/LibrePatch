// Command deploycheck drives software-deployment scenarios against a running
// server and a real enrolled Windows agent on the same machine. It is used by
// the Windows CI job (informational until it has passed on a VM) and by
// test/vm-matrix. Exit status 0 means every scenario passed.
//
//	go run ./test/tools/deploycheck -url http://localhost:18080 -totp-file totp.txt -scenario winget-7zip
package main

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/auzring1/librepatch/internal/server/auth"
)

type api struct {
	base, csrf string
	c          *http.Client
}

func (a *api) do(method, path string, body any, headers map[string]string, raw []byte) (int, map[string]any, error) {
	var rd io.Reader
	switch {
	case raw != nil:
		rd = bytes.NewReader(raw)
	case body != nil:
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
		if headers == nil {
			headers = map[string]string{}
		}
		headers["Content-Type"] = "application/json"
	}
	req, _ := http.NewRequest(method, a.base+"/api/v1"+path, rd)
	req.Header.Set("Origin", a.base)
	if a.csrf != "" {
		req.Header.Set("X-CSRF-Token", a.csrf)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := a.c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, nil
}

func (a *api) must(method, path string, body any, want int) map[string]any {
	st, out, err := a.do(method, path, body, nil, nil)
	if err != nil || st != want {
		fail("%s %s: HTTP %d %v (want %d) %v", method, path, st, out, want, err)
	}
	return out
}

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+f+"\n", a...)
	os.Exit(1)
}

func main() {
	base := flag.String("url", "http://localhost:18080", "server base URL")
	email := flag.String("email", "admin@example.com", "")
	password := flag.String("password", "Granite-Lantern-Pickle-42", "")
	totpFile := flag.String("totp-file", "", "file written by bootstrap -totp-out")
	scenario := flag.String("scenario", "winget-7zip", "winget-7zip | winget | unsigned-pinned | agent-update")
	relDir := flag.String("release-dir", "", "directory with librepatch-agent-<version>.exe/.lprel files (scenario agent-update)")
	goodVer := flag.String("good-version", "0.9.1", "release the agent must update to (scenario agent-update)")
	badVer := flag.String("broken-version", "0.9.2", "release that never connects; the agent must roll back (scenario agent-update)")
	pkgID := flag.String("package", "", "winget identifier (scenario winget)")
	pkgScope := flag.String("scope", "machine", "machine | user (scenario winget)")
	detect := flag.String("detect-file", "", "file that must exist after install and be gone after uninstall (scenario winget)")
	jsonOut := flag.String("json-out", "", "append a VM-matrix result entry to this file on success (scenario winget)")
	osLabel := flag.String("os", "", "OS label recorded in the result, e.g. win11-23h2 (scenario winget)")
	flag.Parse()
	jar, _ := cookiejar.New(nil)
	a := &api{base: *base, c: &http.Client{Jar: jar, Timeout: 10 * time.Minute}}

	raw, err := os.ReadFile(*totpFile)
	if err != nil {
		fail("read totp secret: %v", err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		fail("totp secret: %v", err)
	}
	login := a.must("POST", "/auth/login", map[string]any{"email": *email, "password": *password}, 200)
	a.csrf, _ = login["csrf_token"].(string)
	// Bootstrap already used the steps around its own start, and the server refuses a code it has seen.
	// The server accepts t-1..t+1 around now, so try each step in that window once (newest first) and
	// wait for the clock to move on to a fresh step when all of them were used.
	var mfa map[string]any
	tried := map[int64]bool{}
	for i := 0; i < 12 && mfa == nil; i++ {
		cur := auth.TOTPStep(time.Now())
		for _, st := range []int64{cur + 1, cur, cur - 1} {
			if tried[st] {
				continue
			}
			tried[st] = true
			code, out, err := a.do("POST", "/auth/mfa", map[string]any{"code": auth.TOTPCode(secret, st)}, nil, nil)
			if err == nil && code == 200 {
				mfa = out
				break
			}
		}
		if mfa == nil {
			time.Sleep(10 * time.Second)
		}
	}
	if mfa == nil {
		fail("could not complete MFA")
	}
	a.csrf, _ = mfa["csrf_token"].(string)

	devs := a.must("GET", "/devices?status=active&limit=5", nil, 200)
	items, _ := devs["items"].([]any)
	if len(items) == 0 {
		fail("no enrolled device")
	}
	device := items[0].(map[string]any)["id"].(string)

	switch *scenario {
	case "winget-7zip":
		winget(a, device, "7zip.7zip", "machine", filepath.Join(os.Getenv("ProgramFiles"), "7-Zip", "7z.exe"))
	case "winget":
		if *pkgID == "" || *detect == "" {
			fail("-package and -detect-file are required")
		}
		winget(a, device, *pkgID, *pkgScope, *detect)
		if *jsonOut != "" {
			record(*jsonOut, *pkgID, *pkgScope, *osLabel)
		}
	case "unsigned-pinned":
		unsignedPinned(a, device)
	case "agent-update":
		agentUpdate(a, device, *relDir, *goodVer, *badVer)
	default:
		fail("unknown scenario %q", *scenario)
	}
	fmt.Println("PASS", *scenario)
}

// waitJob polls the deployment until every job is terminal and returns the jobs.
func waitJob(a *api, dep string, timeout time.Duration) []any {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out := a.must("GET", "/deployments/"+dep+"/jobs", nil, 200)
		jobs, _ := out["items"].([]any)
		done := len(jobs) > 0
		for _, j := range jobs {
			switch j.(map[string]any)["status"] {
			case "succeeded", "succeeded_reboot", "failed", "expired", "cancelled", "rejected":
			default:
				done = false
			}
		}
		if done {
			return jobs
		}
		time.Sleep(3 * time.Second)
	}
	fail("deployment %s did not finish in %s", dep, timeout)
	return nil
}

func jobLog(a *api, job any) string {
	id := job.(map[string]any)["id"].(string)
	d := a.must("GET", "/jobs/"+id, nil, 200)
	b, _ := json.MarshalIndent(d, "", "  ")
	return string(b)
}

// record appends a passing run in the format of internal/server/catalog/matrix_results.json.
func record(path, id, scope, osLabel string) {
	var all []map[string]string
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &all)
	}
	all = append(all, map[string]string{"identifier": id, "scope": scope, "os": osLabel,
		"run_id": time.Now().UTC().Format("20060102T150405Z"), "passed_at": time.Now().UTC().Format(time.RFC3339)})
	b, _ := json.MarshalIndent(all, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		fail("write %s: %v", path, err)
	}
}

// winget imports a package from winget-pkgs, installs it, checks the detection file,
// uninstalls it and checks the file is gone.
func winget(a *api, device, id, scope, exe string) {
	imp := a.must("POST", "/catalog/import", map[string]any{"identifier": id}, 201)
	pkg := imp["package_id"].(string)
	if _, err := os.Stat(exe); err == nil {
		fail("%s already exists; run on a clean image", exe)
	}
	dep := a.must("POST", "/deployments", map[string]any{"name": "ci install " + id, "action": "install", "package_id": pkg,
		"scope": scope, "device_ids": []string{device}, "unverified_confirmed": true}, 201)["deployment_id"].(string)
	jobs := waitJob(a, dep, 10*time.Minute)
	if s := jobs[0].(map[string]any)["status"]; s != "succeeded" && s != "succeeded_reboot" {
		fail("install job is %v:\n%s", s, jobLog(a, jobs[0]))
	}
	if _, err := os.Stat(exe); err != nil {
		fail("job reported success but %s is missing", exe)
	}
	fmt.Println("installed:", exe)

	// Uninstall needs the new Uninstall entry to have reached server inventory.
	var un string
	for i := 0; i < 30 && un == ""; i++ {
		st, out, _ := a.do("POST", "/deployments", map[string]any{"name": "ci remove " + id, "action": "uninstall", "package_id": pkg,
			"scope": scope, "device_ids": []string{device}, "unverified_confirmed": true}, nil, nil)
		if st == 201 {
			un = out["deployment_id"].(string)
			break
		}
		time.Sleep(5 * time.Second)
	}
	if un == "" {
		fail("could not plan the uninstall (inventory never listed the package)")
	}
	jobs = waitJob(a, un, 5*time.Minute)
	if s := jobs[0].(map[string]any)["status"]; s != "succeeded" && s != "succeeded_reboot" {
		fail("uninstall job is %v:\n%s", s, jobLog(a, jobs[0]))
	}
	if _, err := os.Stat(exe); err == nil {
		fail("uninstall reported success but %s still exists", exe)
	}
}

// unsignedPinned uploads an unsigned program with a signer pin that cannot match.
// The agent must refuse to run it, so the marker file must not appear.
func unsignedPinned(a *api, device string) {
	self, err := os.Executable()
	if err != nil {
		fail("%v", err)
	}
	body, err := os.ReadFile(self)
	if err != nil {
		fail("%v", err)
	}
	st, up, err := a.do("POST", "/catalog/content", nil, map[string]string{"Content-Type": "application/octet-stream", "X-File-Name": "unsigned.exe"}, body)
	if err != nil || st != 201 {
		fail("upload: %d %v %v", st, up, err)
	}
	marker := filepath.Join(os.Getenv("ProgramFiles"), "RnvCheck", "never.txt")
	pkg := a.must("POST", "/catalog/custom", map[string]any{"identifier": "RnvCheck.Unsigned", "name": "Unsigned check", "version": "1.0.0",
		"sha256": up["sha256"], "file_name": "unsigned.exe", "type": "exe", "arch": "x64", "scope": "machine", "args": []string{"/S"},
		"signer_subject": "CN=Nobody Inc", "detection": []map[string]any{{"kind": "file", "key": `%ProgramFiles%\RnvCheck\never.txt`}}}, 201)["package_id"].(string)
	dep := a.must("POST", "/deployments", map[string]any{"name": "ci unsigned", "action": "install", "package_id": pkg,
		"scope": "machine", "device_ids": []string{device}}, 201)["deployment_id"].(string)
	jobs := waitJob(a, dep, 3*time.Minute)
	s := jobs[0].(map[string]any)["status"]
	if s != "failed" && s != "rejected" {
		fail("expected the unsigned installer to be refused, job is %v:\n%s", s, jobLog(a, jobs[0]))
	}
	log := jobLog(a, jobs[0])
	if !strings.Contains(strings.ToLower(log), "signature") && !strings.Contains(strings.ToLower(log), "signer") {
		fail("job failed but not for a signature reason:\n%s", log)
	}
	if _, err := os.Stat(marker); err == nil {
		fail("the unsigned installer ran")
	}
}

// uploadRelease sends <dir>/librepatch-agent-<v>.exe with its .lprel bundle and returns the release id.
func uploadRelease(a *api, dir, v string) string {
	bin, err := os.ReadFile(filepath.Join(dir, "librepatch-agent-"+v+".exe"))
	if err != nil {
		fail("%v", err)
	}
	bundle, err := os.ReadFile(filepath.Join(dir, "librepatch-agent-"+v+".lprel"))
	if err != nil {
		fail("%v", err)
	}
	st, out, err := a.do("POST", "/agent-releases", nil, map[string]string{"Content-Type": "application/octet-stream", "X-Release-Bundle": base64.StdEncoding.EncodeToString(bundle)}, bin)
	if err != nil || st != 201 {
		fail("upload release %s: %d %v %v", v, st, out, err)
	}
	return out["id"].(string)
}

func deviceVersion(a *api, device string) (string, bool) {
	d := a.must("GET", "/devices/"+device, nil, 200)
	v, _ := d["agent_version"].(string)
	online, _ := d["online"].(bool)
	return v, online
}

func lastAgentJob(a *api, device string) (status, reason string) {
	out := a.must("GET", "/devices/"+device+"/jobs", nil, 200)
	items, _ := out["items"].([]any)
	for _, j := range items {
		m := j.(map[string]any)
		if m["type"] == "agent_update" {
			status, _ = m["status"].(string)
			reason, _ = m["status_reason"].(string)
			return
		}
	}
	return "", ""
}

// agentUpdate moves the installed agent to a good release (it must come back healthy on the new
// version) and then to a broken one (the safety net must put the good version back).
func agentUpdate(a *api, device, dir, good, bad string) {
	if dir == "" {
		fail("-release-dir is required")
	}
	start, _ := deviceVersion(a, device)
	fmt.Println("running version:", start)
	target := func(id string) {
		a.must("PUT", "/agent-rollout", map[string]any{"release_id": id, "soak_hours": 0, "success_threshold": 90, "batch_per_tick": 10}, 204)
	}
	wait := func(what string, timeout time.Duration, ok func() bool) {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			if ok() {
				return
			}
			time.Sleep(5 * time.Second)
		}
		st, why := lastAgentJob(a, device)
		v, online := deviceVersion(a, device)
		fail("timed out waiting for %s (device runs %q online=%v; last update job %s %s)", what, v, online, st, why)
	}

	target(uploadRelease(a, dir, good))
	wait("the update to "+good, 8*time.Minute, func() bool {
		v, online := deviceVersion(a, device)
		st, _ := lastAgentJob(a, device)
		return v == good && online && st == "succeeded"
	})
	fmt.Println("updated to", good)

	target(uploadRelease(a, dir, bad))
	wait("the rollback from "+bad, 15*time.Minute, func() bool {
		v, online := deviceVersion(a, device)
		st, _ := lastAgentJob(a, device)
		return v == good && online && st == "failed"
	})
	fmt.Println("rolled back to", good, "after the broken release", bad)
	a.must("PUT", "/agent-rollout", map[string]any{"release_id": nil, "soak_hours": 0, "success_threshold": 90, "batch_per_tick": 10}, 204)
}
