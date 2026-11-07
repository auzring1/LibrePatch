//go:build !windows

package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/auzring1/librepatch/internal/agent/core"
	"github.com/auzring1/librepatch/internal/agent/jobs"
	"github.com/auzring1/librepatch/internal/agent/selfupdate"
	"github.com/auzring1/librepatch/internal/agent/store"
	"github.com/auzring1/librepatch/internal/shared/release"
)

// uploadRelease sends a bundle and binary to POST /agent-releases.
func (h *harness) uploadRelease(bundle, binary []byte) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest("POST", h.base+"/api/v1/agent-releases", bytes.NewReader(binary))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Release-Bundle", base64.StdEncoding.EncodeToString(bundle))
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

func signedBundle(t *testing.T, priv ed25519.PrivateKey, version string, binary []byte) []byte {
	t.Helper()
	h := sha256.Sum256(binary)
	mb, err := release.Marshal(&release.Manifest{Format: 1, Product: release.Product, Version: version, OS: runtimeOS(), Arch: runtimeArch(),
		SHA256: hex.EncodeToString(h[:]), Size: uint64(len(binary))})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := release.EncodeBundle(&release.Bundle{Manifest: mb, Signature: release.Sign(priv, mb), KeyID: release.KeyID(priv.Public().(ed25519.PublicKey))})
	return b
}

func TestAgentSelfUpdateEndToEnd(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h.app.Releases.Keys = []ed25519.PublicKey{pub}

	// The "agent binary" is a script that reports its version, which is all the engine runs.
	script := func(v string) []byte {
		return []byte("#!/bin/sh\necho '" + brand.VersionBanner + " " + v + " (e2e)'\n")
	}

	var ta *testAgent
	restarted := make(chan *testAgent, 1)
	engineFor := func(version string, hook func()) func(*core.Agent, *store.Store) {
		return func(a *core.Agent, st *store.Store) {
			a.Version = version
			p := jobs.NewPlatform(a.DataDir)
			if hook != nil {
				p.(interface{ Dev() *selfupdate.Dev }).Dev().RestartHook = hook
			}
			a.Jobs = &jobs.Engine{P: p, Store: st, Log: a.Log, ReleaseKeys: []ed25519.PublicKey{pub}}
		}
	}
	hook := func() {
		// What the service manager does: the old process exits, the new binary starts.
		ta.stop()
		restarted <- h.restartAgent(ta, engineFor("1.1.0", nil))
	}
	ta = h.startAgent(h.createToken("su", 5, false), &fakeHW{host: "LAP-SU", serial: "SSU", uuid: "USU"}, nil, engineFor("1.0.0", hook))
	waitFor(t, agentConnectWait, "agent connected", func() bool { return ta.state() == "connected" })
	dev := h.devices()[0]["id"].(string)
	waitFor(t, 10*time.Second, "version reported", func() bool { return h.device(dev)["agent_version"] == "1.0.0" })

	// Uploads: a bundle signed by an unknown key and a binary that differs from the manifest are refused.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	if st, b := h.uploadRelease(signedBundle(t, otherPriv, "1.1.0", script("1.1.0")), script("1.1.0")); st != 422 {
		t.Fatalf("a release signed by an unknown key must be refused: %d %v", st, b)
	}
	if st, b := h.uploadRelease(signedBundle(t, priv, "1.1.0", script("1.1.0")), script("9.9.9")); st != 422 {
		t.Fatalf("a binary that does not match the manifest must be refused: %d %v", st, b)
	}
	st, rel := h.uploadRelease(signedBundle(t, priv, "1.1.0", script("1.1.0")), script("1.1.0"))
	if st != 201 {
		t.Fatalf("upload: %d %v", st, rel)
	}
	st, ro := h.do("PUT", "/api/v1/agent-rollout", map[string]any{"release_id": rel["id"], "soak_hours": 0, "success_threshold": 90, "batch_per_tick": 10}, nil)
	if st != 204 {
		t.Fatalf("rollout: %d %v", st, ro)
	}

	h.app.Releases.Tick(t.Context())
	var jobID string
	waitFor(t, 10*time.Second, "update job", func() bool {
		_, js := h.do("GET", "/api/v1/devices/"+dev+"/jobs", nil, nil)
		for _, j := range items(js) {
			if j["type"] == "agent_update" {
				jobID = j["id"].(string)
			}
		}
		return jobID != ""
	})

	// The old agent verifies, downloads, stages and "restarts"; the new one proves itself and the job succeeds.
	var ta2 *testAgent
	select {
	case ta2 = <-restarted:
	case <-time.After(30 * time.Second):
		_, j := h.do("GET", "/api/v1/jobs/"+jobID, nil, nil)
		t.Fatalf("the agent never switched to the new version: %v", j)
	}
	j := h.waitJobByID(jobID, "succeeded")
	if res, _ := j["result"].(map[string]any); res == nil || res["message"] == nil {
		t.Fatalf("job result: %v", j)
	}
	waitFor(t, 15*time.Second, "new version reported", func() bool { return h.device(dev)["agent_version"] == "1.1.0" })

	// The slot switched, the safety net was disarmed and nothing is left to do.
	dir := ta2.dir
	if b, _ := os.ReadFile(filepath.Join(dir, "active-slot")); string(b) != "b" {
		t.Fatalf("active slot = %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "rollback-task.json")); err == nil {
		t.Fatal("the rollback task is still armed")
	}
	if _, err := selfupdate.Load(dir); err == nil {
		t.Fatal("update state not cleared")
	}
	if _, err := os.Stat(filepath.Join(dir, "slots", "slot-b", strings.TrimSuffix(brand.AgentExe, ".exe"))); err != nil {
		t.Fatalf("new binary not staged: %v", err)
	}

	// Another tick has nothing to do (the device runs the target), and the rollout reports it.
	h.app.Releases.Tick(t.Context())
	_, js := h.do("GET", "/api/v1/devices/"+dev+"/jobs", nil, nil)
	n := 0
	for _, j := range items(js) {
		if j["type"] == "agent_update" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d update jobs", n)
	}
	_, list := h.do("GET", "/api/v1/agent-releases", nil, nil)
	status := list["status"].(map[string]any)
	if status["updated"] != float64(1) {
		t.Fatalf("rollout status: %v", status)
	}
}
