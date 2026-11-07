//go:build compose

// Package integration runs the real docker-compose stack (Caddy, server,
// PostgreSQL) and a real agent process against it.
//
//	docker compose -f deploy/docker-compose.yml build   # or: make image
//	go test -tags compose -count=1 -timeout 15m ./test/integration/
package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/auzring1/librepatch/internal/agent/core"
	"github.com/auzring1/librepatch/internal/server/auth"
)

const (
	project   = "librepatch-it"
	httpsPort = "28443"
	gwPort    = "28444"
	origin    = "https://localhost:" + httpsPort
	password  = "Granite-Lantern-Pickle-42"
)

type stack struct {
	t   *testing.T
	dir string
}

func repoRoot() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..")
}

func run(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out.String())
	}
	return out.String()
}

func (s *stack) compose(args ...string) string {
	s.t.Helper()
	base := []string{"compose", "-p", project, "-f", filepath.Join(s.dir, "docker-compose.yml"), "--env-file", filepath.Join(s.dir, ".env")}
	return run(s.t, s.dir, "docker", append(base, args...)...)
}

func up(t *testing.T) *stack {
	dir := t.TempDir()
	root := repoRoot()
	for _, f := range []string{"docker-compose.yml"} {
		b, err := os.ReadFile(filepath.Join(root, "deploy", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Only needed so that compose can resolve the build contexts; the stack itself runs from the three images.
	run(t, root, "cp", "-r", filepath.Join(root, "deploy", "postgres"), filepath.Join(root, "deploy", "caddy"), dir)
	env := strings.Join([]string{
		"LIBREPATCH_HOSTNAME=localhost", "LIBREPATCH_CADDY_TLS=internal", "LIBREPATCH_HTTP_PORT=28080", "LIBREPATCH_HTTPS_PORT=" + httpsPort,
		"LIBREPATCH_PUBLIC_PORT_SUFFIX=:" + httpsPort, "LIBREPATCH_GATEWAY_PORT=" + gwPort, "LIBREPATCH_FRONTEND_SUBNET=172.31.251.0/24",
		"LIBREPATCH_CADDY_IP=172.31.251.10",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &stack{t: t, dir: dir}
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(s.compose("logs", "--no-color", "--tail", "80"))
		}
		s.compose("down", "-v", "--remove-orphans")
	})
	s.compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "180")
	return s
}

type client struct {
	t    *testing.T
	h    *http.Client
	csrf string
}

func (c *client) do(method, path string, body any) (int, map[string]any) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, origin+"/api/v1"+path, rd)
	req.Header.Set("Origin", origin)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.h.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func waitFor(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestComposeStack(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	s := up(t)

	// --- Container hardening (docs/THREAT-MODEL.md T-SRV-1/2) ---
	inspect := func(svc, format string) string {
		id := strings.TrimSpace(s.compose("ps", "-q", svc))
		return strings.TrimSpace(run(t, s.dir, "docker", "inspect", "--format", format, id))
	}
	if u := inspect("server", "{{.Config.User}}"); u != "65532:65532" {
		t.Errorf("server user = %q, want non-root 65532", u)
	}
	for _, svc := range []string{"server", "postgres", "caddy"} {
		if ro := inspect(svc, "{{.HostConfig.ReadonlyRootfs}}"); ro != "true" {
			t.Errorf("%s root filesystem not read-only", svc)
		}
		if caps := inspect(svc, "{{.HostConfig.CapDrop}}"); !strings.Contains(caps, "ALL") {
			t.Errorf("%s does not drop all capabilities: %s", svc, caps)
		}
		if nnp := inspect(svc, "{{.HostConfig.SecurityOpt}}"); !strings.Contains(nnp, "no-new-privileges") {
			t.Errorf("%s lacks no-new-privileges", svc)
		}
	}
	// Decision D111: maintenance stays running (idle) after its work, so container managers show every container as up.
	if run := inspect("maintenance", "{{.State.Running}} {{.State.Health.Status}}"); run != "true healthy" {
		t.Errorf("maintenance should be running and healthy after the first start, got %q", run)
	}
	// Decision D110: the stack needs no files next to the compose file, so no service may mount one from the host.
	for _, svc := range []string{"server", "postgres", "caddy"} {
		if m := inspect(svc, "{{json .Mounts}}"); strings.Contains(m, `"Type":"bind"`) {
			t.Errorf("%s mounts a file or folder from the host: %s", svc, m)
		}
	}
	if ports := inspect("postgres", "{{json .NetworkSettings.Ports}}"); strings.Contains(ports, "HostPort") {
		t.Errorf("postgres publishes a host port: %s", ports)
	}

	// --- Trust Caddy's internal CA for the console ---
	rootPEM := filepath.Join(s.dir, "caddy-root.crt")
	s.compose("cp", "caddy:/data/caddy/pki/authorities/local/root.crt", rootPEM)
	pemBytes, _ := os.ReadFile(rootPEM)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("could not load Caddy root")
	}
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, h: &http.Client{Jar: jar, Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}}

	// Security headers through the proxy.
	resp, err := c.h.Get(origin + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, h := range []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}

	// --- First-run setup using the token from the server log ---
	var token string
	waitFor(t, 60*time.Second, "setup token in logs", func() bool {
		m := regexp.MustCompile(`one-time setup token:\s+([A-Za-z0-9_-]{20,})`).FindStringSubmatch(s.compose("logs", "--no-color", "--no-log-prefix", "server"))
		if m != nil {
			token = m[1]
		}
		return token != ""
	})
	st, b := c.do("POST", "/setup/begin", map[string]any{"setup_token": token, "email": "admin@example.com"})
	if st != 200 {
		t.Fatalf("setup begin: %d %v", st, b)
	}
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b["totp_secret"].(string))
	step := auth.TOTPStep(time.Now())
	st, b = c.do("POST", "/setup/complete", map[string]any{"setup_token": token, "org_name": "IT", "display_name": "Ada",
		"email": "admin@example.com", "password": password, "root_passphrase": "integration-root-passphrase", "totp_code": auth.TOTPCode(secret, step)})
	if st != 200 {
		t.Fatalf("setup complete: %d %v", st, b)
	}
	st, b = c.do("POST", "/auth/login", map[string]any{"email": "admin@example.com", "password": password})
	if st != 200 {
		t.Fatalf("login: %d %v", st, b)
	}
	c.csrf = b["csrf_token"].(string)
	st, b = c.do("POST", "/auth/mfa", map[string]any{"code": auth.TOTPCode(secret, step+1)})
	if st != 200 {
		t.Fatalf("mfa: %d %v", st, b)
	}
	c.csrf = b["csrf_token"].(string)

	// --- The stack created its own master key (decision D109): nothing works until the administrator has saved it ---
	if st, _ := c.do("GET", "/devices", nil); st != 403 {
		t.Fatalf("before the master key is saved, other calls must be refused: HTTP %d", st)
	}
	st, b = c.do("GET", "/security/master-key", nil)
	if st != 200 {
		t.Fatalf("show master key: %d %v", st, b)
	}
	shownKey, _ := b["key"].(string)
	if !regexp.MustCompile(`^([0-9a-f]{8}-){7}[0-9a-f]{8}$`).MatchString(shownKey) {
		t.Fatalf("master key shown in an unexpected format: %q", shownKey)
	}
	// The same key is what the server container actually uses.
	if out := s.compose("exec", "-T", "server", "/librepatch-server", "show-master-key"); !strings.Contains(out, shownKey) {
		t.Fatalf("show-master-key does not match the key shown in the console:\n%s", out)
	}
	if st, b = c.do("POST", "/security/master-key/acknowledge", map[string]any{"confirm": shownKey[len(shownKey)-6:]}); st != 204 {
		t.Fatalf("acknowledge master key: %d %v", st, b)
	}

	// The server must record the client IP forwarded by Caddy, never Caddy's own.
	_, au := c.do("GET", "/audit?limit=5", nil)
	for _, it := range au["items"].([]any) {
		if ip := it.(map[string]any)["actor_ip"].(string); ip == "" || ip == "172.31.251.10" {
			t.Errorf("audit recorded actor IP %q (want the forwarded client address)", ip)
		}
	}
	// A client-supplied X-Forwarded-For must not let callers choose their IP.
	spoof, _ := http.NewRequest("POST", origin+"/api/v1/auth/login", strings.NewReader(`{"email":"nobody@example.com","password":"x"}`))
	spoof.Header.Set("Content-Type", "application/json")
	spoof.Header.Set("Origin", origin)
	spoof.Header.Set("X-Forwarded-For", "203.0.113.77")
	if r, err := c.h.Do(spoof); err == nil {
		r.Body.Close()
	}
	_, au = c.do("GET", "/audit?limit=5", nil)
	for _, it := range au["items"].([]any) {
		if ip := it.(map[string]any)["actor_ip"].(string); ip == "203.0.113.77" {
			t.Errorf("spoofed X-Forwarded-For was trusted")
		}
	}

	st, b = c.do("POST", "/enrollment-tokens", map[string]any{"name": "it", "max_uses": 2, "expires_in_hours": 1, "require_approval": false})
	if st != 201 {
		t.Fatalf("token: %d %v", st, b)
	}
	enrollment := b["enrollment_string"].(string)

	// --- A real agent process enrolls through the published gateway port ---
	agentBin := filepath.Join(s.dir, "librepatch-agent")
	run(t, repoRoot(), "go", "build", "-o", agentBin, "./cmd/librepatch-agent")
	agentDir := filepath.Join(s.dir, "agent")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	agent := exec.CommandContext(ctx, agentBin, "run", "--data-dir", agentDir, "--token", enrollment)
	var agentOut bytes.Buffer
	agent.Stdout, agent.Stderr = &agentOut, &agentOut
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		_ = agent.Wait()
		if t.Failed() {
			t.Log("agent output:\n" + agentOut.String())
		}
	}()
	var deviceID string
	waitFor(t, 60*time.Second, "agent connected", func() bool {
		st, _ := core.ReadStatus(agentDir)
		deviceID = st.DeviceID
		return st.State == "connected"
	})
	waitFor(t, 30*time.Second, "device online with hardware", func() bool {
		_, d := c.do("GET", "/devices/"+deviceID, nil)
		return d["online"] == true && d["hardware"] != nil
	})

	// --- Software deployment through the real stack: a 3 MiB upload passes Caddy (1 MB default
	// limit elsewhere), lands on the content volume, and the agent installs it from the gateway. ---
	script := "#!/bin/sh\nmkdir -p \"$(dirname \"$0\")/../../pf/Acme\"\necho ok > \"$(dirname \"$0\")/../../pf/Acme/tool.txt\"\nexit 0\n"
	body := append([]byte(script), bytes.Repeat([]byte("# padding\n"), 3<<20/10)...)
	upReq, _ := http.NewRequest("POST", origin+"/api/v1/catalog/content", bytes.NewReader(body))
	upReq.Header.Set("Origin", origin)
	upReq.Header.Set("Content-Type", "application/octet-stream")
	upReq.Header.Set("X-File-Name", "install.sh")
	upReq.Header.Set("X-CSRF-Token", c.csrf)
	upResp, err := c.h.Do(upReq)
	if err != nil {
		t.Fatal(err)
	}
	var up map[string]any
	_ = json.NewDecoder(upResp.Body).Decode(&up)
	upResp.Body.Close()
	if upResp.StatusCode != 201 {
		t.Fatalf("upload through the proxy: %d %v", upResp.StatusCode, up)
	}
	st, b = c.do("POST", "/catalog/custom", map[string]any{"identifier": "Acme.Tool", "name": "Acme Tool", "version": "1.0.0",
		"sha256": up["sha256"], "file_name": "install.sh", "type": "exe", "arch": "neutral", "scope": "machine", "args": []string{"/silent"},
		"detection": []map[string]any{{"kind": "file", "key": "%ProgramFiles%/Acme/tool.txt"}}})
	if st != 201 {
		t.Fatalf("custom package: %d %v", st, b)
	}
	st, b = c.do("POST", "/deployments", map[string]any{"name": "compose test", "action": "install", "package_id": b["package_id"],
		"scope": "machine", "device_ids": []string{deviceID}})
	if st != 201 {
		t.Fatalf("deployment: %d %v", st, b)
	}
	depID := b["deployment_id"].(string)
	waitFor(t, 60*time.Second, "deployment completed", func() bool {
		_, d := c.do("GET", "/deployments/"+depID, nil)
		return d["status"] == "completed"
	})
	_, jb := c.do("GET", "/deployments/"+depID+"/jobs", nil)
	if js, _ := jb["items"].([]any); len(js) != 1 || js[0].(map[string]any)["status"] != "succeeded" {
		t.Fatalf("job results: %v", jb)
	}
	if _, err := os.Stat(filepath.Join(agentDir, "pf", "Acme", "tool.txt")); err != nil {
		t.Fatalf("installer did not run: %v", err)
	}

	// --- Revocation cuts the agent off immediately ---
	if st, _ := c.do("POST", "/devices/"+deviceID+"/revoke", map[string]any{"reason": "integration"}); st != 204 {
		t.Fatalf("revoke: %d", st)
	}
	waitFor(t, 15*time.Second, "agent rejected", func() bool {
		st, _ := core.ReadStatus(agentDir)
		return st.State == "rejected"
	})
	_, d := c.do("GET", "/devices/"+deviceID, nil)
	if d["online"] != false || d["status"] != "revoked" {
		t.Fatalf("device after revoke: %v", d)
	}

	// --- Audit chain verifies with the admin CLI inside the container ---
	out := s.compose("exec", "-T", "server", "/librepatch-server", "admin", "verify-audit")
	if !strings.Contains(out, "audit chain intact") {
		t.Fatalf("verify-audit: %s", out)
	}
	fmt.Println(strings.TrimSpace(out))

	// --- The long-running server must not hold the schema-owner credential (docs/THREAT-MODEL.md T-SRV-4) ---
	mounts := inspect("server", "{{json .Mounts}}")
	if strings.Contains(mounts, "secrets_owner") || strings.Contains(mounts, "secrets_pg") {
		t.Errorf("server container has owner/superuser secrets mounted: %s", mounts)
	}
	if !strings.Contains(mounts, "secrets_app") || !strings.Contains(mounts, "secrets_key") {
		t.Errorf("server container lacks its own login or the master key: %s", mounts)
	}
	// The database container never sees the master key.
	if pm := inspect("postgres", "{{json .Mounts}}"); strings.Contains(pm, "secrets_key") {
		t.Errorf("postgres container has the master key mounted: %s", pm)
	}
	// ... while the one-shot maintenance service can still back the stack up and verify the archive.
	passFile := filepath.Join(s.dir, "backup-pass")
	if err := os.WriteFile(passFile, []byte("integration-test-passphrase-123"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := []string{"compose", "-p", project, "-f", filepath.Join(s.dir, "docker-compose.yml"), "--env-file", filepath.Join(s.dir, ".env"),
		"run", "--rm", "--no-deps", "-T", "-v", passFile + ":/pass:ro", "maintenance"}
	bk := exec.Command("docker", append(append([]string{}, base...), "backup", "--out", "-", "--passphrase-file", "/pass")...)
	var archive, bkErr bytes.Buffer
	bk.Stdout, bk.Stderr = &archive, &bkErr
	if err := bk.Run(); err != nil || archive.Len() < 1000 {
		t.Fatalf("backup via maintenance: %v (%d bytes)\n%s", err, archive.Len(), bkErr.String())
	}
	vf := exec.Command("docker", append(append([]string{}, base...), "backup", "--verify", "-", "--passphrase-file", "/pass")...)
	vf.Stdin = bytes.NewReader(archive.Bytes())
	if vout, err := vf.CombinedOutput(); err != nil {
		t.Fatalf("backup --verify: %v\n%s", err, vout)
	}
}
