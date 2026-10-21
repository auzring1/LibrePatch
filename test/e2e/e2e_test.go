// Package e2e runs the real server (HTTP API + mTLS gateway) and the real
// agent core in-process against a real PostgreSQL database.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/config"
	"github.com/auzring1/librepatch/internal/agent/core"
	"github.com/auzring1/librepatch/internal/agent/keystore"
	"github.com/auzring1/librepatch/internal/agent/store"
	"github.com/auzring1/librepatch/internal/server/app"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/auth"
	sconfig "github.com/auzring1/librepatch/internal/server/config"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

// ---------- harness ----------

type harness struct {
	t      *testing.T
	app    *app.App
	db     *pgtest.DB
	base   string
	origin string
	http   *http.Client
	csrf   string
	totp   []byte
	step   int64
}

func newHarness(t *testing.T) *harness { return newHarnessWith(t, 90*24*time.Hour) }

func newHarnessWith(t *testing.T, certLife time.Duration) *harness {
	return newHarnessCfg(t, certLife, nil)
}

// newHarnessCfg is newHarnessWith with a hook to adjust the server configuration.
func newHarnessCfg(t *testing.T, certLife time.Duration, mutate func(*sconfig.Config)) *harness {
	return newHarnessPrep(t, certLife, mutate, nil)
}

// newHarnessPrep also lets a test prepare the database (with the master key the server will use) before the server starts.
func newHarnessPrep(t *testing.T, certLife time.Duration, mutate func(*sconfig.Config), prepare func(db *pgtest.DB, key []byte)) *harness {
	t.Helper()
	db := pgtest.New(t)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	if prepare != nil {
		prepare(db, key)
	}
	pub, _ := url.Parse("http://localhost")
	cfg := &sconfig.Config{
		DevMode: true, HTTPAddr: "127.0.0.1:0", PublicURL: pub, GatewayAddr: "127.0.0.1:0",
		GatewayPublicAddr: "localhost:8443", GatewaySANs: []string{"localhost", "127.0.0.1"},
		DatabaseURL: db.AppURL, MasterKey: key,
		DeviceCertLifetime: certLife, DeviceRenewGrace: 180 * 24 * time.Hour,
		EnrollPollInterval: time.Second, HeartbeatInterval: 2 * time.Second,
		SessionIdleTimeout: 30 * time.Minute, SessionAbsTimeout: 12 * time.Hour, LogLevel: "warn",
		ContentDir: t.TempDir(), WingetSource: "off",
	}
	if mutate != nil {
		mutate(cfg)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	ctx, cancel := context.WithCancel(context.Background())
	a, err := app.New(ctx, cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = a.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; a.Close() })
	waitFor(t, 5*time.Second, "http listening", func() bool { return a.HTTPAddr() != "" })
	jar, _ := cookiejar.New(nil)
	return &harness{t: t, app: a, db: db, base: "http://" + a.HTTPAddr(), origin: cfg.Origin(),
		http: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
}

func waitFor(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (h *harness) do(method, path string, body any, hdr map[string]string) (int, map[string]any) {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", h.origin)
	if h.csrf != "" {
		req.Header.Set("X-CSRF-Token", h.csrf)
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := h.http.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (h *harness) code(offset int64) string { return auth.TOTPCode(h.totp, h.step+offset) }

const adminPassword = "Granite-Lantern-Pickle-42"

// setupAndLogin completes first-run setup and signs in with MFA.
func (h *harness) setupAndLogin() {
	t := h.t
	if st, b := h.do("GET", "/api/v1/setup/status", nil, nil); st != 200 || b["setup_required"] != true {
		t.Fatalf("setup status: %d %v", st, b)
	}
	if st, _ := h.do("POST", "/api/v1/setup/begin", map[string]any{"setup_token": "wrong", "email": "admin@example.com"}, nil); st != 403 {
		t.Fatalf("bad setup token: %d", st)
	}
	st, b := h.do("POST", "/api/v1/setup/begin", map[string]any{"setup_token": h.app.SetupToken(), "email": "admin@example.com"}, nil)
	if st != 200 {
		t.Fatalf("setup begin: %d %v", st, b)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b["totp_secret"].(string))
	if err != nil {
		t.Fatal(err)
	}
	h.totp, h.step = secret, auth.TOTPStep(time.Now())
	req := map[string]any{"setup_token": h.app.SetupToken(), "org_name": "Acme", "display_name": "Ada Admin",
		"email": "admin@example.com", "password": "password1234", "root_passphrase": "a-long-root-ca-passphrase", "totp_code": h.code(0)}
	if st, _ := h.do("POST", "/api/v1/setup/complete", req, nil); st != 400 {
		t.Fatalf("weak password accepted: %d", st)
	}
	req["password"] = adminPassword
	st, b = h.do("POST", "/api/v1/setup/complete", req, nil)
	if st != 200 || len(b["recovery_codes"].([]any)) != 10 {
		t.Fatalf("setup complete: %d %v", st, b)
	}
	select {
	case <-h.app.GatewayReady:
	case <-time.After(5 * time.Second):
		t.Fatal("gateway did not start after setup")
	}
	if st, _ := h.do("POST", "/api/v1/setup/complete", req, nil); st != 409 && st != 403 {
		t.Fatalf("second setup allowed: %d", st)
	}

	// Login: wrong password, then password + MFA. The setup step was consumed,
	// so the same code must be rejected (replay) and the next step accepted.
	if st, _ := h.do("POST", "/api/v1/auth/login", map[string]any{"email": "admin@example.com", "password": "nope-nope-nope"}, nil); st != 401 {
		t.Fatalf("bad password: %d", st)
	}
	st, b = h.do("POST", "/api/v1/auth/login", map[string]any{"email": "admin@example.com", "password": adminPassword}, nil)
	if st != 200 || b["mfa"] != "verify" {
		t.Fatalf("login: %d %v", st, b)
	}
	h.csrf = b["csrf_token"].(string)
	if st, _ := h.do("GET", "/api/v1/devices", nil, nil); st != 401 {
		t.Fatalf("pre-MFA session must not access the API: %d", st)
	}
	if st, _ := h.do("POST", "/api/v1/auth/mfa", map[string]any{"code": h.code(0)}, nil); st != 401 {
		t.Fatalf("replayed TOTP accepted: %d", st)
	}
	st, b = h.do("POST", "/api/v1/auth/mfa", map[string]any{"code": h.code(1)}, nil)
	if st != 200 {
		t.Fatalf("mfa: %d %v", st, b)
	}
	h.csrf = b["csrf_token"].(string)
	if st, b := h.do("GET", "/api/v1/auth/session", nil, nil); st != 200 || b["user"].(map[string]any)["email"] != "admin@example.com" {
		t.Fatalf("session: %d %v", st, b)
	}
}

func (h *harness) createToken(name string, uses int, approval bool) string {
	st, b := h.do("POST", "/api/v1/enrollment-tokens", map[string]any{"name": name, "max_uses": uses,
		"expires_in_hours": 1, "require_approval": approval}, nil)
	if st != 201 {
		h.t.Fatalf("create token: %d %v", st, b)
	}
	if !strings.Contains(b["install_command"].(string), "librepatch-agent.exe install --server") {
		h.t.Fatalf("install command: %v", b["install_command"])
	}
	return b["enrollment_string"].(string)
}

func (h *harness) devices() []map[string]any {
	st, b := h.do("GET", "/api/v1/devices", nil, nil)
	if st != 200 {
		h.t.Fatalf("devices: %d %v", st, b)
	}
	var out []map[string]any
	for _, d := range b["items"].([]any) {
		out = append(out, d.(map[string]any))
	}
	return out
}

func (h *harness) device(id string) map[string]any {
	st, b := h.do("GET", "/api/v1/devices/"+id, nil, nil)
	if st != 200 {
		h.t.Fatalf("device: %d %v", st, b)
	}
	return b
}

// ---------- fake hardware ----------

type fakeHW struct {
	mu     sync.Mutex
	serial string
	uuid   string
	host   string
}

func (f *fakeHW) Collect(context.Context) (*agentv1.HardwareInventory, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &agentv1.HardwareInventory{Hostname: f.host, OsCaption: "Windows 11 Pro", OsBuild: 26100, OsUbr: 2033,
		Arch: "amd64", Manufacturer: "Contoso", Model: "Laptop 9", Serial: f.serial, SmbiosUuid: f.uuid,
		Chassis: "notebook", CpuModel: "Test CPU", CpuLogicalCores: 8, RamBytes: 16 << 30,
		Disks:      []*agentv1.Disk{{Mount: "C:", Filesystem: "NTFS", SizeBytes: 512 << 30, FreeBytes: 100 << 30}},
		Interfaces: []*agentv1.NetInterface{{Name: "Ethernet", Mac: "00:11:22:33:44:55", Addresses: []string{"10.0.0.5"}}}}, nil
}

func (f *fakeHW) Heartbeat(context.Context) (*agentv1.Heartbeat, error) {
	return &agentv1.Heartbeat{UptimeS: 1234, LoggedOnUser: `ACME\ada`}, nil
}

type testAgent struct {
	dir    string
	agent  *core.Agent
	cancel context.CancelFunc
	done   chan struct{}
	st     *store.Store
}

func (h *harness) startAgent(enrollment string, hw *fakeHW, now func() time.Time, opts ...func(*core.Agent, *store.Store)) *testAgent {
	h.t.Helper()
	dir := h.t.TempDir()
	cfg, err := config.FromBundle(enrollment, h.app.GatewayAddr())
	if err != nil {
		h.t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		h.t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		h.t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil)).With("agent", hw.host)
	}
	a := &core.Agent{Cfg: cfg, CfgPath: cfgPath, DataDir: dir, Store: st, Keys: keystore.Default(dir), HW: hw,
		Log: log, Version: "test", KeyPrefix: uniquePrefix(h.t), BackoffBase: 50 * time.Millisecond, BackoffMax: 500 * time.Millisecond,
		PendingPoll: 300 * time.Millisecond, Now: now}
	for _, o := range opts {
		o(a, st)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ta := &testAgent{dir: dir, agent: a, cancel: cancel, done: make(chan struct{}), st: st}
	go func() { _ = a.Run(ctx); close(ta.done) }()
	h.t.Cleanup(ta.stop)
	return ta
}

func (ta *testAgent) stop() {
	select {
	case <-ta.done:
		return
	default:
	}
	ta.cancel()
	<-ta.done
	_ = ta.st.Close()
}

func (ta *testAgent) state() string {
	s, _ := core.ReadStatus(ta.dir)
	return s.State
}

func (ta *testAgent) identity(t *testing.T) *store.Identity {
	id, err := ta.st.Identity()
	if err != nil || id == nil {
		t.Fatalf("identity: %v", err)
	}
	return id
}

// ---------- tests ----------

func TestEndToEnd(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()

	// SSE: subscribe before the agent connects and expect a device.online event.
	sseEvents := make(chan string, 32)
	sseCtx, sseCancel := context.WithCancel(context.Background())
	defer sseCancel()
	req, _ := http.NewRequestWithContext(sseCtx, "GET", h.base+"/api/v1/events", nil)
	sseClient := &http.Client{Jar: h.http.Jar}
	resp, err := sseClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("sse: %v %v", err, resp)
	}
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "event: ") {
				sseEvents <- strings.TrimPrefix(sc.Text(), "event: ")
			}
		}
	}()

	// --- Auto-approved enrollment ---
	enr := h.createToken("auto", 5, false)
	hw1 := &fakeHW{host: "PC-001", serial: "SN-001", uuid: "UUID-001"}
	a1 := h.startAgent(enr, hw1, nil)
	waitFor(t, 15*time.Second, "agent 1 connected", func() bool { return a1.state() == "connected" })
	devs := h.devices()
	if len(devs) != 1 || devs[0]["status"] != "active" {
		t.Fatalf("devices: %v", devs)
	}
	id1 := devs[0]["id"].(string)
	waitFor(t, 10*time.Second, "device online + hardware", func() bool {
		d := h.device(id1)
		hw, _ := d["hardware"].(map[string]any)
		return d["online"] == true && hw != nil && hw["manufacturer"] == "Contoso" && d["os_build"] == "26100.2033"
	})
	waitFor(t, 5*time.Second, "SSE device.online", func() bool {
		for {
			select {
			case e := <-sseEvents:
				if e == "device.online" {
					return true
				}
			default:
				return false
			}
		}
	})
	// The enrollment secret is erased from disk after use.
	if b, _ := os.ReadFile(filepath.Join(a1.dir, "config.json")); bytes.Contains(b, []byte("enrollment_token")) {
		t.Fatal("enrollment token still present in config.json")
	}
	if a1.identity(t).DeviceID != id1 {
		t.Fatal("agent/server device id mismatch")
	}
	if len(a1.identity(t).SigningDER) != 1 {
		t.Fatal("agent did not store the job-signing certificate")
	}

	// --- Re-enrollment of the same hardware requires approval ---
	a1dup := h.startAgent(enr, &fakeHW{host: "PC-001", serial: "SN-001", uuid: "UUID-001"}, nil)
	waitFor(t, 10*time.Second, "duplicate pending", func() bool { return a1dup.state() == "pending_approval" })
	var dupID string
	for _, d := range h.devices() {
		if d["status"] == "pending" {
			dupID = d["id"].(string)
			if d["replaces_device_id"] != id1 {
				t.Fatalf("pending duplicate should reference %s: %v", id1, d)
			}
		}
	}
	if dupID == "" {
		t.Fatal("no pending device for re-enrollment")
	}
	a1dup.stop()

	// --- Approval flow ---
	enrApproval := h.createToken("approval", 1, true)
	a2 := h.startAgent(enrApproval, &fakeHW{host: "PC-002", serial: "SN-002", uuid: "UUID-002"}, nil)
	waitFor(t, 10*time.Second, "agent 2 pending", func() bool { return a2.state() == "pending_approval" })
	id2 := a2.identity(t).DeviceID
	if st, _ := h.do("POST", "/api/v1/devices/"+id2+"/approve", map[string]any{}, nil); st != 204 {
		t.Fatalf("approve: %d", st)
	}
	waitFor(t, 15*time.Second, "agent 2 connected after approval", func() bool { return a2.state() == "connected" })

	// Token exhausted (max_uses=1): a further enrollment is rejected.
	a3 := h.startAgent(enrApproval, &fakeHW{host: "PC-003", serial: "SN-003", uuid: "UUID-003"}, nil)
	waitFor(t, 10*time.Second, "exhausted token rejected", func() bool { return a3.state() == "error" })
	a3.stop()

	// --- CSRF / origin protections on a state-changing call ---
	if st, _ := h.do("POST", "/api/v1/devices/"+id2+"/revoke", map[string]any{}, map[string]string{"X-CSRF-Token": ""}); st != 403 {
		t.Fatalf("missing CSRF token accepted: %d", st)
	}
	if st, _ := h.do("POST", "/api/v1/devices/"+id2+"/revoke", map[string]any{}, map[string]string{"Origin": "https://evil.example"}); st != 403 {
		t.Fatalf("cross-origin request accepted: %d", st)
	}

	// --- Immediate revocation ---
	idn2 := a2.identity(t)
	if st, _ := h.do("POST", "/api/v1/devices/"+id2+"/revoke", map[string]any{"reason": "lost laptop"}, nil); st != 204 {
		t.Fatalf("revoke: %d", st)
	}
	waitFor(t, 15*time.Second, "agent 2 told it is revoked", func() bool { return a2.state() == "rejected" })
	waitFor(t, 5*time.Second, "device 2 offline", func() bool { return h.device(id2)["online"] == false })
	if err := mtlsConnect(h, a2, idn2); err == nil {
		t.Fatal("revoked device could still open a stream")
	}

	// --- Deleting devices: only revoked ones, everything of theirs goes ---
	if st, _ := h.do("DELETE", "/api/v1/devices/"+id1, nil, nil); st != 409 {
		t.Fatalf("an active device was deletable: %d", st)
	}
	if st, _ := h.do("DELETE", "/api/v1/devices/"+id2, nil, nil); st != 204 {
		t.Fatalf("delete revoked device: %d", st)
	}
	if st, _ := h.do("GET", "/api/v1/devices/"+id2, nil, nil); st != 404 {
		t.Fatalf("deleted device still readable: %d", st)
	}
	var left int
	_ = h.db.Pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM device_certs WHERE device_id=$1) + (SELECT count(*) FROM devices WHERE id=$1)`, id2).Scan(&left)
	if left != 0 {
		t.Fatalf("device rows left behind: %d", left)
	}
	if err := mtlsConnect(h, a2, idn2); err == nil {
		t.Fatal("a deleted device could open a stream")
	}
	if st, b := h.do("POST", "/api/v1/devices/delete", map[string]any{"ids": []string{id1, id2}}, nil); st != 200 || b["deleted"].(float64) != 0 || b["skipped"].(float64) != 2 {
		t.Fatalf("bulk delete of an active and a missing device: %d %v", st, b)
	}

	// --- Enrollment with a bad token is rejected generically ---
	if code := enrollRaw(h, "bogus-token-bogus-token-bogus-token-bogus-token"); code != codes.PermissionDenied {
		t.Fatalf("bad token: %v", code)
	}

	// --- Audit log covers the story and its chain is intact ---
	st, b := h.do("GET", "/api/v1/audit?limit=500", nil, nil)
	if st != 200 {
		t.Fatalf("audit: %d", st)
	}
	seen := map[string]bool{}
	for _, it := range b["items"].([]any) {
		seen[it.(map[string]any)["action"].(string)] = true
	}
	for _, want := range []string{"setup.complete", "auth.login", "enrollment_token.create", "device.enroll",
		"device.approve", "device.revoke", "device.delete", "device.certificate_issue"} {
		if !seen[want] {
			t.Errorf("audit missing %q (have %v)", want, seen)
		}
	}
	res, err := audit.Verify(context.Background(), dbq.New(h.db.Pool))
	if err != nil || res.BrokenAt != 0 || res.Checked < 10 {
		t.Fatalf("audit chain: %+v %v", res, err)
	}

	// --- Logout ends the session ---
	if st, _ := h.do("POST", "/api/v1/auth/logout", map[string]any{}, nil); st != 204 {
		t.Fatalf("logout: %d", st)
	}
	if st, _ := h.do("GET", "/api/v1/devices", nil, nil); st != 401 {
		t.Fatalf("after logout: %d", st)
	}
}

// mtlsConnect opens a raw Connect stream with an agent's stored identity.
func mtlsConnect(h *harness, ta *testAgent, id *store.Identity) error {
	root, _ := x509.ParseCertificate(id.RootDER)
	key, err := keystore.Default(ta.dir).Open(id.KeyName)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	tc := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "127.0.0.1", RootCAs: pool,
		Certificates: []tls.Certificate{{Certificate: [][]byte{id.CertDER, id.IssuingDER}, PrivateKey: key}}}
	conn, err := grpc.NewClient("passthrough:///"+h.app.GatewayAddr(), grpc.WithTransportCredentials(credentials.NewTLS(tc)))
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := agentv1.NewAgentChannelServiceClient(conn).Connect(ctx)
	if err != nil {
		return err
	}
	if err := stream.Send(&agentv1.ConnectRequest{Msg: &agentv1.ConnectRequest_Hello{Hello: &agentv1.Hello{DeviceId: id.DeviceID}}}); err != nil {
		return err
	}
	_, err = stream.Recv()
	return err
}

// enrollRaw calls Enroll with an arbitrary token over pinned TLS.
func enrollRaw(h *harness, token string) codes.Code {
	a := h.app.Authority()
	pool := x509.NewCertPool()
	pool.AddCert(a.Root)
	tc := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "127.0.0.1", RootCAs: pool}
	conn, err := grpc.NewClient("passthrough:///"+h.app.GatewayAddr(), grpc.WithTransportCredentials(credentials.NewTLS(tc)))
	if err != nil {
		return codes.Unknown
	}
	defer conn.Close()
	key, _, _ := keystore.Default(h.t.TempDir()).Create(uniquePrefix(h.t) + "1")
	csr, _ := keystore.CSR(key)
	_, err = agentv1.NewEnrollmentServiceClient(conn).Enroll(context.Background(), &agentv1.EnrollRequest{Token: token, CsrDer: csr, Hostname: "x"})
	return status.Code(err)
}

// TestCertificateRenewal uses 12-second certificates: the agent must renew
// on its own before expiry, retire the old key, and also recover from an
// already-expired certificate inside the grace period.
func TestCertificateRenewal(t *testing.T) {
	h := newHarnessWith(t, 12*time.Second)
	h.setupAndLogin()
	enr := h.createToken("renew", 1, false)
	ta := h.startAgent(enr, &fakeHW{host: "PC-R", serial: "SN-R", uuid: "UUID-R"}, nil)
	waitFor(t, 10*time.Second, "connected", func() bool { return ta.state() == "connected" })
	first := ta.identity(t)
	devID := uuid.MustParse(first.DeviceID)

	// Proactive renewal (renew at < 1/3 lifetime remaining, checked each heartbeat).
	waitFor(t, 20*time.Second, "proactive renewal", func() bool {
		id, _ := ta.st.Identity()
		return id != nil && id.KeyGen >= 2 && h.app.Hub.Online(devID)
	})
	// The agent saves the new identity first and deletes the old key right after, so give the delete a moment
	// (a real CNG key takes noticeably longer to delete than a file).
	waitFor(t, 10*time.Second, "old device key deleted", func() bool {
		_, err := keystore.Default(ta.dir).Open(ta.agent.KeyPrefix + "1")
		return errors.Is(err, keystore.ErrNotFound)
	})
	waitFor(t, 10*time.Second, "old certificate superseded", func() bool {
		var n int
		_ = h.db.Pool.QueryRow(context.Background(),
			`SELECT count(*) FROM device_certs WHERE device_id=$1 AND revoke_reason='superseded'`, devID).Scan(&n)
		return n >= 1
	})

	// Expired certificate inside the grace period: stop the agent until its
	// certificate has expired, then restart; it must renew and reconnect.
	ta.stop()
	st, err := store.Open(filepath.Join(ta.dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := st.Identity()
	_ = st.Close()
	cert, _ := x509.ParseCertificate(id.CertDER)
	time.Sleep(time.Until(cert.NotAfter.Add(time.Second)))
	ta2 := h.restartAgent(ta)
	waitFor(t, 20*time.Second, "renewed after expiry", func() bool {
		nid, _ := ta2.st.Identity()
		return nid != nil && nid.KeyGen > id.KeyGen && h.app.Hub.Online(devID)
	})
	var renewedExpired int
	_ = h.db.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE action='device.certificate_renew' AND details->>'was_expired'='true'`).Scan(&renewedExpired)
	if renewedExpired != 1 {
		t.Fatalf("expected one expired-certificate renewal in the audit log, got %d", renewedExpired)
	}
}

// restartAgent starts a new agent process on an existing data directory.
func (h *harness) restartAgent(old *testAgent, opts ...func(*core.Agent, *store.Store)) *testAgent {
	h.t.Helper()
	cfg, err := config.Load(filepath.Join(old.dir, "config.json"))
	if err != nil {
		h.t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(old.dir, "state.db"))
	if err != nil {
		h.t.Fatal(err)
	}
	a := &core.Agent{Cfg: cfg, CfgPath: filepath.Join(old.dir, "config.json"), DataDir: old.dir, Store: st,
		Keys: keystore.Default(old.dir), HW: old.agent.HW, Log: old.agent.Log, Version: "test", KeyPrefix: old.agent.KeyPrefix,
		BackoffBase: 50 * time.Millisecond, BackoffMax: 500 * time.Millisecond}
	for _, o := range opts {
		o(a, st)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ta := &testAgent{dir: old.dir, agent: a, cancel: cancel, done: make(chan struct{}), st: st}
	go func() { _ = a.Run(ctx); close(ta.done) }()
	h.t.Cleanup(ta.stop)
	return ta
}

// uniquePrefix gives each test agent its own key names. On Windows the keys
// are real CNG machine keys, so they are deleted when the test ends.
func uniquePrefix(t *testing.T) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	p := "LibrePatch-Test-" + hex.EncodeToString(b) + "-"
	t.Cleanup(func() {
		ks := keystore.Default(t.TempDir())
		for g := 1; g <= 10; g++ {
			_ = ks.Delete(fmt.Sprintf("%s%d", p, g))
		}
	})
	return p
}
