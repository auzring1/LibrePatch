package jobs

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/selfupdate"
	"github.com/auzring1/librepatch/internal/shared/release"
)

// fakeUpdater records the slot operations of an agent update.
type fakeUpdater struct {
	mu        sync.Mutex
	slot      string
	calls     []string
	armed     bool
	armedAt   time.Time
	failArm   bool
	failSwitc bool
}

func (f *fakeUpdater) rec(s string) { f.mu.Lock(); f.calls = append(f.calls, s); f.mu.Unlock() }
func (f *fakeUpdater) called(s string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, s) {
			return true
		}
	}
	return false
}
func (f *fakeUpdater) Current() (string, string, error) {
	return f.slot, "/prog/slot-" + f.slot + "/agent", nil
}
func (f *fakeUpdater) StageInactive(string) (string, string, error) {
	f.rec("stage")
	o := "b"
	if f.slot == "b" {
		o = "a"
	}
	return o, "/prog/slot-" + o + "/agent", nil
}
func (f *fakeUpdater) Switch(slot string) error {
	f.rec("switch:" + slot)
	if f.failSwitc {
		return errors.New("scm refused")
	}
	f.slot = slot
	return nil
}
func (f *fakeUpdater) ScheduleRollback(at time.Time, _ string) error {
	if f.failArm {
		return errors.New("task scheduler unavailable")
	}
	f.rec("arm")
	f.armed, f.armedAt = true, at
	return nil
}
func (f *fakeUpdater) CancelRollback() error { f.rec("disarm"); f.armed = false; return nil }
func (f *fakeUpdater) Restart() error        { f.rec("restart"); return nil }
func (f *fakeUpdater) Bounce() error         { f.rec("bounce"); return nil }

type suRig struct {
	*rig
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	dir  string
	bin  []byte
}

func newSURig(t *testing.T) *suRig {
	r := newRig(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := &suRig{rig: r, pub: pub, priv: priv, dir: t.TempDir(), bin: []byte("MZ new agent binary")}
	r.p.su = &fakeUpdater{slot: "a"}
	r.e.DataDir, r.e.Version = s.dir, "1.0.0"
	r.e.ReleaseKeys = []ed25519.PublicKey{pub}
	r.f.data[""] = s.bin
	r.p.runFn = func(spec RunSpec, _ string) (RunResult, error) {
		if len(spec.Args) == 1 && spec.Args[0] == "version" {
			return RunResult{LogTail: brand.VersionBanner + " 1.1.0 (abc)\\n"}, nil
		}
		return RunResult{}, nil
	}
	return s
}

func (s *suRig) manifest(version string, mut func(*release.Manifest)) *release.Manifest {
	m := &release.Manifest{Format: 1, Product: release.Product, Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH,
		SHA256: hex.EncodeToString(sum(s.bin)), Size: uint64(len(s.bin))}
	if mut != nil {
		mut(m)
	}
	return m
}

func (s *suRig) env(id string, m *release.Manifest, key ed25519.PrivateKey) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
	mb, err := release.Marshal(m)
	if err != nil {
		s.t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	kid, _ := hex.DecodeString(release.KeyID(pub))
	env := &agentv1.JobEnvelope{Version: 1, JobId: id, OrgId: "o", DeviceId: "d", Type: agentv1.JobType_JOB_TYPE_AGENT_UPDATE,
		IssuedAt: s.now.Unix(), NotBefore: s.now.Unix(), ExpiresAt: s.now.Add(24 * time.Hour).Unix(), Nonce: make([]byte, 16),
		Body: &agentv1.JobEnvelope_AgentUpdate{AgentUpdate: &agentv1.AgentUpdateBody{Manifest: mb, Signature: release.Sign(key, mb), KeyId: kid}}}
	return s.sign(env), env
}

// restarted is a fresh engine of another version on the same store and data directory, like the
// service after it restarted into a new binary.
func (s *suRig) restarted(version string) *Engine {
	return &Engine{P: s.p, Store: s.e.Store, Report: s.rec, Fetch: s.f, Now: s.e.Now, Local: time.UTC, DataDir: s.dir, Version: version, ReleaseKeys: s.e.ReleaseKeys}
}

func (s *suRig) lastMsg(id string) string {
	if u := s.rec.last(id); u != nil && u.Result != nil {
		return u.Result.Message
	}
	return ""
}

func TestAgentUpdateSwitchesSlotsAndConfirmsAfterRestart(t *testing.T) {
	s := newSURig(t)
	se, env := s.env("u1", s.manifest("1.1.0", nil), s.priv)
	s.e.Accept(se, env)
	s.tick()

	su := s.p.su
	for _, c := range []string{"stage", "arm", "switch:b", "restart"} {
		if !su.called(c) {
			t.Fatalf("expected %q in %v", c, su.calls)
		}
	}
	if !su.armed || su.armedAt.Unix() != s.now.Add(selfupdate.RollbackWindow).Unix() {
		t.Fatalf("rollback task not armed for the window: %v %v", su.armed, su.armedAt)
	}
	st, err := selfupdate.Load(s.dir)
	if err != nil || st.Status != selfupdate.StatusSwitching || st.FromVersion != "1.0.0" || st.ToVersion != "1.1.0" || st.ToSlot != "b" {
		t.Fatalf("state: %+v %v", st, err)
	}
	if s.state("u1") != agentv1.JobState_JOB_STATE_RUNNING {
		t.Fatalf("job must stay running until the new version proves itself: %v", s.state("u1"))
	}
	// The loop must not run the job again, however often it ticks.
	s.tick()
	s.tick()
	if n := countCalls(su, "stage"); n != 1 {
		t.Fatalf("job ran %d times", n)
	}

	// "Restart": a new engine in the new version, same store and data directory.
	e2 := s.restarted("1.1.0")
	e2.SelfUpdateStartup()
	if s.state("u1") != agentv1.JobState_JOB_STATE_RUNNING {
		t.Fatal("startup alone must not confirm the update")
	}
	e2.SelfUpdateHealthy()
	if s.state("u1") != agentv1.JobState_JOB_STATE_SUCCEEDED || !strings.Contains(s.lastMsg("u1"), "1.0.0 to 1.1.0") {
		t.Fatalf("not confirmed: %v %q", s.state("u1"), s.lastMsg("u1"))
	}
	if su.armed {
		t.Fatal("the rollback task must be disarmed once healthy")
	}
	if _, err := selfupdate.Load(s.dir); !errors.Is(err, selfupdate.ErrNone) {
		t.Fatalf("state not cleared: %v", err)
	}
	// Healthy is idempotent.
	e2.SelfUpdateHealthy()
}

func countCalls(f *fakeUpdater, prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func TestAgentUpdateRollsBackWhenTheNewVersionNeverBecomesHealthy(t *testing.T) {
	s := newSURig(t)
	se, env := s.env("u2", s.manifest("1.1.0", nil), s.priv)
	s.e.Accept(se, env)
	s.tick()

	// Too early for the safety net.
	if _, err := selfupdate.RollbackCheck(s.dir, s.p.su, s.now.Add(time.Minute)); err == nil {
		t.Fatal("the rollback check must wait for the deadline")
	}
	msg, err := selfupdate.RollbackCheck(s.dir, s.p.su, s.now.Add(selfupdate.RollbackWindow+time.Second))
	if err != nil || !strings.Contains(msg, "did not become healthy") {
		t.Fatalf("%q %v", msg, err)
	}
	if s.p.su.slot != "a" || !s.p.su.called("bounce") {
		t.Fatalf("old slot not restored: slot %s calls %v", s.p.su.slot, s.p.su.calls)
	}
	// The restored (old) agent starts and reports the failure.
	s.e.SelfUpdateStartup()
	if s.state("u2") != agentv1.JobState_JOB_STATE_FAILED || !strings.Contains(s.lastMsg("u2"), "did not become healthy") {
		t.Fatalf("%v %q", s.state("u2"), s.lastMsg("u2"))
	}
	if _, err := selfupdate.Load(s.dir); !errors.Is(err, selfupdate.ErrNone) {
		t.Fatal("state not cleared after reporting the rollback")
	}
	// A healthy update is never rolled back.
	s2 := newSURig(t)
	se, env = s2.env("u3", s2.manifest("1.1.0", nil), s2.priv)
	s2.e.Accept(se, env)
	s2.tick()
	e2 := s2.restarted("1.1.0")
	e2.SelfUpdateHealthy()
	if msg, err := selfupdate.RollbackCheck(s2.dir, s2.p.su, s2.now.Add(time.Hour)); err != nil || s2.p.su.called("switch:a") {
		t.Fatalf("rolled back a healthy update: %q %v %v", msg, err, s2.p.su.calls)
	}
}

func TestAgentUpdateRefusals(t *testing.T) {
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name string
		do   func(s *suRig) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope)
		want string
		sec  agentv1.SecurityEventKind
	}{
		{"manifest signed by a key we do not trust", func(s *suRig) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
			return s.env("r1", s.manifest("1.1.0", nil), other)
		}, "not trusted", agentv1.SecurityEventKind_SECURITY_EVENT_KIND_BAD_SIGNATURE},
		{"same version", func(s *suRig) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
			return s.env("r2", s.manifest("1.0.0", nil), s.priv)
		}, "already running", 0},
		{"downgrade", func(s *suRig) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
			return s.env("r3", s.manifest("0.9.0", nil), s.priv)
		}, "downgrade", 0},
		{"wrong platform", func(s *suRig) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
			return s.env("r4", s.manifest("1.1.0", func(m *release.Manifest) {
				m.Arch = "arm64"
				if runtime.GOARCH == "arm64" {
					m.Arch = "amd64"
				}
			}), s.priv)
		}, "this machine is", 0},
		{"too old to jump", func(s *suRig) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
			return s.env("r5", s.manifest("1.1.0", func(m *release.Manifest) { m.MinVersion = "1.0.5" }), s.priv)
		}, "too old", 0},
		{"binary differs from the signed hash", func(s *suRig) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
			s.f.data[""] = []byte("MZ something else entirely!")
			return s.env("r6", s.manifest("1.1.0", func(m *release.Manifest) { m.Size = 27 }), s.priv)
		}, "download failed", agentv1.SecurityEventKind_SECURITY_EVENT_KIND_HASH_MISMATCH},
		{"binary reports another version", func(s *suRig) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
			return s.env("r7", s.manifest("1.2.0", nil), s.priv)
		}, "does not report version", 0},
		{"pinned signer does not match", func(s *suRig) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
			s.p.sig = Signature{Signed: true, Valid: true, Subject: "Somebody Else"}
			return s.env("r8", s.manifest("1.1.0", func(m *release.Manifest) { m.AuthenticodeSubject = "LibrePatch Software" }), s.priv)
		}, "pinned signer", agentv1.SecurityEventKind_SECURITY_EVENT_KIND_SIGNER_MISMATCH},
		{"rollback task cannot be armed", func(s *suRig) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
			s.p.su.failArm = true
			return s.env("r9", s.manifest("1.1.0", nil), s.priv)
		}, "safety net", 0},
		{"service switch fails", func(s *suRig) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
			s.p.su.failSwitc = true
			return s.env("r10", s.manifest("1.1.0", nil), s.priv)
		}, "cannot switch", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newSURig(t)
			se, env := c.do(s)
			s.e.Accept(se, env)
			s.tick()
			if s.state(env.JobId) != agentv1.JobState_JOB_STATE_FAILED || !strings.Contains(s.lastMsg(env.JobId), c.want) {
				t.Fatalf("%v %q (want %q)", s.state(env.JobId), s.lastMsg(env.JobId), c.want)
			}
			if c.sec != 0 {
				found := false
				for _, k := range s.rec.sec {
					found = found || k == c.sec
				}
				if !found {
					t.Fatalf("security event %v not raised: %v", c.sec, s.rec.sec)
				}
			}
			// Nothing may be left half-done: no armed task, no state file, no restart.
			if s.p.su.armed || s.p.su.called("restart") {
				t.Fatalf("left a half-done update: %v", s.p.su.calls)
			}
			if _, err := selfupdate.Load(s.dir); !errors.Is(err, selfupdate.ErrNone) {
				t.Fatalf("state file left behind: %v", err)
			}
			if c.name != "service switch fails" && c.name != "rollback task cannot be armed" && s.p.su.called("switch") {
				t.Fatalf("switched slots despite the refusal: %v", s.p.su.calls)
			}
		})
	}
}

func TestAgentUpdateNeedsAReleaseKeyAndPlatform(t *testing.T) {
	s := newSURig(t)
	s.e.ReleaseKeys = nil // falls back to the compiled-in keys: none in a test binary
	se, env := s.env("n1", s.manifest("1.1.0", nil), s.priv)
	s.e.Accept(se, env)
	s.tick()
	if s.state("n1") != agentv1.JobState_JOB_STATE_FAILED || !strings.Contains(s.lastMsg("n1"), "no vendor release key") {
		t.Fatalf("%v %q", s.state("n1"), s.lastMsg("n1"))
	}
	s2 := newSURig(t)
	s2.p.su = nil
	se, env = s2.env("n2", s2.manifest("1.1.0", nil), s2.priv)
	s2.e.Accept(se, env)
	s2.tick()
	if s2.state("n2") != agentv1.JobState_JOB_STATE_FAILED || !strings.Contains(s2.lastMsg("n2"), "not available") {
		t.Fatalf("%v %q", s2.state("n2"), s2.lastMsg("n2"))
	}
}

func TestAgentUpdateValidationAndCeiling(t *testing.T) {
	s := newSURig(t)
	s.e.Allowed = map[string]bool{"inventory": true}
	se, env := s.env("c1", s.manifest("1.1.0", nil), s.priv)
	s.e.Accept(se, env)
	if s.state("c1") != agentv1.JobState_JOB_STATE_REJECTED {
		t.Fatalf("the local ceiling must stop agent updates: %v", s.state("c1"))
	}
	s = newSURig(t)
	bad := func(id string, mut func(*agentv1.JobEnvelope)) {
		_, env := s.env(id, s.manifest("1.1.0", nil), s.priv)
		mut(env)
		s.e.Accept(s.sign(env), env)
		if s.state(id) != agentv1.JobState_JOB_STATE_REJECTED {
			t.Errorf("%s: %v", id, s.state(id))
		}
	}
	bad("v1", func(e *agentv1.JobEnvelope) { e.GetAgentUpdate().Signature = []byte("short") })
	bad("v2", func(e *agentv1.JobEnvelope) { e.GetAgentUpdate().Manifest = nil })
	bad("v3", func(e *agentv1.JobEnvelope) { e.TargetUserSid = "S-1-5-21-1-2-3-1001" })
	bad("v4", func(e *agentv1.JobEnvelope) { e.GetAgentUpdate().TimeoutS = 99999 })
}
