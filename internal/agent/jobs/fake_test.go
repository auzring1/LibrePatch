package jobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/inventory"
	"github.com/auzring1/librepatch/internal/agent/selfupdate"
	"github.com/auzring1/librepatch/internal/agent/wu"
	"github.com/auzring1/librepatch/internal/shared/installer"
)

// ---- in-memory registry ----

type node struct {
	subs map[string]*node
	vals map[string]string
	dw   map[string]uint32
}

func newNode() *node {
	return &node{subs: map[string]*node{}, vals: map[string]string{}, dw: map[string]uint32{}}
}

func (n *node) add(path string) *node {
	cur := n
	for _, p := range strings.Split(path, `\`) {
		nx, ok := cur.subs[p]
		if !ok {
			nx = newNode()
			cur.subs[p] = nx
		}
		cur = nx
	}
	return cur
}

func (n *node) remove(name string) { delete(n.subs, name) }

func (n *node) SubKeyNames() ([]string, error) {
	var out []string
	for k := range n.subs {
		out = append(out, k)
	}
	return out, nil
}

func (n *node) Open(path string) (inventory.RegNode, error) {
	cur := n
	for _, p := range strings.Split(path, `\`) {
		nx, ok := cur.subs[p]
		if !ok {
			return nil, inventory.ErrRegNotExist
		}
		cur = nx
	}
	return cur, nil
}
func (n *node) String(name string) (string, bool) { v, ok := n.vals[name]; return v, ok }
func (n *node) DWord(name string) (uint32, bool)  { v, ok := n.dw[name]; return v, ok }
func (n *node) Close()                            {}

// ---- fake platform ----

type fakePlatform struct {
	mu       sync.Mutex
	root     string
	machine  *node
	users    map[string]*node
	sessions map[string]bool
	sig      Signature
	build    uint32
	files    map[string]string
	trusted  func(string) error
	freeMB   uint64

	runs   []RunSpec
	runFn  func(spec RunSpec, asUser string) (RunResult, error)
	events chan struct{}

	wuc       *fakeWU
	su        *fakeUpdater
	rebootReq bool
	rebootErr error // returned by Reboot after the call is recorded
	reboots   []rebootCall
	aborts    int

	// user prompts (D124)
	procs     []Proc    // programs "running" now
	answers   []Answer  // what the user answers, in order (empty = Yes)
	asks      []askCall // every question shown
	closed    [][]Proc  // every CloseProcesses call
	noClose   bool      // programs ignore the request to close
	noSession bool      // nobody is signed in
	procsErr  error     // RunningProcesses fails
	onAsk     func()    // runs when a question is shown (a program may close meanwhile)
	psList    []ProcessInfo
	viewErr   error
	services  []ServiceInfo
	eventList []EventInfo
	eventQ    []EventQuery
}

type askCall struct {
	session uint32
	title   string
	message string
	yesNo   bool
	timeout time.Duration
}

type rebootCall struct {
	delay   time.Duration
	message string
}

// fakeWU is a scripted Windows Update Agent.
type fakeWU struct {
	mu       sync.Mutex
	updates  []*agentv1.WuUpdate
	installs [][]*agentv1.WuUpdateRef
	results  map[string]agentv1.WuResult // by update id; default INSTALLED
	reboot   bool                        // the next install asks for a restart
	err      error                       // returned by every call
	hidden   map[string]bool
	policy   *agentv1.WuPolicyInfo
	opts     []wu.Options
	// scanGate, when set, holds every Scan until it is closed (a slow Windows Update search); scanning is signalled
	// when a Scan has started.
	scanGate chan struct{}
	scanning chan struct{}
}

func (f *fakeWU) Scan(ctx context.Context, o wu.Options) ([]*agentv1.WuUpdate, error) {
	if f.scanGate != nil {
		select {
		case f.scanning <- struct{}{}:
		default:
		}
		select {
		case <-f.scanGate:
		case <-ctx.Done():
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opts = append(f.opts, o)
	if f.err != nil {
		return nil, f.err
	}
	return append([]*agentv1.WuUpdate(nil), f.updates...), nil
}

func (f *fakeWU) Install(_ context.Context, o wu.Options, refs []*agentv1.WuUpdateRef) (*wu.InstallResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opts = append(f.opts, o)
	if f.err != nil {
		return nil, f.err
	}
	f.installs = append(f.installs, refs)
	res := &wu.InstallResult{}
	for _, r := range refs {
		st, ok := f.results[r.UpdateId]
		if !ok {
			st = agentv1.WuResult_WU_RESULT_INSTALLED
			if f.reboot {
				st = agentv1.WuResult_WU_RESULT_INSTALLED_REBOOT
			}
		}
		if st == agentv1.WuResult_WU_RESULT_INSTALLED || st == agentv1.WuResult_WU_RESULT_INSTALLED_REBOOT {
			for i, u := range f.updates {
				if u.UpdateId == r.UpdateId {
					f.updates = append(f.updates[:i], f.updates[i+1:]...)
					break
				}
			}
		}
		if st == agentv1.WuResult_WU_RESULT_INSTALLED_REBOOT {
			res.RebootRequired = true
		}
		res.Results = append(res.Results, &agentv1.WuUpdateResult{UpdateId: r.UpdateId, Revision: r.Revision, Result: st})
	}
	return res, nil
}

func (f *fakeWU) Hide(_ context.Context, _ wu.Options, refs []*agentv1.WuUpdateRef, hide bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if f.hidden == nil {
		f.hidden = map[string]bool{}
	}
	for _, r := range refs {
		f.hidden[r.UpdateId] = hide
		for _, u := range f.updates {
			if u.UpdateId == r.UpdateId {
				u.State = agentv1.WuUpdateState_WU_UPDATE_STATE_MISSING
				if hide {
					u.State = agentv1.WuUpdateState_WU_UPDATE_STATE_HIDDEN
				}
			}
		}
	}
	return nil
}

func (f *fakeWU) Policy() *agentv1.WuPolicyInfo {
	if f.policy != nil {
		return f.policy
	}
	return &agentv1.WuPolicyInfo{EffectiveSource: "windows_update"}
}

func (f *fakePlatform) WindowsUpdate() wu.Client { return f.wuc }
func (f *fakePlatform) Reboot(d time.Duration, m string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reboots = append(f.reboots, rebootCall{d, m})
	return f.rebootErr
}
func (f *fakePlatform) AbortReboot() error { f.mu.Lock(); f.aborts++; f.mu.Unlock(); return nil }
func (f *fakePlatform) RebootRequired() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rebootReq
}

func newFake(t *testing.T) *fakePlatform {
	return &fakePlatform{root: t.TempDir(), machine: newNode(), users: map[string]*node{}, sessions: map[string]bool{},
		build: 26100, files: map[string]string{}, events: make(chan struct{}, 4), freeMB: 1 << 20,
		runFn: func(RunSpec, string) (RunResult, error) { return RunResult{}, nil }, trusted: func(string) error { return nil },
		wuc: &fakeWU{results: map[string]agentv1.WuResult{}}}
}

func (f *fakePlatform) userRoot(sid string) *node {
	n, ok := f.users[sid]
	if !ok {
		n = newNode()
		f.users[sid] = n
	}
	return n
}

func (f *fakePlatform) StagingDir(_ installer.Scope, sid, id string) (string, error) {
	d := filepath.Join(f.root, "stage", id)
	return d, os.MkdirAll(d, 0o700)
}
func (f *fakePlatform) RemoveAll(p string) error           { return os.RemoveAll(p) }
func (f *fakePlatform) FreeSpaceMB(string) (uint64, error) { return f.freeMB, nil }
func (f *fakePlatform) OSBuild() uint32                    { return f.build }
func (f *fakePlatform) Env(_ installer.Scope, _ string, n string) string {
	if n == "PROGRAMFILES" {
		return filepath.Join(f.root, "pf")
	}
	return filepath.Join(f.root, strings.ToLower(n))
}
func (f *fakePlatform) FileVersion(p string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.files[p]; ok {
		return v, true, nil
	}
	if _, err := os.Stat(p); err == nil {
		return "", true, nil
	}
	return "", false, nil
}
func (f *fakePlatform) UninstallRoots(scope installer.Scope, sid string) ([]inventory.RegNode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if scope == installer.User {
		n, _ := f.userRoot(sid).add(`Software\Microsoft\Windows\CurrentVersion\Uninstall`), 0
		return []inventory.RegNode{n}, nil
	}
	return []inventory.RegNode{f.machine.add(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`)}, nil
}
func (f *fakePlatform) AppxPackages(string) ([]string, error) { return nil, nil }
func (f *fakePlatform) OpenLocked(p string) (LockedFile, error) {
	return os.Open(p) // #nosec G304 -- test
}
func (f *fakePlatform) VerifySignature(string) (Signature, error) { return f.sig, nil }
func (f *fakePlatform) Run(ctx context.Context, s RunSpec) (RunResult, error) {
	f.mu.Lock()
	f.runs = append(f.runs, s)
	fn := f.runFn
	f.mu.Unlock()
	return fn(s, "")
}
func (f *fakePlatform) RunAsUser(ctx context.Context, sid string, s RunSpec) (RunResult, error) {
	f.mu.Lock()
	if !f.sessions[sid] {
		f.mu.Unlock()
		return RunResult{}, ErrNoSession
	}
	f.runs = append(f.runs, s)
	fn := f.runFn
	f.mu.Unlock()
	return fn(s, sid)
}
func (f *fakePlatform) HasSession(sid string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sessions[sid]
}
func (f *fakePlatform) SessionEvents() <-chan struct{}   { return f.events }
func (f *fakePlatform) TrustedExecutable(p string) error { return f.trusted(p) }
func (f *fakePlatform) MsiExec() string                  { return `C:\Windows\System32\msiexec.exe` }

// ---- fake content ----

type fakeFetcher struct {
	mu   sync.Mutex
	data map[string][]byte // by kind+url
	err  error
	n    int
	// onOpen runs when a download starts (a program may be opened meanwhile).
	onOpen func()
}

func (f *fakeFetcher) Open(_ context.Context, src *agentv1.ContentSource, _ string, _ []byte) (io.ReadCloser, error) {
	if f.onOpen != nil {
		f.onOpen()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.data[src.Url]
	if !ok {
		return nil, errors.New("404")
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// ---- recording reporter ----

type recorder struct {
	mu      sync.Mutex
	updates []*agentv1.JobUpdate
	sec     []agentv1.SecurityEventKind
}

func (r *recorder) Report(u *agentv1.JobUpdate) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updates = append(r.updates, proto.Clone(u).(*agentv1.JobUpdate))
}

func (r *recorder) states(id string) []agentv1.JobState {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []agentv1.JobState
	for _, u := range r.updates {
		if u.JobId == id {
			out = append(out, u.State)
		}
	}
	return out
}

func (r *recorder) last(id string) *agentv1.JobUpdate {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out *agentv1.JobUpdate
	for _, u := range r.updates {
		if u.JobId == id {
			out = u
		}
	}
	return out
}

// ---- in-memory job store ----

type memStore struct {
	mu   sync.Mutex
	m    map[string][]byte
	meta map[string][]byte
}

func (s *memStore) GetMeta(k string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.meta[k]
}
func (s *memStore) SetMeta(k string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.meta == nil {
		s.meta = map[string][]byte{}
	}
	s.meta[k] = append([]byte(nil), v...)
	return nil
}

func (s *memStore) JobPut(id string, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string][]byte{}
	}
	s.m[id] = append([]byte(nil), b...)
	return nil
}
func (s *memStore) JobGet(id string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[id]
}
func (s *memStore) JobAll() (map[string][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string][]byte{}
	for k, v := range s.m {
		out[k] = v
	}
	return out, nil
}
func (s *memStore) JobDelete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
	return nil
}

// ---- harness ----

type rig struct {
	t   *testing.T
	e   *Engine
	p   *fakePlatform
	f   *fakeFetcher
	rec *recorder
	now time.Time
	ctx context.Context
}

func newRig(t *testing.T) *rig {
	p := newFake(t)
	f := &fakeFetcher{data: map[string][]byte{}}
	rec := &recorder{}
	r := &rig{t: t, p: p, f: f, rec: rec, now: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC), ctx: context.Background()}
	r.e = &Engine{P: p, Store: &memStore{}, Report: rec, Fetch: f, Now: func() time.Time { return r.now }, Local: time.UTC,
		Security: func(k agentv1.SecurityEventKind, _ string) { rec.sec = append(rec.sec, k) }}
	return r
}

func sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// installJob builds an accepted-ready EXE install envelope. The package "installs" by
// adding an Uninstall key when the (fake) installer runs.
func (r *rig) installEnv(id string, mut func(*agentv1.JobEnvelope, *agentv1.InstallBody)) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
	payload := []byte("MZ installer bytes " + id)
	r.f.data["https://v.example/"+id+".exe"] = payload
	body := &agentv1.InstallBody{PackageId: "Acme.Tool", Name: "Acme Tool", Version: "2.0", Scope: agentv1.InstallScope_INSTALL_SCOPE_MACHINE,
		Installer: &agentv1.Installer{Type: agentv1.InstallerType_INSTALLER_TYPE_EXE, Sha256: sum(payload), Size: uint64(len(payload)),
			FileName: id + ".exe", Args: []string{"/silent"},
			Sources: []*agentv1.ContentSource{{Kind: agentv1.ContentSourceKind_CONTENT_SOURCE_KIND_VENDOR, Url: "https://v.example/" + id + ".exe"}}},
		Detection: []*agentv1.Detection{{Kind: agentv1.DetectionKind_DETECTION_KIND_REGISTRY, Key: "AcmeTool", Version: "2.0", Cmp: agentv1.VersionCmp_VERSION_CMP_GE}},
	}
	env := &agentv1.JobEnvelope{Version: 1, JobId: id, OrgId: "o", DeviceId: "d", Type: agentv1.JobType_JOB_TYPE_SOFTWARE_INSTALL,
		IssuedAt: r.now.Unix(), NotBefore: r.now.Unix(), ExpiresAt: r.now.Add(24 * time.Hour).Unix(), Nonce: make([]byte, 16),
		Body: &agentv1.JobEnvelope_Install{Install: body}}
	if mut != nil {
		mut(env, body)
	}
	return r.sign(env), env
}

func (r *rig) sign(env *agentv1.JobEnvelope) *agentv1.SignedEnvelope {
	b, err := proto.Marshal(env)
	if err != nil {
		r.t.Fatal(err)
	}
	return &agentv1.SignedEnvelope{Payload: b}
}

// installerRuns makes the fake process register the product like a real installer would.
func (r *rig) installerRegisters(version string, exit int) {
	r.p.runFn = func(s RunSpec, user string) (RunResult, error) {
		if exit == 0 {
			k := r.p.machine.add(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AcmeTool`)
			k.vals["DisplayVersion"] = version
		}
		return RunResult{ExitCode: exit, LogTail: "installed"}, nil
	}
}

func (r *rig) tick() { r.e.init(); r.e.tick(r.ctx) }

func (r *rig) state(id string) agentv1.JobState {
	rec := load(r.e.Store, id)
	if rec == nil {
		r.t.Fatalf("no record for %s", id)
	}
	return rec.state()
}

func osReadDir(p string) ([]os.DirEntry, error) { return os.ReadDir(p) }

func (f *fakePlatform) SelfUpdater() selfupdate.Platform {
	if f.su == nil {
		return nil
	}
	return f.su
}

func (f *fakePlatform) RunningProcesses(names []string, _ string) ([]Proc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.procsErr != nil {
		return nil, f.procsErr
	}
	var out []Proc
	for _, p := range f.procs {
		for _, n := range names {
			if strings.EqualFold(p.Name, n) {
				out = append(out, p)
			}
		}
	}
	return out, nil
}
func (f *fakePlatform) UserSession(string) (uint32, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return 1, !f.noSession
}
func (f *fakePlatform) Ask(_ context.Context, session uint32, title, msg string, timeout time.Duration, yesNo bool) (Answer, error) {
	f.mu.Lock()
	f.asks = append(f.asks, askCall{session, title, msg, yesNo, timeout})
	ans := AnswerYes
	if len(f.answers) > 0 {
		ans, f.answers = f.answers[0], f.answers[1:]
	}
	hook := f.onAsk
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	return ans, nil
}
func (f *fakePlatform) CloseProcesses(_ context.Context, procs []Proc, _ time.Duration) ([]Proc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = append(f.closed, procs)
	if f.noClose {
		return procs, nil
	}
	var keep []Proc
	for _, p := range f.procs {
		gone := false
		for _, c := range procs {
			if c.PID == p.PID {
				gone = true
			}
		}
		if !gone {
			keep = append(keep, p)
		}
	}
	f.procs = keep
	return nil, nil
}

// scripted read-only views
func (f *fakePlatform) Processes() ([]ProcessInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.psList, f.viewErr
}
func (f *fakePlatform) Services() ([]ServiceInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.services, f.viewErr
}
func (f *fakePlatform) Events(_ context.Context, q EventQuery) ([]EventInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.eventQ = append(f.eventQ, q)
	return f.eventList, f.viewErr
}
