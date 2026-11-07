package loadsim

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/config"
	"github.com/auzring1/librepatch/internal/agent/core"
	"github.com/auzring1/librepatch/internal/agent/keystore"
	"github.com/auzring1/librepatch/internal/shared/pkix"
)

// Identity is a simulated device's enrolled identity. The key is a software key held in memory; the
// real agent keeps its key in CNG (TPM or non-exportable KSP).
type Identity struct {
	DeviceID string
	OrgID    string
	Key      *ecdsa.PrivateKey
	CertDER  []byte
	Cert     *x509.Certificate
}

// trustSet is what every agent learned from its enrollment and HelloAck: the pinned root, the issuing
// CA and the job-signing certificates. All agents of one run share one copy.
type trustSet struct {
	root       *x509.Certificate
	rootDER    []byte
	issuingDER []byte
}

// phase groups the statistics of one part of a run (ramp, hold, storm, ...).
type phase struct {
	name  string
	start time.Time
	h     *Hists
	c     *Counters
}

// fleet is the shared state of a run.
type fleet struct {
	cfg      *Config
	log      *slog.Logger
	quietLog *slog.Logger
	api      *API
	fx       *Fixture

	server  string // gateway host:port
	rootPin string
	token   string // enrollment token (from the enrollment string)
	runID   string

	trustV atomic.Pointer[trustSet]
	sigMu  sync.RWMutex
	sigDER [][]byte
	sigCrt []*x509.Certificate

	agents     []*simAgent
	connected  atomic.Int64
	stormEpoch atomic.Int64 // bumped when a storm begins
	inflight   atomic.Int64 // inventory reports sent and not yet acknowledged, fleet wide
	samples    atomic.Int64 // failures logged so far (only the first few are)
	cur        atomic.Pointer[phase]
	phases     []*phase
	phMu       sync.Mutex
	jobs       *JobTracker

	cacheMu   sync.Mutex
	cache     map[int]*Identity
	fromCache atomic.Int64
	enrolled  atomic.Int64
	enrollH   *Hist
}

func (f *fleet) trust() *trustSet { return f.trustV.Load() }

func (f *fleet) hostName(i int) string { return "LS-" + f.runID + "-" + strconv.Itoa(i) }
func (f *fleet) serialOf(i int) string { return "SN-" + f.runID + "-" + strconv.Itoa(i) }
func (f *fleet) uuidOf(i int) string   { return "UU-" + f.runID + "-" + strconv.Itoa(i) }

// startPhase begins collecting statistics under a new name.
func (f *fleet) startPhase(name string) *phase {
	p := &phase{name: name, start: time.Now(), h: NewHists(), c: NewCounters()}
	f.phMu.Lock()
	f.phases = append(f.phases, p)
	f.phMu.Unlock()
	f.cur.Store(p)
	return p
}

func (f *fleet) hist(name string) *Hist { return f.cur.Load().h.Get(name) }
func (f *fleet) count(name string)      { f.cur.Load().c.Inc(name) }

// acceptSigningCerts adds job-signing certificates the server sent, after the same chain check the
// real agent applies (issued directly by the pinned root, job-signing EKU, valid now).
func (f *fleet) acceptSigningCerts(ders [][]byte) {
	for _, d := range ders {
		f.sigMu.RLock()
		known := false
		for _, k := range f.sigDER {
			if bytes.Equal(k, d) {
				known = true
				break
			}
		}
		f.sigMu.RUnlock()
		if known {
			continue
		}
		c, err := x509.ParseCertificate(d)
		if err == nil {
			err = pkix.VerifyJobSigningCert(f.trust().root, c, time.Now())
		}
		if err != nil {
			f.count("fail.bad_signing_cert")
			continue
		}
		f.sigMu.Lock()
		f.sigDER = append(f.sigDER, d)
		f.sigCrt = append(f.sigCrt, c)
		f.sigMu.Unlock()
	}
}

func (f *fleet) signingCerts() []*x509.Certificate {
	f.sigMu.RLock()
	defer f.sigMu.RUnlock()
	return append([]*x509.Certificate(nil), f.sigCrt...)
}

// identity returns the agent's identity from the cache or by enrolling for real.
func (f *fleet) identity(ctx context.Context, a *simAgent) (*Identity, error) {
	f.cacheMu.Lock()
	id := f.cache[a.idx]
	f.cacheMu.Unlock()
	if id != nil {
		f.fromCache.Add(1)
		return id, nil
	}
	return f.enroll(ctx, a)
}

// enroll is the real first contact: key, CSR, pinned-root TLS, Enroll RPC, and the same checks the
// agent makes on the answer.
func (f *fleet) enroll(ctx context.Context, a *simAgent) (*Identity, error) {
	if f.token == "" {
		return nil, errors.New("no enrollment token")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := keystore.CSR(key)
	if err != nil {
		return nil, err
	}
	tc, err := core.PinnedTLS(f.server, f.rootPin)
	if err != nil {
		return nil, err
	}
	t0 := time.Now()
	conn, err := grpc.NewClient("passthrough:///"+f.server, core.DialOptions(tc)...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	resp, err := agentv1.NewEnrollmentServiceClient(conn).Enroll(cctx, &agentv1.EnrollRequest{
		Token: f.token, CsrDer: csr, Hostname: a.host, SmbiosUuid: f.uuidOf(a.idx), Serial: f.serialOf(a.idx),
		OsBuild: "26100", Arch: "amd64", AgentVersion: f.cfg.Version})
	if err != nil {
		f.count("enroll.fail." + classify(err))
		return nil, err
	}
	r := resp.GetResult()
	if r == nil {
		return nil, errors.New("empty enrollment result")
	}
	if r.Status != agentv1.EnrollStatus_ENROLL_STATUS_APPROVED {
		f.count("enroll.fail.not_approved")
		return nil, fmt.Errorf("enrollment status %s: use a token that does not require approval", r.Status)
	}
	root, err := x509.ParseCertificate(r.RootCaDer)
	if err != nil || pkix.SPKIPin(root) != f.rootPin {
		return nil, errors.New("server sent a root CA that does not match the pin")
	}
	cert, err := x509.ParseCertificate(r.ClientCertDer)
	if err != nil {
		return nil, fmt.Errorf("invalid client certificate: %w", err)
	}
	if f.trustV.Load() == nil {
		f.trustV.CompareAndSwap(nil, &trustSet{root: root, rootDER: r.RootCaDer, issuingDER: r.IssuingCaDer})
	}
	f.acceptSigningCerts(r.JobSigningCertsDer)
	f.enrollH.Record(time.Since(t0))
	f.hist("enroll").Record(time.Since(t0))
	f.enrolled.Add(1)
	id := &Identity{DeviceID: r.DeviceId, OrgID: r.OrgId, Key: key, CertDER: r.ClientCertDer, Cert: cert}
	f.cacheMu.Lock()
	f.cache[a.idx] = id
	f.cacheMu.Unlock()
	return id, nil
}

// ---- identity cache ----

type cacheFile struct {
	RootPin    string       `json:"root_pin"`
	RunID      string       `json:"run_id"`
	RootDER    string       `json:"root"`
	IssuingDER string       `json:"issuing"`
	SigningDER []string     `json:"signing"`
	Identities []cacheEntry `json:"identities"`
}

type cacheEntry struct {
	Index    int    `json:"i"`
	DeviceID string `json:"device_id"`
	OrgID    string `json:"org_id"`
	KeyDER   string `json:"key"`
	CertDER  string `json:"cert"`
}

// loadCache reads the identity cache if it belongs to this server's CA. It returns the run ID to use.
func loadCache(path, rootPin string) (runID string, ids map[int]*Identity, tr *trustSet, signing [][]byte) {
	ids = map[int]*Identity{}
	b, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path for the tool's own cache
	if err != nil {
		return "", ids, nil, nil
	}
	var cf cacheFile
	if json.Unmarshal(b, &cf) != nil || cf.RootPin != rootPin || cf.RunID == "" {
		return "", ids, nil, nil
	}
	rd, e1 := base64.StdEncoding.DecodeString(cf.RootDER)
	iss, e2 := base64.StdEncoding.DecodeString(cf.IssuingDER)
	root, e3 := x509.ParseCertificate(rd)
	if e1 != nil || e2 != nil || e3 != nil || pkix.SPKIPin(root) != rootPin {
		return "", ids, nil, nil
	}
	tr = &trustSet{root: root, rootDER: rd, issuingDER: iss}
	for _, s := range cf.SigningDER {
		if d, err := base64.StdEncoding.DecodeString(s); err == nil {
			signing = append(signing, d)
		}
	}
	for _, e := range cf.Identities {
		kd, err1 := base64.StdEncoding.DecodeString(e.KeyDER)
		cd, err2 := base64.StdEncoding.DecodeString(e.CertDER)
		if err1 != nil || err2 != nil {
			continue
		}
		k, err := x509.ParseECPrivateKey(kd)
		if err != nil {
			continue
		}
		c, err := x509.ParseCertificate(cd)
		if err != nil || time.Until(c.NotAfter) < time.Hour {
			continue // about to expire: enroll afresh
		}
		ids[e.Index] = &Identity{DeviceID: e.DeviceID, OrgID: e.OrgID, Key: k, CertDER: cd, Cert: c}
	}
	return cf.RunID, ids, tr, signing
}

func (f *fleet) saveCache(path string) error {
	f.cacheMu.Lock()
	cf := cacheFile{RootPin: f.rootPin, RunID: f.runID}
	if tr := f.trust(); tr != nil {
		cf.RootDER = base64.StdEncoding.EncodeToString(tr.rootDER)
		cf.IssuingDER = base64.StdEncoding.EncodeToString(tr.issuingDER)
	}
	f.sigMu.RLock()
	for _, d := range f.sigDER {
		cf.SigningDER = append(cf.SigningDER, base64.StdEncoding.EncodeToString(d))
	}
	f.sigMu.RUnlock()
	for i, id := range f.cache {
		kd, err := x509.MarshalECPrivateKey(id.Key)
		if err != nil {
			continue
		}
		cf.Identities = append(cf.Identities, cacheEntry{Index: i, DeviceID: id.DeviceID, OrgID: id.OrgID,
			KeyDER: base64.StdEncoding.EncodeToString(kd), CertDER: base64.StdEncoding.EncodeToString(id.CertDER)})
	}
	f.cacheMu.Unlock()
	b, err := json.Marshal(cf)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// resolveEnrollment fills server, root pin and token from the enrollment string (minting one first
// through the API when none was given).
func (f *fleet) resolveEnrollment(ctx context.Context) error {
	cfg := f.cfg
	enr := cfg.Enrollment
	if enr == "" {
		missing := cfg.Agents
		uses := min(100000, missing+missing/5+50)
		var err error
		enr, err = f.api.MintEnrollmentToken(ctx, "loadsim "+time.Now().UTC().Format("2006-01-02 15:04:05"), uses, 24*time.Hour)
		if err != nil {
			return err
		}
	}
	bc, err := config.FromBundle(enr, cfg.Server)
	if err != nil {
		return err
	}
	f.server, f.rootPin, f.token = bc.Server, bc.RootPin, bc.EnrollmentToken
	return nil
}

// ---- job tracking ----

// JobTracker joins what the REST caller and the simulated agents each know about a job.
type JobTracker struct {
	mu sync.Mutex
	m  map[string]*jobRec
}

type jobRec struct {
	created, offered, resultSent, acked time.Time
}

// NewJobTracker returns an empty tracker.
func NewJobTracker() *JobTracker { return &JobTracker{m: map[string]*jobRec{}} }

func (t *JobTracker) rec(id string) *jobRec {
	r := t.m[id]
	if r == nil {
		r = &jobRec{}
		t.m[id] = r
	}
	return r
}

// Created notes when the REST request that made the job was started.
func (t *JobTracker) Created(id string, at time.Time) {
	t.mu.Lock()
	t.rec(id).created = at
	t.mu.Unlock()
}

// Offered notes the first time an agent verified the job.
func (t *JobTracker) Offered(id string, at time.Time) {
	t.mu.Lock()
	if r := t.rec(id); r.offered.IsZero() {
		r.offered = at
	}
	t.mu.Unlock()
}

// ResultSent notes when the agent sent the final update.
func (t *JobTracker) ResultSent(id string, at time.Time) {
	t.mu.Lock()
	if r := t.rec(id); r.resultSent.IsZero() {
		r.resultSent = at
	}
	t.mu.Unlock()
}

// Acked notes when the server acknowledged the final update (it has then recorded it).
func (t *JobTracker) Acked(id string, at time.Time) {
	t.mu.Lock()
	if r := t.rec(id); r.acked.IsZero() {
		r.acked = at
	}
	t.mu.Unlock()
}

// JobStats is the joined result.
type JobStats struct {
	Created   int     `json:"created"`
	Offered   int     `json:"offered"`
	Completed int     `json:"completed"`
	Lost      int     `json:"lost"`
	Dispatch  Summary `json:"dispatch_ms"`   // REST request start -> agent verified the offer
	ResultRTT Summary `json:"result_rtt_ms"` // agent sent the result -> server acknowledged it
	EndToEnd  Summary `json:"end_to_end_ms"` // REST request start -> result acknowledged
}

// Stats joins the records of the jobs this tool created (others, such as jobs created by the
// server's own scheduler, are ignored).
func (t *JobTracker) Stats() JobStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	d, rr, e := NewHist(), NewHist(), NewHist()
	var s JobStats
	for _, r := range t.m {
		if r.created.IsZero() {
			continue
		}
		s.Created++
		if !r.offered.IsZero() {
			s.Offered++
			d.Record(r.offered.Sub(r.created))
		}
		if !r.acked.IsZero() {
			s.Completed++
			e.Record(r.acked.Sub(r.created))
			if !r.resultSent.IsZero() {
				rr.Record(r.acked.Sub(r.resultSent))
			}
		}
	}
	s.Lost = s.Created - s.Completed
	s.Dispatch, s.ResultRTT, s.EndToEnd = d.Summary(), rr.Summary(), e.Summary()
	return s
}

// Outstanding is the number of created jobs without an acknowledged result.
func (t *JobTracker) Outstanding() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, r := range t.m {
		if !r.created.IsZero() && r.acked.IsZero() {
			n++
		}
	}
	return n
}
