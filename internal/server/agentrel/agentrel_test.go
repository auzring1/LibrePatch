package agentrel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/catalog"
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/pki"
	"github.com/auzring1/librepatch/internal/shared/ptr"
	"github.com/auzring1/librepatch/internal/shared/release"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

type nullDispatcher struct{}

func (nullDispatcher) Offer(uuid.UUID, *agentv1.SignedEnvelope) bool { return false }

type fx struct {
	t      *testing.T
	pool   *pgxpool.Pool
	svc    *Service
	org    uuid.UUID
	user   uuid.UUID
	site   uuid.UUID
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	mu     sync.Mutex
	offset time.Duration
}

func (f *fx) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return time.Now().Add(f.offset)
}
func (f *fx) advance(d time.Duration) { f.mu.Lock(); f.offset += d; f.mu.Unlock() }

func newFx(t *testing.T) *fx {
	db := pgtest.New(t)
	h, err := pki.NewHierarchy("Test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	auth := pki.NewAuthority(h.Root.Cert, h.Issuing, h.JobSigning)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fx{t: t, pool: db.Pool, org: uuid.New(), user: uuid.New(), site: uuid.New(), pub: pub, priv: priv}
	dep := &deploy.Service{Pool: db.Pool, Authority: func() *pki.Authority { return auth }, Dispatcher: nullDispatcher{}, Now: f.now}
	f.svc = &Service{Pool: db.Pool, Deploy: dep, Content: &catalog.Store{Dir: t.TempDir()}, Now: f.now, Keys: []ed25519.PublicKey{pub}}
	dep.AfterTerminal = func(ctx context.Context, j dbq.Job, status string, u *agentv1.JobUpdate) {
		f.svc.AfterJob(ctx, j, status, u)
	}
	f.exec("INSERT INTO organizations (id, name) VALUES ($1, 'o')", f.org)
	f.exec("INSERT INTO users (id, org_id, email, display_name, password_hash) VALUES ($1, $2, $3, 'A', 'x')", f.user, f.org, f.user.String()+"@example.com")
	f.exec("INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 's')", f.site, f.org)
	return f
}

func (f *fx) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fx) actor() Actor { return Actor{Org: f.org, User: f.user, IP: "127.0.0.1"} }

func (f *fx) device(version string) uuid.UUID {
	id := uuid.New()
	f.exec("INSERT INTO devices (id, org_id, site_id, status, hostname, arch, online, agent_version) VALUES ($1,$2,$3,'active',$4,'amd64',true,$5)",
		id, f.org, f.site, "h-"+id.String()[:8], version)
	return id
}

func (f *fx) group(devs ...uuid.UUID) uuid.UUID {
	id := uuid.New()
	f.exec("INSERT INTO groups (id, org_id, name, kind, created_by) VALUES ($1,$2,$3,'static',$4)", id, f.org, "g"+id.String()[:6], f.user)
	for _, d := range devs {
		f.exec("INSERT INTO group_members (group_id, device_id) VALUES ($1,$2)", id, d)
	}
	return id
}

// bundle signs a release of binary at version with the fixture's key (or another).
func (f *fx) bundle(version string, binary []byte, key ed25519.PrivateKey) []byte {
	h := sha256.Sum256(binary)
	m := &release.Manifest{Format: 1, Product: release.Product, Version: version, OS: "windows", Arch: "amd64", SHA256: hex.EncodeToString(h[:]), Size: uint64(len(binary))}
	mb, err := release.Marshal(m)
	if err != nil {
		f.t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	b, _ := release.EncodeBundle(&release.Bundle{Manifest: mb, Signature: release.Sign(key, mb), KeyID: release.KeyID(pub)})
	return b
}

func (f *fx) addRelease(version string) Release {
	f.t.Helper()
	bin := []byte("MZ agent " + version)
	r, err := f.svc.AddRelease(context.Background(), f.actor(), f.bundle(version, bin, f.priv), bytes.NewReader(bin))
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func (f *fx) rollout(rel Release, mut func(*Rollout)) {
	f.t.Helper()
	ro := Rollout{ReleaseID: &rel.ID, SoakHours: 1, SuccessThreshold: 100, BatchPerTick: 100}
	if mut != nil {
		mut(&ro)
	}
	if err := f.svc.SetRollout(context.Background(), f.actor(), ro); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) openJobs(dev uuid.UUID) int {
	return f.count("SELECT count(*) FROM jobs WHERE device_id=$1 AND type='agent_update' AND status IN ('queued','sent','accepted','waiting','running')", dev)
}

// finish ends the device's agent_update job as the engine would report it.
func (f *fx) finish(dev uuid.UUID, status, msg string) {
	f.t.Helper()
	ctx := context.Background()
	var id uuid.UUID
	if err := f.pool.QueryRow(ctx, "SELECT id FROM jobs WHERE device_id=$1 AND type='agent_update' ORDER BY created_at DESC LIMIT 1", dev).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	f.exec("UPDATE jobs SET status=$2 WHERE id=$1", id, status)
	j, err := dbq.New(f.pool).GetJob(ctx, dbq.GetJobParams{ID: id, OrgID: f.org})
	if err != nil {
		f.t.Fatal(err)
	}
	f.svc.AfterJob(ctx, j, status, &agentv1.JobUpdate{JobId: id.String(), Result: &agentv1.JobResult{Message: msg}})
}

func TestAddReleaseVerifiesTheBundleAndTheBinary(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	bin := []byte("MZ the real agent")
	r, err := f.svc.AddRelease(ctx, f.actor(), f.bundle("1.2.0", bin, f.priv), bytes.NewReader(bin))
	if err != nil || r.Version != "1.2.0" || r.Status != "available" || r.Size != int64(len(bin)) {
		t.Fatalf("%v %+v", err, r)
	}
	if f.count("SELECT count(*) FROM audit_log WHERE action='agent.release_add'") != 1 {
		t.Fatal("upload not audited")
	}
	if _, err := f.svc.AddRelease(ctx, f.actor(), f.bundle("1.2.0", bin, f.priv), bytes.NewReader(bin)); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate version: %v", err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := f.svc.AddRelease(ctx, f.actor(), f.bundle("1.3.0", bin, other), bytes.NewReader(bin)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a bundle signed by an unknown key must be refused: %v", err)
	}
	if _, err := f.svc.AddRelease(ctx, f.actor(), f.bundle("1.3.0", bin, f.priv), strings.NewReader("MZ a different file!!")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a binary that does not match the manifest must be refused: %v", err)
	}
	if f.count("SELECT count(*) FROM agent_releases") != 1 {
		t.Fatal("a refused upload left a release behind")
	}
	if _, err := f.svc.AddRelease(ctx, f.actor(), []byte("{}"), bytes.NewReader(bin)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("garbage bundle: %v", err)
	}
	// A server build without a release key accepts nothing.
	f.svc.Keys = []ed25519.PublicKey{}
	if _, err := f.svc.AddRelease(ctx, f.actor(), f.bundle("1.4.0", bin, f.priv), bytes.NewReader(bin)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no release key: %v", err)
	}
}

func TestRolloutUpdatesOnlyOlderDevicesOnceAndInBatches(t *testing.T) {
	f := newFx(t)
	rel := f.addRelease("1.2.0")
	old1, old2, old3 := f.device("1.0.0"), f.device("1.1.0"), f.device("1.0.5")
	cur, newer, unknown := f.device("1.2.0"), f.device("1.3.0"), f.device("")
	f.rollout(rel, func(r *Rollout) { r.BatchPerTick = 2 })
	ctx := context.Background()

	f.svc.Tick(ctx)
	got := 0
	for _, d := range []uuid.UUID{old1, old2, old3} {
		got += f.openJobs(d)
	}
	if got != 2 {
		t.Fatalf("the batch limit is 2 jobs per tick, got %d", got)
	}
	for _, d := range []uuid.UUID{cur, newer, unknown} {
		if f.openJobs(d) != 0 {
			t.Fatal("a device that is current, newer or of unknown version must not get an update job")
		}
	}
	f.svc.Tick(ctx) // the third device now; nobody gets a second job
	for _, d := range []uuid.UUID{old1, old2, old3} {
		if f.openJobs(d) != 1 {
			t.Fatalf("device %s has %d open jobs", d, f.openJobs(d))
		}
	}
	// The job carries the vendor-signed manifest and the target release.
	var body []byte
	if err := f.pool.QueryRow(ctx, "SELECT body FROM jobs WHERE device_id=$1 AND type='agent_update'", old1).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var env agentv1.JobEnvelope
	if err := protoUnmarshal(body, &env); err != nil || env.GetAgentUpdate() == nil || env.Type != agentv1.JobType_JOB_TYPE_AGENT_UPDATE {
		t.Fatalf("job body: %v %+v", err, &env)
	}
	if _, err := release.Verify([]ed25519.PublicKey{f.pub}, env.GetAgentUpdate().Manifest, env.GetAgentUpdate().Signature, hex.EncodeToString(env.GetAgentUpdate().KeyId)); err != nil {
		t.Fatalf("the manifest in the job must verify under the vendor key: %v", err)
	}
}

func TestPilotGoesFirstThenTheRestAfterSoakAndSuccess(t *testing.T) {
	f := newFx(t)
	rel := f.addRelease("1.2.0")
	p1, p2 := f.device("1.0.0"), f.device("1.0.0")
	o1, o2 := f.device("1.0.0"), f.device("1.0.0")
	g := f.group(p1, p2)
	f.rollout(rel, func(r *Rollout) { r.PilotGroupIDs = []uuid.UUID{g}; r.SoakHours = 6; r.SuccessThreshold = 100 })
	ctx := context.Background()

	f.svc.Tick(ctx)
	if f.openJobs(p1) != 1 || f.openJobs(p2) != 1 || f.openJobs(o1) != 0 || f.openJobs(o2) != 0 {
		t.Fatal("only the pilot may be updated first")
	}
	f.finish(p1, "succeeded", "")
	f.svc.Tick(ctx)
	if f.openJobs(o1) != 0 {
		t.Fatal("others must wait while a pilot device is still updating")
	}
	f.finish(p2, "succeeded", "")
	f.exec("UPDATE devices SET agent_version='1.2.0' WHERE id = ANY($1)", []uuid.UUID{p1, p2})
	f.advance(15 * time.Minute) // past "recently updated" but inside the soak
	f.svc.Tick(ctx)
	if f.openJobs(o1) != 0 {
		t.Fatal("others must wait for the soak time")
	}
	st, _ := f.svc.Status(ctx, f.org)
	if !strings.Contains(st.Waiting, "soaking") || st.PilotUpdated != 2 {
		t.Fatalf("status should explain the wait: %+v", st)
	}
	f.advance(6 * time.Hour)
	f.svc.Tick(ctx)
	if f.openJobs(o1) != 1 || f.openJobs(o2) != 1 {
		t.Fatal("the rest must be updated once the pilot proved itself")
	}
}

func TestPilotFailurePausesTheRolloutAndAuditsIt(t *testing.T) {
	f := newFx(t)
	rel := f.addRelease("1.2.0")
	p1, p2 := f.device("1.0.0"), f.device("1.0.0")
	o1 := f.device("1.0.0")
	g := f.group(p1, p2)
	f.rollout(rel, func(r *Rollout) { r.PilotGroupIDs = []uuid.UUID{g}; r.SuccessThreshold = 90 })
	ctx := context.Background()
	f.svc.Tick(ctx)
	f.finish(p1, "failed", "rolled back: did not become healthy")
	f.svc.Tick(ctx)
	var paused bool
	var reason string
	if err := f.pool.QueryRow(ctx, "SELECT paused, paused_reason FROM agent_rollout WHERE org_id=$1", f.org).Scan(&paused, &reason); err != nil {
		t.Fatal(err)
	}
	if !paused || !strings.Contains(reason, "pilot failed") {
		t.Fatalf("paused=%v reason=%q", paused, reason)
	}
	if f.count("SELECT count(*) FROM audit_log WHERE action='agent.rollout_hold'") != 1 {
		t.Fatal("the automatic hold must be audited")
	}
	f.svc.Tick(ctx)
	if f.openJobs(o1) != 0 {
		t.Fatal("nothing may be updated while the rollout is on hold")
	}
}

func TestFailedUpdatesAreRetriedLaterAndNotForever(t *testing.T) {
	f := newFx(t)
	rel := f.addRelease("1.2.0")
	d := f.device("1.0.0")
	f.rollout(rel, nil)
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		f.svc.Tick(ctx)
		if f.openJobs(d) != 1 {
			t.Fatalf("attempt %d: no job", i)
		}
		f.finish(d, "failed", "boom")
		f.svc.Tick(ctx)
		if f.openJobs(d) != 0 {
			t.Fatalf("attempt %d: retried at once", i)
		}
		f.advance(25 * time.Hour)
	}
	f.svc.Tick(ctx)
	if f.openJobs(d) != 0 {
		t.Fatal("three failures are the limit")
	}
	var msg string
	f.pool.QueryRow(ctx, "SELECT last_error FROM agent_attempts WHERE device_id=$1", d).Scan(&msg)
	if msg != "boom" {
		t.Fatalf("the reason must be kept for the console: %q", msg)
	}
}

func TestExpiredJobsAreReplannedAndWithdrawnTargetsStopTheRollout(t *testing.T) {
	f := newFx(t)
	rel := f.addRelease("1.2.0")
	d := f.device("1.0.0")
	f.rollout(rel, nil)
	ctx := context.Background()
	f.svc.Tick(ctx)
	f.finish(d, "expired", "")
	if f.count("SELECT count(*) FROM agent_attempts WHERE device_id=$1", d) != 0 {
		t.Fatal("an expired job must release its attempt")
	}
	f.svc.Tick(ctx)
	if f.openJobs(d) != 1 {
		t.Fatal("an expired job is planned again")
	}
	if err := f.svc.SetStatus(ctx, f.actor(), rel.ID, "withdrawn"); err != nil {
		t.Fatal(err)
	}
	var paused bool
	f.pool.QueryRow(ctx, "SELECT paused FROM agent_rollout WHERE org_id=$1", f.org).Scan(&paused)
	if !paused {
		t.Fatal("withdrawing the target must pause the rollout")
	}
	if err := f.svc.Delete(ctx, f.actor(), rel.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("the target cannot be deleted: %v", err)
	}
	if err := f.svc.SetRollout(ctx, f.actor(), Rollout{ReleaseID: &rel.ID, SoakHours: 1, SuccessThreshold: 90, BatchPerTick: 10}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a withdrawn release cannot be the target: %v", err)
	}
	if err := f.svc.SetRollout(ctx, f.actor(), Rollout{SoakHours: 1, SuccessThreshold: 90, BatchPerTick: 10}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Delete(ctx, f.actor(), rel.ID); err != nil {
		t.Fatalf("delete after clearing the target: %v", err)
	}
}

func TestRolloutValidation(t *testing.T) {
	f := newFx(t)
	rel := f.addRelease("1.2.0")
	for name, ro := range map[string]Rollout{
		"threshold": {ReleaseID: &rel.ID, SoakHours: 1, SuccessThreshold: 0, BatchPerTick: 10},
		"soak":      {ReleaseID: &rel.ID, SoakHours: 9999, SuccessThreshold: 90, BatchPerTick: 10},
		"batch":     {ReleaseID: &rel.ID, SoakHours: 1, SuccessThreshold: 90, BatchPerTick: 0},
		"unknown":   {ReleaseID: ptr.Of(uuid.New()), SoakHours: 1, SuccessThreshold: 90, BatchPerTick: 10},
		"window":    {ReleaseID: &rel.ID, SoakHours: 1, SuccessThreshold: 90, BatchPerTick: 10, Window: &deploy.Window{StartMinute: 5000, DurationMinutes: 60}},
	} {
		if err := f.svc.SetRollout(context.Background(), f.actor(), ro); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func protoUnmarshal(b []byte, m proto.Message) error { return proto.Unmarshal(b, m) }
