package updates

import (
	"context"
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
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/pki"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

type offers struct {
	mu     sync.Mutex
	online map[uuid.UUID]bool
	got    map[uuid.UUID]int
}

func (o *offers) Offer(id uuid.UUID, _ *agentv1.SignedEnvelope) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.online[id] {
		return false
	}
	o.got[id]++
	return true
}

type fx struct {
	t      *testing.T
	pool   *pgxpool.Pool
	svc    *Service
	dep    *deploy.Service
	org    uuid.UUID
	user   uuid.UUID
	site   uuid.UUID
	offset time.Duration
	mu     sync.Mutex
}

func (f *fx) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return time.Now().Add(f.offset)
}

func (f *fx) advance(d time.Duration) {
	f.mu.Lock()
	f.offset += d
	f.mu.Unlock()
}

func newFx(t *testing.T) *fx {
	db := pgtest.New(t)
	h, err := pki.NewHierarchy("Test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	auth := pki.NewAuthority(h.Root.Cert, h.Issuing, h.JobSigning)
	f := &fx{t: t, pool: db.Pool, org: uuid.New(), user: uuid.New(), site: uuid.New()}
	dep := &deploy.Service{Pool: db.Pool, Authority: func() *pki.Authority { return auth }, Dispatcher: &offers{online: map[uuid.UUID]bool{}, got: map[uuid.UUID]int{}}, Now: f.now}
	f.dep = dep
	f.svc = &Service{Pool: db.Pool, Deploy: dep, Now: f.now}
	dep.AfterTerminal = f.svc.AfterJob
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

func (f *fx) actor() Actor { return Actor{Org: f.org, User: f.user, IP: "127.0.0.1"} }

func (f *fx) device(host string, online bool) dbq.Device {
	id := uuid.New()
	f.exec("INSERT INTO devices (id, org_id, site_id, status, hostname, arch, online) VALUES ($1,$2,$3,'active',$4,'amd64',$5)", id, f.org, f.site, host, online)
	d, err := dbq.New(f.pool).GetDevice(context.Background(), id)
	if err != nil {
		f.t.Fatal(err)
	}
	return d
}

func (f *fx) group(name string, devices ...uuid.UUID) uuid.UUID {
	id := uuid.New()
	f.exec("INSERT INTO groups (id, org_id, name, kind, created_by) VALUES ($1,$2,$3,'static',$4)", id, f.org, name, f.user)
	for _, d := range devices {
		f.exec("INSERT INTO group_members (group_id, device_id) VALUES ($1,$2)", id, d)
	}
	return id
}

func uid(n int) string {
	return strings.Replace("00000000-0000-0000-0000-0000000000NN", "NN", string(rune('0'+n/10))+string(rune('0'+n%10)), 1)
}

func upd(n int, class, sev string, state agentv1.WuUpdateState) *agentv1.WuUpdate {
	return &agentv1.WuUpdate{UpdateId: uid(n), Revision: 1, Title: "Update " + uid(n)[34:], Kb: []string{"50000" + uid(n)[34:]}, Classification: class,
		Severity: sev, Products: []string{"Windows 11"}, State: state, ReleaseDate: time.Now().Add(-48 * time.Hour).Unix()}
}

func (f *fx) snapshot(d dbq.Device, rev uint64, ups ...*agentv1.WuUpdate) {
	f.t.Helper()
	snap := &agentv1.WuInventory{Updates: ups, ScannedAt: time.Now().Unix(), Policy: &agentv1.WuPolicyInfo{EffectiveSource: "windows_update"}}
	if err := f.svc.ApplySnapshot(context.Background(), d, rev, snap); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) count(sql string, args ...any) int {
	var n int
	if err := f.pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

const missing, hidden = agentv1.WuUpdateState_WU_UPDATE_STATE_MISSING, agentv1.WuUpdateState_WU_UPDATE_STATE_HIDDEN

func TestSnapshotBuildsCatalogAndReplacesDeviceState(t *testing.T) {
	f := newFx(t)
	d1, d2 := f.device("pc1", false), f.device("pc2", false)
	f.snapshot(d1, 1, upd(1, "Security Updates", "Critical", missing), upd(2, "Definition Updates", "", missing), upd(3, "Drivers", "", missing))
	f.snapshot(d2, 1, upd(1, "Security Updates", "Critical", missing))
	if n := f.count("SELECT count(*) FROM wu_updates WHERE org_id = $1", f.org); n != 3 {
		t.Fatalf("catalog has %d updates", n)
	}
	if n := f.count("SELECT count(*) FROM device_updates WHERE update_id = $1", uuid.MustParse(uid(1))); n != 2 {
		t.Fatalf("update 1 on %d devices", n)
	}
	// A new scan replaces the device's list (update 2 and 3 got installed, a hidden one appeared).
	f.snapshot(d1, 2, upd(1, "Security Updates", "Critical", missing), upd(4, "Updates", "Low", hidden))
	if n := f.count("SELECT count(*) FROM device_updates WHERE device_id = $1", d1.ID); n != 2 {
		t.Fatalf("device 1 now lists %d", n)
	}
	var rev int64
	var scanErr string
	var reboot bool
	_ = f.pool.QueryRow(context.Background(), "SELECT wu_rev, wu_scan_error, wu_reboot_required FROM devices WHERE id = $1", d1.ID).Scan(&rev, &scanErr, &reboot)
	if rev != 2 || scanErr != "" || reboot {
		t.Fatalf("device fields: %d %q %v", rev, scanErr, reboot)
	}
	// A failed scan keeps the error and clears the list.
	if err := f.svc.ApplySnapshot(context.Background(), d1, 3, &agentv1.WuInventory{ScanError: "0x80072ee2 no network", ScannedAt: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	_ = f.pool.QueryRow(context.Background(), "SELECT wu_scan_error FROM devices WHERE id = $1", d1.ID).Scan(&scanErr)
	if !strings.Contains(scanErr, "0x80072ee2") || f.count("SELECT count(*) FROM device_updates WHERE device_id = $1", d1.ID) != 0 {
		t.Fatalf("failed scan: %q", scanErr)
	}
}

func TestSnapshotRejectsHostileData(t *testing.T) {
	f := newFx(t)
	d := f.device("pc", false)
	good := upd(1, "Security Updates", "Critical", missing)
	cases := map[string]func(u *agentv1.WuUpdate){
		"bad id":            func(u *agentv1.WuUpdate) { u.UpdateId = "'; DROP TABLE wu_updates;--" },
		"unknown state":     func(u *agentv1.WuUpdate) { u.State = 99 },
		"bad severity":      func(u *agentv1.WuUpdate) { u.Severity = "Catastrophic" },
		"empty title":       func(u *agentv1.WuUpdate) { u.Title = "" },
		"negative rev":      func(u *agentv1.WuUpdate) { u.Revision = -4 },
		"bad kb":            func(u *agentv1.WuUpdate) { u.Kb = []string{"KB1; DROP"} },
		"too many kbs":      func(u *agentv1.WuUpdate) { u.Kb = make([]string, 40) },
		"too many products": func(u *agentv1.WuUpdate) { u.Products = make([]string, 40) },
	}
	for name, mut := range cases {
		u := proto.Clone(good).(*agentv1.WuUpdate)
		mut(u)
		err := f.svc.ApplySnapshot(context.Background(), d, 1, &agentv1.WuInventory{Updates: []*agentv1.WuUpdate{u}, ScannedAt: time.Now().Unix()})
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var many []*agentv1.WuUpdate
	for i := 0; i < maxUpdatesPerSnapshot+1; i++ {
		many = append(many, good)
	}
	if err := f.svc.ApplySnapshot(context.Background(), d, 1, &agentv1.WuInventory{Updates: many}); !errors.Is(err, ErrInvalid) {
		t.Errorf("too many updates: %v", err)
	}
	// Control characters in text are neutralized and a scan time in the future is not trusted.
	u := proto.Clone(good).(*agentv1.WuUpdate)
	u.Title = "Evil\x00\nTitle"
	if err := f.svc.ApplySnapshot(context.Background(), d, 1, &agentv1.WuInventory{Updates: []*agentv1.WuUpdate{u}, ScannedAt: time.Now().Add(100 * 24 * time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	var title string
	var at time.Time
	_ = f.pool.QueryRow(context.Background(), "SELECT title FROM wu_updates WHERE update_id = $1", uuid.MustParse(uid(1))).Scan(&title)
	_ = f.pool.QueryRow(context.Background(), "SELECT wu_scanned_at FROM devices WHERE id = $1", d.ID).Scan(&at)
	if strings.ContainsAny(title, "\x00\n") || at.After(time.Now().Add(time.Hour)) {
		t.Fatalf("title %q scanned %v", title, at)
	}
	if f.count("SELECT count(*) FROM wu_updates") != 1 {
		t.Fatal("hostile rows were stored")
	}
}

func TestDecisionsAreAuditedAndHideReachesTheRightDevices(t *testing.T) {
	f := newFx(t)
	a, b, c := f.device("a", true), f.device("b", true), f.device("c", true)
	f.snapshot(a, 1, upd(1, "Security Updates", "Critical", missing))
	f.snapshot(b, 1, upd(1, "Security Updates", "Critical", hidden))
	f.snapshot(c, 1)
	ctx := context.Background()
	id := uuid.MustParse(uid(1))
	res, err := f.svc.Decide(ctx, f.actor(), []uuid.UUID{id, uuid.New()}, "hidden", "breaks the printer")
	f.dep.Wait()
	if err != nil || res.Changed != 1 || res.Missing != 1 || res.HideJobs != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	// only the device that misses it is told to hide it
	var dev uuid.UUID
	_ = f.pool.QueryRow(ctx, "SELECT device_id FROM jobs WHERE type = 'wu_hide'").Scan(&dev)
	if dev != a.ID || f.count("SELECT count(*) FROM jobs WHERE type = 'wu_hide'") != 1 {
		t.Fatalf("hide jobs for %v", dev)
	}
	// declining afterwards un-hides where it was hidden by us (the update leaves the hidden decision)
	if res, err = f.svc.Decide(ctx, f.actor(), []uuid.UUID{id}, "declined", ""); err != nil || res.HideJobs != 1 {
		t.Fatalf("unhide: %+v %v", res, err)
	}
	var title string
	_ = f.pool.QueryRow(ctx, "SELECT title FROM jobs WHERE type = 'wu_hide' ORDER BY created_at DESC LIMIT 1").Scan(&title)
	if !strings.HasPrefix(title, "Unhide") {
		t.Fatalf("second job is %q", title)
	}
	if _, err := f.svc.Decide(ctx, f.actor(), []uuid.UUID{id}, "none", ""); err != nil {
		t.Fatal(err)
	}
	if f.count("SELECT count(*) FROM wu_approvals") != 0 {
		t.Fatal("reset left a decision behind")
	}
	if f.count("SELECT count(*) FROM audit_log WHERE action = 'wu.decision'") != 3 {
		t.Fatal("every decision must be audited")
	}
	if _, err := f.svc.Decide(ctx, f.actor(), []uuid.UUID{id}, "maybe", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad decision: %v", err)
	}
}

func TestRulesApproveOnceAndNeverOverrideAnAdministrator(t *testing.T) {
	f := newFx(t)
	d := f.device("a", false)
	f.snapshot(d, 1,
		upd(1, "Security Updates", "Critical", missing),  // matches
		upd(2, "Security Updates", "Low", missing),       // severity does not match
		upd(3, "Definition Updates", "", missing),        // classification does not match
		upd(4, "Security Updates", "Important", missing), // the administrator declined it
		upd(5, "Drivers", "", missing))                   // drivers need include_drivers
	f.exec("UPDATE wu_updates SET is_driver = true WHERE update_id = $1", uuid.MustParse(uid(5)))
	ctx := context.Background()
	if _, err := f.svc.Decide(ctx, f.actor(), []uuid.UUID{uuid.MustParse(uid(4))}, "declined", "known bad"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SaveRule(ctx, f.actor(), nil, Rule{Name: "Security", Classifications: []string{"security updates"}, Severities: []string{"Critical", "Important"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SaveRule(ctx, f.actor(), nil, Rule{Name: "Everything slowly", DelayDays: 30, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	f.svc.Tick(ctx)
	decision := func(n int) string {
		var d string
		_ = f.pool.QueryRow(ctx, "SELECT COALESCE((SELECT decision || '/' || source FROM wu_approvals WHERE update_id = $1), 'pending')", uuid.MustParse(uid(n))).Scan(&d)
		return d
	}
	want := map[int]string{1: "approved/rule", 2: "pending", 3: "pending", 4: "declined/manual", 5: "pending"}
	for n, w := range want {
		if got := decision(n); got != w {
			t.Errorf("update %d: %s, want %s", n, got, w)
		}
	}
	if f.count("SELECT count(*) FROM audit_log WHERE action = 'wu.auto_approve'") != 1 {
		t.Fatal("auto-approvals must be audited")
	}
	// With a delay in the past (the slow rule has 30 days; our updates are 2 days old) nothing more happens,
	// and including drivers approves the driver too.
	f.svc.Tick(ctx)
	if decision(2) != "pending" {
		t.Fatal("the delay was ignored")
	}
	if _, err := f.svc.SaveRule(ctx, f.actor(), nil, Rule{Name: "Drivers", Classifications: []string{"Drivers"}, IncludeDrivers: true, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	f.svc.Tick(ctx)
	if decision(5) != "approved/rule" {
		t.Fatalf("driver rule: %s", decision(5))
	}
	// Validation.
	for name, r := range map[string]Rule{
		"no name":      {},
		"bad severity": {Name: "x", Severities: []string{"Huge"}},
		"bad delay":    {Name: "x", DelayDays: 4000},
	} {
		if _, err := f.svc.SaveRule(ctx, f.actor(), nil, r); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	if _, err := f.svc.SaveRule(ctx, f.actor(), nil, Rule{Name: "Security"}); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate name: %v", err)
	}
}

// ringFixture builds a pilot ring (device p1, p2) and a broad ring (device b1) and one approved update
// missing on all three.
type ringFixture struct {
	*fx
	p1, p2, b1   dbq.Device
	pilot, broad Ring
	update       uuid.UUID
}

func newRingFixture(t *testing.T, soakHours, threshold int32) *ringFixture {
	f := newFx(t)
	r := &ringFixture{fx: f, update: uuid.MustParse(uid(1))}
	r.p1, r.p2, r.b1 = f.device("p1", true), f.device("p2", true), f.device("b1", true)
	pg, bg := f.group("pilot", r.p1.ID, r.p2.ID), f.group("broad", r.b1.ID)
	ctx := context.Background()
	var err error
	if r.pilot, err = f.svc.SaveRing(ctx, f.actor(), nil, Ring{Name: "Pilot", Ordinal: 1, GroupIDs: []uuid.UUID{pg}, SoakHours: soakHours, SuccessThreshold: threshold, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if r.broad, err = f.svc.SaveRing(ctx, f.actor(), nil, Ring{Name: "Broad", Ordinal: 2, GroupIDs: []uuid.UUID{bg}, SuccessThreshold: threshold, Enabled: true,
		Reboot: RebootCfg{Allow: "outside_active_hours", ActiveStart: 480, ActiveEnd: 1020}}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []dbq.Device{r.p1, r.p2, r.b1} {
		f.snapshot(d, 1, upd(1, "Security Updates", "Critical", missing))
	}
	if _, err := f.svc.Decide(ctx, f.actor(), []uuid.UUID{r.update}, "approved", ""); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *ringFixture) jobsFor(d dbq.Device) []dbq.Job {
	rows, err := r.pool.Query(context.Background(), "SELECT id FROM jobs WHERE device_id = $1 AND type = 'wu_install' ORDER BY created_at", d.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	var out []dbq.Job
	for _, id := range ids {
		j, err := dbq.New(r.pool).GetJob(context.Background(), dbq.GetJobParams{ID: id, OrgID: r.org})
		if err != nil {
			r.t.Fatal(err)
		}
		out = append(out, j)
	}
	return out
}

// finish reports a job's result the way the agent would.
func (r *ringFixture) finish(d dbq.Device, j dbq.Job, result agentv1.WuResult) {
	r.t.Helper()
	err := r.dep.ApplyUpdate(context.Background(), d, &agentv1.JobUpdate{JobId: j.ID.String(), State: agentv1.JobState_JOB_STATE_SUCCEEDED,
		Result: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, WuResults: []*agentv1.WuUpdateResult{{UpdateId: r.update.String(), Result: result}}}})
	if result == agentv1.WuResult_WU_RESULT_FAILED {
		err = r.dep.ApplyUpdate(context.Background(), d, &agentv1.JobUpdate{JobId: j.ID.String(), State: agentv1.JobState_JOB_STATE_FAILED,
			Result: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_FAILED, WuResults: []*agentv1.WuUpdateResult{{UpdateId: r.update.String(), Result: result, Hresult: -2145124322}}}})
	}
	if err != nil {
		r.t.Fatal(err)
	}
}

func TestRingsPilotFirstThenBroadAfterSoakAndSuccess(t *testing.T) {
	r := newRingFixture(t, 4, 90)
	ctx := context.Background()
	r.svc.Tick(ctx)
	r.dep.Wait()
	if len(r.jobsFor(r.p1)) != 1 || len(r.jobsFor(r.p2)) != 1 || len(r.jobsFor(r.b1)) != 0 {
		t.Fatalf("only the pilot ring may start: %d %d %d", len(r.jobsFor(r.p1)), len(r.jobsFor(r.p2)), len(r.jobsFor(r.b1)))
	}
	j := r.jobsFor(r.p1)[0]
	var env agentv1.JobEnvelope
	if err := proto.Unmarshal(j.Body, &env); err != nil {
		t.Fatal(err)
	}
	if env.Type != agentv1.JobType_JOB_TYPE_WU_INSTALL || len(env.GetWuInstall().Updates) != 1 || env.GetWuInstall().Updates[0].UpdateId != r.update.String() ||
		env.GetWuInstall().Reboot.Allow != agentv1.RebootAllow_REBOOT_ALLOW_NEVER {
		t.Fatalf("pilot job: %+v", env.GetWuInstall())
	}
	// Both pilot devices succeed, but the soak time has not passed: the broad ring waits.
	r.finish(r.p1, r.jobsFor(r.p1)[0], agentv1.WuResult_WU_RESULT_INSTALLED_REBOOT)
	r.finish(r.p2, r.jobsFor(r.p2)[0], agentv1.WuResult_WU_RESULT_INSTALLED)
	r.svc.Tick(ctx)
	if len(r.jobsFor(r.b1)) != 0 {
		t.Fatal("the broad ring started before the soak time was over")
	}
	r.advance(5 * time.Hour)
	r.svc.Tick(ctx)
	r.dep.Wait()
	bj := r.jobsFor(r.b1)
	if len(bj) != 1 {
		t.Fatalf("broad ring jobs: %d", len(bj))
	}
	_ = proto.Unmarshal(bj[0].Body, &env)
	if env.GetWuInstall().Reboot.Allow != agentv1.RebootAllow_REBOOT_ALLOW_OUTSIDE_ACTIVE_HOURS || env.GetWuInstall().Reboot.ActiveHours.StartMinute != 480 {
		t.Fatalf("the ring's restart policy did not reach the job: %+v", env.GetWuInstall().Reboot)
	}
	// Nothing is queued twice while a job is in flight or after it succeeded.
	r.svc.Tick(ctx)
	r.finish(r.b1, bj[0], agentv1.WuResult_WU_RESULT_INSTALLED)
	r.svc.Tick(ctx)
	if len(r.jobsFor(r.b1)) != 1 || len(r.jobsFor(r.p1)) != 1 {
		t.Fatal("an installed update was queued again")
	}
}

func TestRingFailureRaisesAHoldUntilAnAdministratorReleasesIt(t *testing.T) {
	r := newRingFixture(t, 0, 90)
	ctx := context.Background()
	r.svc.Tick(ctx)
	r.finish(r.p1, r.jobsFor(r.p1)[0], agentv1.WuResult_WU_RESULT_FAILED)
	r.finish(r.p2, r.jobsFor(r.p2)[0], agentv1.WuResult_WU_RESULT_INSTALLED)
	r.svc.Tick(ctx)
	r.dep.Wait()
	if len(r.jobsFor(r.b1)) != 0 {
		t.Fatal("a failing pilot must stop the broad ring")
	}
	holds, err := r.svc.ListHolds(ctx, r.org)
	if err != nil || len(holds) != 1 || !strings.Contains(holds[0].Reason, "1 of 2") || holds[0].RingName != "Pilot" {
		t.Fatalf("%+v %v", holds, err)
	}
	if r.count("SELECT count(*) FROM audit_log WHERE action = 'wu.hold'") != 1 {
		t.Fatal("holds must be audited")
	}
	// The hold is not raised again on the next ticks.
	r.svc.Tick(ctx)
	if h, _ := r.svc.ListHolds(ctx, r.org); len(h) != 1 {
		t.Fatalf("holds: %d", len(h))
	}
	if err := r.svc.ReleaseHold(ctx, r.actor(), holds[0].ID); err != nil {
		t.Fatal(err)
	}
	r.svc.Tick(ctx)
	r.dep.Wait()
	if len(r.jobsFor(r.b1)) != 1 {
		t.Fatal("released hold must let the update continue")
	}
	if err := r.svc.ReleaseHold(ctx, r.actor(), holds[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second release: %v", err)
	}
}

func TestFailedInstallsAreRetriedLaterAndNotForever(t *testing.T) {
	r := newRingFixture(t, 0, 10) // a lenient threshold: the failure itself does not raise a hold
	ctx := context.Background()
	for attempt := 1; attempt <= maxAutoFailures; attempt++ {
		r.svc.Tick(ctx)
		js := r.jobsFor(r.p1)
		if len(js) != attempt {
			t.Fatalf("attempt %d: %d jobs", attempt, len(js))
		}
		r.finish(r.p1, js[attempt-1], agentv1.WuResult_WU_RESULT_FAILED)
		r.svc.Tick(ctx)
		if len(r.jobsFor(r.p1)) != attempt {
			t.Fatalf("retried at once after failure %d", attempt)
		}
		r.advance(25 * time.Hour)
	}
	r.svc.Tick(ctx)
	if n := len(r.jobsFor(r.p1)); n != maxAutoFailures {
		t.Fatalf("after %d failures the device is left alone, but it has %d jobs", maxAutoFailures, n)
	}
}

func TestExpiredJobsReleaseTheirUpdates(t *testing.T) {
	r := newRingFixture(t, 0, 90)
	ctx := context.Background()
	r.svc.Tick(ctx)
	j := r.jobsFor(r.p1)[0]
	if err := r.dep.ApplyUpdate(ctx, r.p1, &agentv1.JobUpdate{JobId: j.ID.String(), State: agentv1.JobState_JOB_STATE_EXPIRED}); err != nil {
		t.Fatal(err)
	}
	if r.count("SELECT count(*) FROM wu_attempts WHERE device_id = $1", r.p1.ID) != 0 {
		t.Fatal("an expired job left its attempt behind, so the update would never be planned again")
	}
	r.svc.Tick(ctx)
	if len(r.jobsFor(r.p1)) != 2 {
		t.Fatalf("the update was not planned again: %d", len(r.jobsFor(r.p1)))
	}
}

func TestDeviceActions(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	online, offline := f.device("on", true), f.device("off", false)
	f.snapshot(online, 1, upd(1, "Security Updates", "Critical", missing), upd(2, "Updates", "", hidden))
	jobType := func(id uuid.UUID) string {
		var t string
		_ = f.pool.QueryRow(ctx, "SELECT type FROM jobs WHERE id = $1", id).Scan(&t)
		return t
	}
	id, err := f.svc.ScanDevice(ctx, f.actor(), online.ID)
	if err != nil || jobType(id) != "wu_scan" {
		t.Fatalf("scan: %v %v", id, err)
	}
	// Install only what the device's scan lists as missing.
	if _, err := f.svc.InstallOnDevice(ctx, f.actor(), online.ID, []string{uid(2), uuid.NewString()}, RebootCfg{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("hidden or unknown updates must not be installable: %v", err)
	}
	id, err = f.svc.InstallOnDevice(ctx, f.actor(), online.ID, []string{uid(1), uid(2)}, RebootCfg{Allow: "deadline", DeadlineHours: 24})
	f.dep.Wait()
	if err != nil || jobType(id) != "wu_install" {
		t.Fatalf("install: %v %v", id, err)
	}
	var env agentv1.JobEnvelope
	var body []byte
	_ = f.pool.QueryRow(ctx, "SELECT body FROM jobs WHERE id = $1", id).Scan(&body)
	_ = proto.Unmarshal(body, &env)
	if len(env.GetWuInstall().Updates) != 1 || env.GetWuInstall().Reboot.Allow != agentv1.RebootAllow_REBOOT_ALLOW_DEADLINE || env.GetWuInstall().Reboot.DeadlineAt == 0 {
		t.Fatalf("%+v", env.GetWuInstall())
	}
	if _, err := f.svc.InstallOnDevice(ctx, f.actor(), online.ID, []string{uid(1)}, RebootCfg{Allow: "now"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an install cannot demand an immediate restart: %v", err)
	}
	// Restart: online devices only, bounded countdown.
	if _, err := f.svc.RebootDevice(ctx, f.actor(), offline.ID, 5, ""); !errors.Is(err, ErrOffline) {
		t.Fatalf("offline restart: %v", err)
	}
	if _, err := f.svc.RebootDevice(ctx, f.actor(), online.ID, 0, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no countdown: %v", err)
	}
	id, err = f.svc.RebootDevice(ctx, f.actor(), online.ID, 10, "maintenance\nnow")
	if err != nil || jobType(id) != "reboot" {
		t.Fatalf("reboot: %v %v", id, err)
	}
	_ = f.pool.QueryRow(ctx, "SELECT body FROM jobs WHERE id = $1", id).Scan(&body)
	_ = proto.Unmarshal(body, &env)
	if env.GetReboot().Reboot.NotifyMinutes != 10 || strings.Contains(env.GetReboot().Reason, "\n") {
		t.Fatalf("%+v", env.GetReboot())
	}
	if f.count("SELECT count(*) FROM audit_log WHERE action IN ('wu.scan','wu.install','device.reboot')") != 3 {
		t.Fatal("device actions must be audited")
	}
	// Another organization's device is not reachable.
	if _, err := f.svc.ScanDevice(ctx, Actor{Org: uuid.New(), User: f.user}, online.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-org: %v", err)
	}
	// Install everywhere: only devices that miss it.
	other := f.device("other", true)
	f.snapshot(other, 1, upd(1, "Security Updates", "Critical", missing))
	n, err := f.svc.InstallUpdate(ctx, f.actor(), uuid.MustParse(uid(1)), nil, RebootCfg{})
	f.dep.Wait()
	if err != nil || n != 2 {
		t.Fatalf("install everywhere: %d %v", n, err)
	}
	if _, err := f.svc.InstallUpdate(ctx, f.actor(), uuid.MustParse(uid(2)), nil, RebootCfg{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an update nobody misses: %v", err)
	}
}

func TestOnlineCheckAndInstallAreOneOffAndAudited(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	d := f.device("wsus-pc", true)
	f.snapshot(d, 1, upd(1, "Security Updates", "Critical", missing))
	// The organization follows each device's own source (WSUS) and includes drivers.
	if err := f.svc.SetSettings(ctx, f.actor(), Settings{Service: "default", IncludeDrivers: true}); err != nil {
		t.Fatal(err)
	}
	body := func(id uuid.UUID) *agentv1.JobEnvelope {
		var raw []byte
		_ = f.pool.QueryRow(ctx, "SELECT body FROM jobs WHERE id = $1", id).Scan(&raw)
		var env agentv1.JobEnvelope
		_ = proto.Unmarshal(raw, &env)
		return &env
	}
	// The normal scan and install keep using the organization's source and are not one-off.
	id, err := f.svc.ScanDevice(ctx, f.actor(), d.ID)
	if err != nil || body(id).GetWuScan().OneOff || body(id).GetWuScan().Service != agentv1.WuService_WU_SERVICE_DEFAULT {
		t.Fatalf("normal scan: %v %+v", err, body(id).GetWuScan())
	}
	id, err = f.svc.InstallOnDevice(ctx, f.actor(), d.ID, []string{uid(1)}, RebootCfg{})
	if err != nil || body(id).GetWuInstall().OneOff || body(id).GetWuInstall().Service != agentv1.WuService_WU_SERVICE_DEFAULT {
		t.Fatalf("normal install: %v %+v", err, body(id).GetWuInstall())
	}
	// The online check goes to Windows Update on the internet, never with drivers, and is remembered by nobody.
	id, err = f.svc.ScanDeviceOnline(ctx, f.actor(), d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(id).GetWuScan(); !b.OneOff || b.Service != agentv1.WuService_WU_SERVICE_WINDOWS_UPDATE || b.IncludeDrivers {
		t.Fatalf("online scan: %+v", b)
	}
	id, err = f.svc.InstallOnDeviceOnline(ctx, f.actor(), d.ID, []string{uid(1)}, RebootCfg{})
	f.dep.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if b := body(id).GetWuInstall(); !b.OneOff || b.Service != agentv1.WuService_WU_SERVICE_WINDOWS_UPDATE || b.IncludeDrivers || len(b.Updates) != 1 {
		t.Fatalf("online install: %+v", b)
	}
	if _, err := f.svc.InstallOnDeviceOnline(ctx, f.actor(), d.ID, []string{uuid.NewString()}, RebootCfg{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("only updates the last scan lists can be installed online: %v", err)
	}
	// Going around the organization's source is audited under its own actions, with the source named.
	if f.count("SELECT count(*) FROM audit_log WHERE action = 'wu.scan_online'") != 1 || f.count("SELECT count(*) FROM audit_log WHERE action = 'wu.install_online' AND details->>'source' = 'windows_update'") != 1 {
		t.Fatal("online check and install must be audited as such")
	}
	if _, err := f.svc.ScanDeviceOnline(ctx, Actor{Org: uuid.New(), User: f.user}, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-org: %v", err)
	}
}

func TestOnlineCheckIsRefusedForAnAgentThatWouldRememberIt(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	d := f.device("old-agent", true)
	f.snapshot(d, 1, upd(1, "Security Updates", "Critical", missing))
	f.exec("UPDATE devices SET agent_version = '1.1.2' WHERE id = $1", d.ID)
	// An agent before 1.1.3 ignores "one-off" and would use the internet for every daily scan from now on.
	if _, err := f.svc.ScanDeviceOnline(ctx, f.actor(), d.ID); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "1.1.3") {
		t.Fatalf("online scan for agent 1.1.2: %v", err)
	}
	if _, err := f.svc.InstallOnDeviceOnline(ctx, f.actor(), d.ID, []string{uid(1)}, RebootCfg{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("online install for agent 1.1.2: %v", err)
	}
	if f.count("SELECT count(*) FROM jobs WHERE device_id = $1", d.ID) != 0 || f.count("SELECT count(*) FROM audit_log WHERE action LIKE 'wu.%_online'") != 0 {
		t.Fatal("a refused request must not queue a job or write an audit entry")
	}
	if _, err := f.svc.ScanDevice(ctx, f.actor(), d.ID); err != nil {
		t.Fatalf("the normal scan still works for an old agent: %v", err)
	}
	for _, v := range []string{"1.1.3", "1.2.0", "test"} { // newer releases and development builds
		f.exec("UPDATE devices SET agent_version = $2 WHERE id = $1", d.ID, v)
		if _, err := f.svc.ScanDeviceOnline(ctx, f.actor(), d.ID); err != nil {
			t.Fatalf("online scan for agent %q: %v", v, err)
		}
	}
}

func TestSettingsReachEveryDeviceAndRingsAreValidated(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	d1, d2 := f.device("a", true), f.device("b", false)
	f.svc.Tick(ctx)
	f.dep.Wait()
	scans := func() int { return f.count("SELECT count(*) FROM jobs WHERE type = 'wu_scan'") }
	if scans() != 1 {
		t.Fatalf("a new online device gets one scan job: %d", scans())
	}
	f.svc.Tick(ctx)
	if scans() != 1 {
		t.Fatal("a device is sent the settings once")
	}
	if err := f.svc.SetSettings(ctx, f.actor(), Settings{Service: "microsoft_update", IncludeDrivers: true}); err != nil {
		t.Fatal(err)
	}
	f.exec("UPDATE devices SET online = true WHERE id = $1", d2.ID)
	f.svc.Tick(ctx)
	f.dep.Wait()
	if scans() != 3 { // d1 again with the new settings, d2 for the first time
		t.Fatalf("scan jobs after a settings change: %d", scans())
	}
	var body []byte
	_ = f.pool.QueryRow(ctx, "SELECT body FROM jobs WHERE device_id = $1 AND type = 'wu_scan' ORDER BY created_at DESC LIMIT 1", d1.ID).Scan(&body)
	var env agentv1.JobEnvelope
	_ = proto.Unmarshal(body, &env)
	if env.GetWuScan().Service != agentv1.WuService_WU_SERVICE_MICROSOFT_UPDATE || !env.GetWuScan().IncludeDrivers {
		t.Fatalf("%+v", env.GetWuScan())
	}
	if s := f.svc.GetSettings(ctx, f.org); s.Service != "microsoft_update" || !s.IncludeDrivers {
		t.Fatalf("%+v", s)
	}
	if err := f.svc.SetSettings(ctx, f.actor(), Settings{Service: "bing"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad service: %v", err)
	}

	// Ring validation.
	g := f.group("g", d1.ID)
	ok := Ring{Name: "Pilot", Ordinal: 1, GroupIDs: []uuid.UUID{g}, SuccessThreshold: 90, Enabled: true}
	if _, err := f.svc.SaveRing(ctx, f.actor(), nil, ok); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*Ring){
		"duplicate order": func(r *Ring) { r.Name = "Other" },
		"unknown group":   func(r *Ring) { r.Name, r.Ordinal, r.GroupIDs = "X", 2, []uuid.UUID{uuid.New()} },
		"threshold":       func(r *Ring) { r.Name, r.Ordinal, r.SuccessThreshold = "X", 2, 0 },
		"bad window": func(r *Ring) {
			r.Name, r.Ordinal, r.Window = "X", 2, &deploy.Window{StartMinute: 5000, DurationMinutes: 10}
		},
		"deadline without hours": func(r *Ring) { r.Name, r.Ordinal, r.Reboot = "X", 2, RebootCfg{Allow: "deadline"} },
		"bad restart policy":     func(r *Ring) { r.Name, r.Ordinal, r.Reboot = "X", 2, RebootCfg{Allow: "always"} },
	}
	for name, mut := range bad {
		r := ok
		mut(&r)
		_, err := f.svc.SaveRing(ctx, f.actor(), nil, r)
		want := ErrInvalid
		if name == "duplicate order" {
			want = ErrConflict
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := f.svc.DeleteRing(ctx, f.actor(), uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete unknown: %v", err)
	}
}

func TestRebootCfgProto(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	p := RebootCfg{Allow: "deadline", ActiveStart: 480, ActiveEnd: 1020, NotifyMinutes: 30, DeadlineHours: 48}.Proto(now)
	if p.Allow != agentv1.RebootAllow_REBOOT_ALLOW_DEADLINE || p.DeadlineAt != now.Add(48*time.Hour).Unix() || p.NotifyMinutes != 30 || p.ActiveHours.EndMinute != 1020 {
		t.Fatalf("%+v", p)
	}
	if p := (RebootCfg{}).Proto(now); p.Allow != agentv1.RebootAllow_REBOOT_ALLOW_NEVER {
		t.Fatalf("zero value must never restart: %+v", p)
	}
}

func TestGateRules(t *testing.T) {
	ring := dbq.WuRing{Name: "Pilot", SoakHours: 24, SuccessThreshold: 80}
	now := time.Now()
	first := now.Add(-30 * time.Hour)
	cases := []struct {
		name   string
		st     attemptStats
		hold   holdState
		needs  bool
		passed bool
		reason bool
	}{
		{"nobody needed it", attemptStats{}, holdState{}, false, true, false},
		{"nothing finished yet", attemptStats{total: 4, first: first}, holdState{}, false, false, false},
		{"soaked and healthy", attemptStats{total: 4, installed: 4, first: first}, holdState{}, false, true, false},
		{"still soaking", attemptStats{total: 4, installed: 4, first: now.Add(-2 * time.Hour)}, holdState{}, false, false, false},
		{"too many failures at once", attemptStats{total: 10, installed: 3, failed: 2, first: now.Add(-time.Hour)}, holdState{}, false, false, true},
		{"within the allowed failure rate", attemptStats{total: 10, installed: 9, failed: 1, first: first}, holdState{}, false, true, false},
		{"most of the ring has not reported", attemptStats{total: 10, installed: 2, first: first}, holdState{}, false, false, false},
		{"a week past the soak time one report is enough", attemptStats{total: 10, installed: 1, first: now.Add(-9 * 24 * time.Hour)}, holdState{}, false, true, false},
		{"open hold", attemptStats{total: 4, installed: 4, first: first}, holdState{open: true}, false, false, false},
		{"released hold", attemptStats{total: 4, failed: 4, first: first}, holdState{released: true}, false, true, false},
		{"ring has not started yet", attemptStats{}, holdState{}, true, false, false},
	}
	for _, c := range cases {
		passed, reason := gate(c.st, ring, c.hold, now, c.needs)
		if passed != c.passed || (reason != "") != c.reason {
			t.Errorf("%s: passed=%v reason=%q", c.name, passed, reason)
		}
	}
}

// The dashboard and the reports count a device as "needs a restart" from the heartbeat's pending-reboot flag or from the
// "restart required" of the last Windows Update scan. That scan flag is only refreshed by the next scan, so after the
// person restarted it stayed true and the dashboard kept counting a device whose own page showed nothing. It now counts
// only if the scan was taken after the last boot.
func TestStaleRestartRequiredFromAScanBeforeTheLastBootIsIgnored(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	now := time.Now()
	set := func(d dbq.Device, pending bool, scanRequired bool, scannedAgo time.Duration, uptime time.Duration) {
		f.exec(`UPDATE devices SET pending_reboot = $2, wu_reboot_required = $3, wu_scanned_at = $4, last_seen_at = $5, uptime_s = $6 WHERE id = $1`,
			d.ID, pending, scanRequired, now.Add(-scannedAgo), now, int64(uptime.Seconds()))
	}
	restarted := f.device("restarted-after-the-scan", true)
	set(restarted, false, true, 2*time.Hour, 10*time.Minute) // scan 2 h ago, booted 10 minutes ago
	stillPending := f.device("scan-after-the-boot", true)
	set(stillPending, false, true, 2*time.Hour, 4*time.Hour) // booted 4 h ago, scanned 2 h ago: still needs it
	heartbeat := f.device("heartbeat-says-so", true)
	set(heartbeat, true, false, 2*time.Hour, 10*time.Minute) // the agent sees a pending restart right now
	unknown := f.device("uptime-not-reported", true)
	set(unknown, false, true, 2*time.Hour, 0) // no uptime to compare with: keep the old behaviour

	rows, err := dbq.New(f.pool).ComplianceReport(ctx, f.org)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range rows {
		got[r.Hostname] = r.RebootPending != nil && *r.RebootPending
	}
	want := map[string]bool{"restarted-after-the-scan": false, "scan-after-the-boot": true, "heartbeat-says-so": true, "uptime-not-reported": true}
	for host, w := range want {
		if got[host] != w {
			t.Errorf("%s: needs a restart = %v, want %v", host, got[host], w)
		}
	}
}

// With the organization's Windows updates switched off nothing is scanned, approved, scheduled or installed, what devices
// report is dropped, and a restart (not a Windows update feature) still works. Switching back on picks the work up again.
func TestSwitchingWindowsUpdatesOffStopsEverything(t *testing.T) {
	r := newRingFixture(t, 0, 90)
	ctx := context.Background()
	on := true
	r.svc.Enabled = func(context.Context, uuid.UUID) bool { return on }

	on = false
	// The scheduler leaves the rings and the rules alone.
	r.svc.Tick(ctx)
	r.dep.Wait()
	if n := len(r.jobsFor(r.p1)) + len(r.jobsFor(r.p2)) + len(r.jobsFor(r.b1)); n != 0 {
		t.Fatalf("%d install jobs were queued while Windows updates are off", n)
	}
	// Every administrator action is refused.
	if _, err := r.svc.ScanDevice(ctx, r.actor(), r.p1.ID); !errors.Is(err, ErrDisabled) {
		t.Fatalf("scan: %v", err)
	}
	if _, err := r.svc.InstallOnDevice(ctx, r.actor(), r.p1.ID, []string{uid(1)}, RebootCfg{}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("install on a device: %v", err)
	}
	if _, err := r.svc.InstallUpdate(ctx, r.actor(), r.update, nil, RebootCfg{}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("install everywhere: %v", err)
	}
	if _, err := r.svc.HideOnDevice(ctx, r.actor(), r.p1.ID, []string{uid(1)}, true); !errors.Is(err, ErrDisabled) {
		t.Fatalf("hide: %v", err)
	}
	// What a device reports is acknowledged and dropped.
	before := r.count("SELECT count(*) FROM wu_updates WHERE org_id = $1", r.org)
	r.snapshot(r.p1, 2, upd(7, "Security Updates", "Critical", missing))
	if after := r.count("SELECT count(*) FROM wu_updates WHERE org_id = $1", r.org); after != before {
		t.Fatalf("a report was stored while Windows updates are off: %d -> %d", before, after)
	}
	// A restart is not a Windows update feature.
	if _, err := r.svc.RebootDevice(ctx, r.actor(), r.p1.ID, 5, "test"); err != nil {
		t.Fatalf("restart must keep working: %v", err)
	}
	r.dep.Wait()

	on = true
	r.svc.Tick(ctx)
	r.dep.Wait()
	if len(r.jobsFor(r.p1)) != 1 || len(r.jobsFor(r.p2)) != 1 {
		t.Fatalf("switching back on must resume the rollout: %d %d", len(r.jobsFor(r.p1)), len(r.jobsFor(r.p2)))
	}
}
