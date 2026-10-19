package policies

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func (f *fx) ring(name string, ordinal int, delayDays, soakHours, threshold int, devs ...uuid.UUID) uuid.UUID {
	f.t.Helper()
	g := f.group(devs...)
	id := uuid.New()
	f.exec(`INSERT INTO wu_rings (id, org_id, name, ordinal, group_ids, delay_days, soak_hours, success_threshold) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		id, f.org, name, ordinal, []uuid.UUID{g}, delayDays, soakHours, threshold)
	return id
}

func (f *fx) finish(status string, devs ...uuid.UUID) {
	f.t.Helper()
	for _, d := range devs {
		f.exec("UPDATE jobs SET status=$2 WHERE device_id=$1 AND type IN ('software_install','software_update') AND status IN ('queued','sent','accepted','waiting','running')", d, status)
	}
}

func (f *fx) stageStates(policy uuid.UUID) []string {
	f.t.Helper()
	ps, err := f.svc.List(context.Background(), f.org)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, p := range ps {
		if p.ID == policy {
			if p.Rollout == nil {
				f.t.Fatal("the policy has no rollout view")
			}
			var out []string
			for _, st := range p.Rollout.Stages {
				out = append(out, st.Name+":"+st.State)
			}
			return out
		}
	}
	f.t.Fatal("policy not listed")
	return nil
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestAVersionWaitsForApproval(t *testing.T) {
	f := newFx(t)
	d := f.device("d", time.Now())
	f.install(d, "1.0")
	g := f.group(d)
	f.policy("keep_updated", []uuid.UUID{g}, func(in *Input) { in.RequireApproval = true })
	ctx := context.Background()

	var needed []string
	f.svc.OnApprovalNeeded = func(_ context.Context, _ uuid.UUID, pkg, ver string) { needed = append(needed, pkg+" "+ver) }
	f.svc.Tick(ctx)
	if f.jobsFor(d) != 0 {
		t.Fatal("a version nobody approved must not go out")
	}
	if len(needed) == 0 || needed[0] != "Acme Tool 2.0" {
		t.Fatalf("the approval notification was not raised: %v", needed)
	}
	q, err := f.svc.Queue(ctx, f.org)
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Pending) != 1 || q.Pending[0].Version != "2.0" || q.Pending[0].Devices != 1 || len(q.Pending[0].Policies) != 1 {
		t.Fatalf("pending: %+v", q.Pending)
	}

	// Declined: still nothing, and it shows as decided.
	if err := f.svc.Decide(ctx, f.actor(), f.pkg, "2.0", "declined", "breaks the printer driver"); err != nil {
		t.Fatal(err)
	}
	f.svc.Tick(ctx)
	if f.jobsFor(d) != 0 {
		t.Fatal("a declined version must not go out")
	}
	if q, _ := f.svc.Queue(ctx, f.org); len(q.Pending) != 0 || len(q.Recent) != 1 || q.Recent[0].Decision != "declined" || q.Recent[0].Note == "" {
		t.Fatalf("queue after declining: %+v", q)
	}

	// Approved: it goes out.
	if err := f.svc.Decide(ctx, f.actor(), f.pkg, "2.0", "approved", ""); err != nil {
		t.Fatal(err)
	}
	f.svc.Tick(ctx)
	if f.jobsFor(d) != 1 {
		t.Fatal("an approved version must go out")
	}
	if f.count("SELECT count(*) FROM audit_log WHERE action IN ('software.approve','software.decline') AND actor_type='user'") != 2 {
		t.Fatal("decisions must be audited")
	}

	// Reset puts it back to waiting.
	if err := f.svc.Decide(ctx, f.actor(), f.pkg, "2.0", "reset", ""); err != nil {
		t.Fatal(err)
	}
	if q, _ := f.svc.Queue(ctx, f.org); len(q.Pending) != 1 {
		t.Fatalf("reset must make it pending again: %+v", q.Pending)
	}
	// A version that is not in the catalog, an unknown decision and a stranger's package are refused.
	if err := f.svc.Decide(ctx, f.actor(), f.pkg, "9.9", "approved", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown version: %v", err)
	}
	if err := f.svc.Decide(ctx, f.actor(), f.pkg, "2.0", "maybe", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown decision: %v", err)
	}
	if err := f.svc.Decide(ctx, Actor{Org: uuid.New(), User: f.user}, f.pkg, "2.0", "approved", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another organization's package: %v", err)
	}
}

func TestANewVersionNeedsItsOwnApproval(t *testing.T) {
	f := newFx(t)
	d := f.device("d", time.Now())
	f.install(d, "1.0")
	g := f.group(d)
	f.policy("keep_updated", []uuid.UUID{g}, func(in *Input) { in.RequireApproval = true })
	ctx := context.Background()
	if err := f.svc.Decide(ctx, f.actor(), f.pkg, "2.0", "approved", ""); err != nil {
		t.Fatal(err)
	}
	f.svc.Tick(ctx)
	f.finish("succeeded", d)
	f.install2(d, "2.0")
	f.catalog("3.0")
	f.advance(3 * time.Hour)
	f.svc.Tick(ctx)
	if f.jobsFor(d) != 1 {
		t.Fatal("approving 2.0 must not approve 3.0")
	}
}

func TestRingsRollOutInOrder(t *testing.T) {
	f := newFx(t)
	p1, b1, b2, loose := f.device("p1", time.Now()), f.device("b1", time.Now()), f.device("b2", time.Now()), f.device("loose", time.Now())
	for _, d := range []uuid.UUID{p1, b1, b2, loose} {
		f.install(d, "1.0")
	}
	f.ring("Pilot", 1, 0, 0, 90, p1)
	f.ring("Broad", 2, 0, 0, 90, b1, b2)
	pol := f.policy("keep_updated", []uuid.UUID{f.group(p1, b1, b2, loose)}, func(in *Input) { in.UseRings = true })
	ctx := context.Background()

	f.svc.Tick(ctx)
	if f.jobsFor(p1) != 1 || f.jobsFor(b1) != 0 || f.jobsFor(b2) != 0 || f.jobsFor(loose) != 0 {
		t.Fatalf("only the pilot ring goes first: p1=%d b1=%d b2=%d loose=%d", f.jobsFor(p1), f.jobsFor(b1), f.jobsFor(b2), f.jobsFor(loose))
	}
	if got := f.stageStates(pol); !equal(got, []string{"Pilot:running", "Broad:waiting", "Devices in no ring:waiting"}) {
		t.Fatalf("stages while the pilot runs: %v", got)
	}
	f.svc.Tick(ctx)
	if f.jobsFor(b1) != 0 {
		t.Fatal("the next ring waits until the pilot has reported")
	}

	f.finish("succeeded", p1)
	f.svc.Tick(ctx)
	if f.jobsFor(b1) != 1 || f.jobsFor(b2) != 1 || f.jobsFor(loose) != 0 {
		t.Fatalf("after a good pilot the broad ring follows: b1=%d b2=%d loose=%d", f.jobsFor(b1), f.jobsFor(b2), f.jobsFor(loose))
	}
	f.finish("succeeded", b1, b2)
	f.svc.Tick(ctx)
	if f.jobsFor(loose) != 1 {
		t.Fatal("devices in no ring come last, but they do get the update")
	}
	// Each stage's deployment is named after its ring.
	if f.count("SELECT count(*) FROM deployments WHERE name LIKE '%(Pilot)' OR name LIKE '%(Broad)'") != 2 {
		t.Fatal("deployments must name their ring")
	}
}

func TestARingThatFailsHoldsTheRolloutUntilReleased(t *testing.T) {
	f := newFx(t)
	p1, p2, b1 := f.device("p1", time.Now()), f.device("p2", time.Now()), f.device("b1", time.Now())
	for _, d := range []uuid.UUID{p1, p2, b1} {
		f.install(d, "1.0")
	}
	f.ring("Pilot", 1, 0, 0, 90, p1, p2)
	f.ring("Broad", 2, 0, 0, 90, b1)
	pol := f.policy("keep_updated", []uuid.UUID{f.group(p1, p2, b1)}, func(in *Input) { in.UseRings = true })
	ctx := context.Background()
	var held []string
	f.svc.OnHold = func(_ context.Context, _ uuid.UUID, title, ring, _ string) { held = append(held, title+"|"+ring) }

	f.svc.Tick(ctx)
	f.finish("failed", p1, p2)
	f.svc.Tick(ctx)
	if f.jobsFor(b1) != 0 {
		t.Fatal("a failing pilot must not reach the broad ring")
	}
	if len(held) != 1 || held[0] != "Acme Tool 2.0|Pilot" {
		t.Fatalf("the hold notification: %v", held)
	}
	if f.count("SELECT count(*) FROM audit_log WHERE action='software.hold' AND actor_type='system'") != 1 {
		t.Fatal("a hold must be audited")
	}
	f.svc.Tick(ctx)
	if f.count("SELECT count(*) FROM software_holds WHERE released_at IS NULL") != 1 || len(held) != 1 {
		t.Fatal("a hold is raised once")
	}
	if got := f.stageStates(pol); got[0] != "Pilot:held" || got[1] != "Broad:waiting" {
		t.Fatalf("stages while held: %v", got)
	}
	q, err := f.svc.Queue(ctx, f.org)
	if err != nil || len(q.Holds) != 1 || q.Holds[0].Ring != "Pilot" || q.Holds[0].Version != "2.0" {
		t.Fatalf("holds in the queue: %+v %v", q, err)
	}

	if err := f.svc.ReleaseHold(ctx, f.actor(), q.Holds[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ReleaseHold(ctx, f.actor(), q.Holds[0].ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("releasing twice: %v", err)
	}
	f.svc.Tick(ctx)
	if f.jobsFor(b1) != 1 {
		t.Fatal("releasing the hold lets the version move on")
	}
}

func TestRingDelayCountsFromAvailability(t *testing.T) {
	f := newFx(t)
	p1, b1 := f.device("p1", time.Now()), f.device("b1", time.Now())
	f.install(p1, "1.0")
	f.install(b1, "1.0")
	f.ring("Pilot", 1, 0, 0, 90, p1)
	f.ring("Broad", 2, 1, 0, 90, b1) // a day after the version is available
	f.policy("keep_updated", []uuid.UUID{f.group(p1, b1)}, func(in *Input) { in.UseRings = true })
	ctx := context.Background()
	f.svc.Tick(ctx)
	f.finish("succeeded", p1)
	f.svc.Tick(ctx)
	if f.jobsFor(b1) != 0 {
		t.Fatal("the broad ring's one-day delay has not passed")
	}
	f.advance(25 * time.Hour)
	f.svc.Tick(ctx)
	if f.jobsFor(b1) != 1 {
		t.Fatal("after the delay the broad ring goes")
	}
}

func TestRingsAreOnlyForKeepUpdatedPolicies(t *testing.T) {
	f := newFx(t)
	g := f.group(f.device("d", time.Now()))
	_, err := f.svc.Create(context.Background(), f.actor(), Input{Name: "b", Kind: "baseline", PackageID: f.pkg, GroupIDs: []uuid.UUID{g}, Enabled: true, UseRings: true})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("a baseline with rings: %v", err)
	}
}

func TestNoRingsDefinedMeansOneStage(t *testing.T) {
	f := newFx(t)
	d := f.device("d", time.Now())
	f.install(d, "1.0")
	pol := f.policy("keep_updated", []uuid.UUID{f.group(d)}, func(in *Input) { in.UseRings = true })
	f.svc.Tick(context.Background())
	if f.jobsFor(d) != 1 {
		t.Fatal("with no ring defined, using rings must not stop the update")
	}
	if got := f.stageStates(pol); !equal(got, []string{"All devices:running"}) {
		t.Fatalf("stages: %v", got)
	}
}

func TestNobodyIsAskedToApproveAVersionNobodyNeeds(t *testing.T) {
	f := newFx(t)
	d := f.device("d", time.Now())
	f.install(d, "2.0") // already current
	f.policy("keep_updated", []uuid.UUID{f.group(d)}, func(in *Input) { in.RequireApproval = true })
	asked := 0
	f.svc.OnApprovalNeeded = func(context.Context, uuid.UUID, string, string) { asked++ }
	f.svc.Tick(context.Background())
	q, err := f.svc.Queue(context.Background(), f.org)
	if err != nil || len(q.Pending) != 0 || asked != 0 {
		t.Fatalf("nothing needs a decision: pending=%v asked=%d err=%v", q.Pending, asked, err)
	}
}
