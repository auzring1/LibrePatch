package deploy

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
)

// One job can be stopped on its own: a job waiting on the PC, a job the PC is running, and nothing else; a finished job
// cannot be cancelled.
func TestOneJobCanBeCancelled(t *testing.T) {
	f := newFixture(t)
	f.catalog(false)
	dev := f.device("pc-1", "amd64")
	plan, err := f.create(Request{Action: "install", Scope: "machine", DeviceIDs: []uuid.UUID{dev}})
	if err != nil {
		t.Fatal(err)
	}
	job := f.jobs(plan.DeploymentID)[0]
	ctx := context.Background()
	f.exec("UPDATE jobs SET status = 'accepted', acked_at = now() WHERE id = $1", job.ID)

	if err := f.svc.CancelJob(ctx, f.org, f.user, job.ID, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	got, _ := dbq.New(f.pool).GetJob(ctx, dbq.GetJobParams{ID: job.ID, OrgID: f.org})
	if got.Status != "cancelled" || got.StatusReason != "cancelled_by_administrator" || !got.CancelPending {
		t.Fatalf("job after cancel: %+v", got)
	}
	var n int
	if err := f.pool.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE action = 'job.cancel' AND org_id = $1", f.org).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the cancellation is audited: %d %v", n, err)
	}
	// Already finished: refused. Unknown: not found.
	if err := f.svc.CancelJob(ctx, f.org, f.user, job.ID, ""); !errors.Is(err, ErrNotCancellable) {
		t.Fatalf("second cancel: %v", err)
	}
	if err := f.svc.CancelJob(ctx, f.org, f.user, uuid.New(), ""); err == nil {
		t.Fatal("an unknown job is not found")
	}
	// A running job can be cancelled too.
	plan2, err := f.create(Request{Action: "install", Scope: "machine", DeviceIDs: []uuid.UUID{dev}, Name: "again"})
	if err != nil {
		t.Fatal(err)
	}
	running := f.jobs(plan2.DeploymentID)[0]
	f.exec("UPDATE jobs SET status = 'running', acked_at = now() WHERE id = $1", running.ID)
	if err := f.svc.CancelJob(ctx, f.org, f.user, running.ID, ""); err != nil {
		t.Fatalf("cancel a running job: %v", err)
	}
}
