package deploy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/shared/envelope"
)

// revokeFixture is an active, online device with one valid certificate, and a record of the connections that were cut.
func revokeFixture(t *testing.T) (*fixture, dbq.Device, *[]string) {
	f := newFixture(t)
	id := f.device("lost-1", "amd64")
	f.exec("UPDATE devices SET online = true WHERE id = $1", id)
	f.exec(`INSERT INTO device_certs (serial, device_id, not_before, not_after, public_key_sha256) VALUES ('abc123', $1, now(), now() + interval '30 days', '\x00')`, id)
	var cut []string
	d, err := dbq.New(f.pool).GetDevice(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.OnRevoked = func(_, device uuid.UUID) { cut = append(cut, device.String()) }
	return f, d, &cut
}

func TestRevokingWithUninstallAsksFirstAndRevokesWhenTheAgentSaysItIsGoing(t *testing.T) {
	f, d, cut := revokeFixture(t)
	ctx := context.Background()
	id, err := f.svc.RequestRevokeWithUninstall(ctx, f.org, f.user, d.ID, "127.0.0.1", "lost laptop")
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Wait()
	// Not revoked yet: a revoked device could not be told anything.
	if f.count("SELECT count(*) FROM devices WHERE id = $1 AND status = 'active'", d.ID) != 1 || len(*cut) != 0 {
		t.Fatal("the device must stay active until the agent has said it is uninstalling")
	}
	j, err := dbq.New(f.pool).GetJob(ctx, dbq.GetJobParams{ID: id, OrgID: f.org})
	if err != nil || j.Type != "agent_uninstall" || j.UserSid != "" {
		t.Fatalf("%v %+v", err, j)
	}
	if b := envOf(t, j).GetAgentUninstall(); b == nil || b.Reason != "lost laptop" || b.RequestedBy != f.user.String() {
		t.Fatalf("body %+v", b)
	}
	if again, err := f.svc.RequestRevokeWithUninstall(ctx, f.org, f.user, d.ID, "", "again"); err != nil || again != id {
		t.Fatalf("asking twice reuses the open request: %v %v", again, err)
	}
	if f.count("SELECT count(*) FROM audit_log WHERE action = 'device.revoke_requested'") != 1 {
		t.Fatal("the request is audited once")
	}
	if open, err := dbq.New(f.pool).OpenAgentUninstall(ctx, d.ID); err != nil || open != id {
		t.Fatalf("the device page can see it is pending: %v %v", open, err)
	}

	// The agent accepts and runs: still active. It reports done: now it is revoked, under the administrator's name.
	for _, st := range []agentv1.JobState{agentv1.JobState_JOB_STATE_ACCEPTED, agentv1.JobState_JOB_STATE_RUNNING} {
		if err := f.svc.ApplyUpdate(ctx, d, &agentv1.JobUpdate{JobId: id.String(), State: st}); err != nil {
			t.Fatal(err)
		}
	}
	if f.count("SELECT count(*) FROM devices WHERE id = $1 AND status = 'active'", d.ID) != 1 {
		t.Fatal("a running uninstall has not finished yet")
	}
	if err := f.svc.ApplyUpdate(ctx, d, &agentv1.JobUpdate{JobId: id.String(), State: agentv1.JobState_JOB_STATE_SUCCEEDED,
		Result: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS}}); err != nil {
		t.Fatal(err)
	}
	if f.count("SELECT count(*) FROM devices WHERE id = $1 AND status = 'revoked' AND revoked_by = $2", d.ID, f.user) != 1 ||
		f.count("SELECT count(*) FROM device_certs WHERE device_id = $1 AND revoked_at IS NOT NULL", d.ID) != 1 {
		t.Fatal("the device and its certificate are revoked")
	}
	if len(*cut) != 1 || (*cut)[0] != d.ID.String() {
		t.Fatalf("the live connection is cut once: %v", *cut)
	}
	if f.count("SELECT count(*) FROM audit_log WHERE action = 'device.revoke' AND actor_id = $1", f.user.String()) != 1 {
		t.Fatal("the revoke is audited under the administrator who asked")
	}
	if f.count("SELECT count(*) FROM devices WHERE id = $1 AND status_reason LIKE 'lost laptop%'", d.ID) != 1 {
		t.Fatal("the reason is kept")
	}
}

func TestAnAgentThatCouldNotUninstallLeavesTheDeviceActive(t *testing.T) {
	f, d, cut := revokeFixture(t)
	ctx := context.Background()
	id, err := f.svc.RequestRevokeWithUninstall(ctx, f.org, f.user, d.ID, "", "lost laptop")
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Wait()
	if err := f.svc.ApplyUpdate(ctx, d, &agentv1.JobUpdate{JobId: id.String(), State: agentv1.JobState_JOB_STATE_FAILED, Reason: "failed"}); err != nil {
		t.Fatal(err)
	}
	if f.count("SELECT count(*) FROM devices WHERE id = $1 AND status = 'active'", d.ID) != 1 || len(*cut) != 0 {
		t.Fatal("a failed uninstall must not revoke; the administrator decides")
	}
	if _, err := dbq.New(f.pool).OpenAgentUninstall(ctx, d.ID); err == nil {
		t.Fatal("a finished request is no longer pending")
	}
}

func TestAnAgentThatWentSilentWhileUninstallingIsRevokedLater(t *testing.T) {
	f, d, cut := revokeFixture(t)
	ctx := context.Background()
	id, err := f.svc.RequestRevokeWithUninstall(ctx, f.org, f.user, d.ID, "", "lost laptop")
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Wait()
	if err := f.svc.ApplyUpdate(ctx, d, &agentv1.JobUpdate{JobId: id.String(), State: agentv1.JobState_JOB_STATE_ACCEPTED}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ApplyUpdate(ctx, d, &agentv1.JobUpdate{JobId: id.String(), State: agentv1.JobState_JOB_STATE_RUNNING}); err != nil {
		t.Fatal(err)
	}
	f.svc.Sweep(ctx)
	if f.count("SELECT count(*) FROM devices WHERE id = $1 AND status = 'active'", d.ID) != 1 {
		t.Fatal("it may still be about to answer")
	}
	f.exec("UPDATE jobs SET started_at = now() - interval '11 minutes' WHERE id = $1", id)
	f.svc.Sweep(ctx)
	if f.count("SELECT count(*) FROM devices WHERE id = $1 AND status = 'revoked'", d.ID) != 1 || len(*cut) != 1 {
		t.Fatalf("a silent agent that has been uninstalling for ten minutes is gone: %v", *cut)
	}
}

func TestRevokingRightAwayDropsAWaitingRequest(t *testing.T) {
	f, d, cut := revokeFixture(t)
	ctx := context.Background()
	id, err := f.svc.RequestRevokeWithUninstall(ctx, f.org, f.user, d.ID, "", "lost laptop")
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Wait()
	if err := f.svc.CancelPendingUninstall(ctx, f.org, f.user, d.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.RevokeDevice(ctx, f.org, &f.user, d.ID, "revoked by administrator", "", nil); err != nil {
		t.Fatal(err)
	}
	var status string
	_ = f.pool.QueryRow(ctx, "SELECT status FROM jobs WHERE id = $1", id).Scan(&status)
	if status != "cancelled" || len(*cut) != 1 {
		t.Fatalf("the waiting request is cancelled and the device revoked: %s %v", status, *cut)
	}
	if err := f.svc.RevokeDevice(ctx, f.org, &f.user, d.ID, "again", "", nil); !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("revoking twice: %v", err)
	}
	if _, err := f.svc.RequestRevokeWithUninstall(ctx, f.org, f.user, d.ID, "", "x"); !errors.Is(err, ErrNotActive) {
		t.Fatalf("a revoked device has no agent to ask: %v", err)
	}
}

// An agent refuses a signed job that lives longer than the protocol allows, so the request must fit.
func TestTheUninstallRequestFitsTheProtocolsMaximumLifetime(t *testing.T) {
	if agentUninstallExpiry+time.Minute > envelope.MaxLifetime {
		t.Fatalf("%v plus the minute the issue time is set back is over %v: the agent would refuse it as expired", agentUninstallExpiry, envelope.MaxLifetime)
	}
}
