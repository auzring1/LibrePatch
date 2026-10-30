package deploy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

const testProfileSID = "S-1-5-21-111-222-333-1105"

// profileDevice is an online device that has reported one idle profile and one signed-in one.
// count runs a COUNT query.
func (f *fixture) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func profileDevice(f *fixture) (dev dbq.Device) {
	id := f.device("pc-1", "amd64")
	f.exec("UPDATE devices SET online = true WHERE id = $1", id)
	f.exec(`INSERT INTO device_users (device_id, sid, username, domain, profile_path, loaded) VALUES
		($1, $2, 'old.user', 'CONTOSO', 'C:\Users\old.user', false),
		($1, 'S-1-5-21-111-222-333-1106', 'here.now', 'CONTOSO', 'C:\Users\here.now', true)`, id, testProfileSID)
	d, err := dbq.New(f.pool).GetDevice(context.Background(), id)
	if err != nil {
		f.t.Fatal(err)
	}
	return d
}

func TestRemovingAProfileQueuesOneAuditedShortLivedJob(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	d := profileDevice(f)
	id, err := f.svc.RemoveProfile(ctx, f.org, f.user, d.ID, "127.0.0.1", testProfileSID)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Wait()
	j, err := dbq.New(f.pool).GetJob(ctx, dbq.GetJobParams{ID: id, OrgID: f.org})
	if err != nil || j.Type != "profile_delete" || j.UserSid != "" {
		t.Fatalf("%v %+v", err, j)
	}
	b := envOf(t, j).GetProfileDelete()
	if b == nil || b.Sid != testProfileSID || b.Username != `CONTOSO\old.user` {
		t.Fatalf("body %+v", b)
	}
	if left := time.Until(j.ExpiresAt); left > profileRemovalExpiry+time.Minute || left < 30*time.Minute {
		t.Fatalf("a removal runs now or not at all, not hours later: %v", left)
	}
	if f.count("SELECT count(*) FROM audit_log WHERE action = 'device.profile_remove' AND outcome = 'success'") != 1 {
		t.Fatal("a profile removal is audited")
	}
}

func TestAProfileThatIsInUseOrUnknownOrOfflineIsRefusedHere(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	d := profileDevice(f)
	if _, err := f.svc.RemoveProfile(ctx, f.org, f.user, d.ID, "", "S-1-5-21-111-222-333-1106"); !errors.Is(err, ErrProfileInUse) {
		t.Fatalf("a signed-in person: %v", err)
	}
	if _, err := f.svc.RemoveProfile(ctx, f.org, f.user, d.ID, "", "S-1-5-21-9-9-9-9"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a profile the device never reported: %v", err)
	}
	f.exec("UPDATE devices SET online = false WHERE id = $1", d.ID)
	if _, err := f.svc.RemoveProfile(ctx, f.org, f.user, d.ID, "", testProfileSID); !errors.Is(err, ErrDeviceOffline) {
		t.Fatalf("an offline device: %v", err)
	}
	f.exec("UPDATE devices SET online = true, status = 'revoked' WHERE id = $1", d.ID)
	if _, err := f.svc.RemoveProfile(ctx, f.org, f.user, d.ID, "", testProfileSID); !errors.Is(err, ErrNotActive) {
		t.Fatalf("a revoked device: %v", err)
	}
	if f.count("SELECT count(*) FROM jobs WHERE type = 'profile_delete'") != 0 || f.count("SELECT count(*) FROM audit_log WHERE action = 'device.profile_remove'") != 0 {
		t.Fatal("a refused request leaves no job and no audit entry")
	}
}

func TestARemovedProfileLeavesTheDevicesListAtOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	d := profileDevice(f)
	id, err := f.svc.RemoveProfile(ctx, f.org, f.user, d.ID, "", testProfileSID)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Wait()
	// A failed removal changes nothing.
	if err := f.svc.ApplyUpdate(ctx, d, &agentv1.JobUpdate{JobId: id.String(), State: agentv1.JobState_JOB_STATE_FAILED, Reason: "profile_in_use"}); err != nil {
		t.Fatal(err)
	}
	if f.count("SELECT count(*) FROM device_users WHERE sid = '"+testProfileSID+"'") != 1 {
		t.Fatal("a refused removal must keep the profile in the list")
	}
	id, err = f.svc.RemoveProfile(ctx, f.org, f.user, d.ID, "", testProfileSID)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Wait()
	if err := f.svc.ApplyUpdate(ctx, d, &agentv1.JobUpdate{JobId: id.String(), State: agentv1.JobState_JOB_STATE_SUCCEEDED, Result: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS}}); err != nil {
		t.Fatal(err)
	}
	if f.count("SELECT count(*) FROM device_users WHERE sid = '"+testProfileSID+"'") != 0 || f.count("SELECT count(*) FROM device_users WHERE device_id = '"+d.ID.String()+"'") != 1 {
		t.Fatal("only the removed profile leaves the list")
	}
}
