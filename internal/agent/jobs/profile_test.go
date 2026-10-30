package jobs

import (
	"strings"
	"testing"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

const profSID = "S-1-5-21-111-222-333-1105"

func (r *rig) profileEnv(id, sid string) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
	env := &agentv1.JobEnvelope{Version: 1, JobId: id, OrgId: "o", DeviceId: "d", Type: agentv1.JobType_JOB_TYPE_PROFILE_DELETE,
		IssuedAt: r.now.Unix(), NotBefore: r.now.Unix(), ExpiresAt: r.now.Add(24 * time.Hour).Unix(), Nonce: make([]byte, 16),
		Body: &agentv1.JobEnvelope_ProfileDelete{ProfileDelete: &agentv1.ProfileDeleteBody{Sid: sid, Username: `CONTOSO\old.user`}}}
	return r.sign(env), env
}

// profileRig has one idle profile on the computer.
func profileRig(t *testing.T) *rig {
	r := newRig(t)
	r.p.profiles = map[string]ProfileInfo{profSID: {Exists: true, Path: `C:\Users\old.user`}}
	r.p.names = map[string][2]string{profSID: {"CONTOSO", "old.user"}}
	return r
}

func runProfile(r *rig, sid string) {
	se, env := r.profileEnv("p1", sid)
	r.e.Accept(se, env)
	r.tick()
}

func TestAnIdleProfileIsRemoved(t *testing.T) {
	r := profileRig(t)
	runProfile(r, profSID)
	res := r.rec.last("p1").Result
	if r.state("p1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.profGone) != 1 || r.p.profGone[0] != profSID ||
		!strings.Contains(res.Message, `CONTOSO\old.user`) || !strings.Contains(res.Message, "account itself was not deleted") {
		t.Fatalf("%v gone=%v %+v", r.state("p1"), r.p.profGone, res)
	}
}

func TestAProfileInUseIsNeverRemoved(t *testing.T) {
	// Signed in, or with a disconnected session.
	r := profileRig(t)
	r.p.sessions[profSID] = true
	runProfile(r, profSID)
	if r.state("p1") != agentv1.JobState_JOB_STATE_FAILED || r.rec.last("p1").Reason != "profile_in_use" || len(r.p.profGone) != 0 ||
		!strings.Contains(r.rec.last("p1").Result.Message, "signed in") {
		t.Fatalf("%v %q %v", r.state("p1"), r.rec.last("p1").Reason, r.p.profGone)
	}
	// A loaded registry hive without a session (a service or a task running as that user).
	r = profileRig(t)
	r.p.profiles[profSID] = ProfileInfo{Exists: true, Path: `C:\Users\old.user`, Loaded: true}
	runProfile(r, profSID)
	if r.state("p1") != agentv1.JobState_JOB_STATE_FAILED || r.rec.last("p1").Reason != "profile_in_use" || len(r.p.profGone) != 0 {
		t.Fatalf("%v %q", r.state("p1"), r.rec.last("p1").Reason)
	}
	// Windows itself refuses at the last moment.
	r = profileRig(t)
	r.p.profErr = ErrProfileInUse
	runProfile(r, profSID)
	if r.state("p1") != agentv1.JobState_JOB_STATE_FAILED || r.rec.last("p1").Reason != "profile_in_use" {
		t.Fatalf("%v %q", r.state("p1"), r.rec.last("p1").Reason)
	}
}

func TestTheAutomaticSignInAccountIsProtected(t *testing.T) {
	r := profileRig(t)
	r.p.autoLogon = [2]string{"CONTOSO", "old.user"}
	runProfile(r, profSID)
	if r.state("p1") != agentv1.JobState_JOB_STATE_FAILED || r.rec.last("p1").Reason != "profile_protected" || len(r.p.profGone) != 0 {
		t.Fatalf("%v %q %v", r.state("p1"), r.rec.last("p1").Reason, r.p.profGone)
	}
	// Another account with the same name in another domain is not the one.
	r = profileRig(t)
	r.p.autoLogon = [2]string{"OTHER", "old.user"}
	runProfile(r, profSID)
	if r.state("p1") != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("%v %q", r.state("p1"), r.rec.last("p1").Reason)
	}
}

func TestAProfileThatIsAlreadyGoneIsNotAnError(t *testing.T) {
	r := profileRig(t)
	delete(r.p.profiles, profSID)
	runProfile(r, profSID)
	if r.state("p1") != agentv1.JobState_JOB_STATE_SUCCEEDED || !r.rec.last("p1").Result.AlreadySatisfied || len(r.p.profGone) != 0 {
		t.Fatalf("%v %+v", r.state("p1"), r.rec.last("p1").Result)
	}
}

func TestOnlyAPersonsAccountCanBeNamed(t *testing.T) {
	for _, sid := range []string{"", "S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-32-544", "S-1-5-21-1-2-3", "S-1-5-21-1-2-3-4; rm", `..\x`, "S-1-5-80-1-2-3-4-5"} {
		r := profileRig(t)
		runProfile(r, sid)
		if len(r.p.profGone) != 0 {
			t.Errorf("%q was acted on", sid)
		}
		if st := load(r.e.Store, "p1"); st != nil && st.state() == agentv1.JobState_JOB_STATE_SUCCEEDED {
			t.Errorf("%q succeeded", sid)
		}
	}
	for _, ok := range []string{profSID, "S-1-12-1-111-222-333-444"} {
		if err := ValidateProfileDelete(&agentv1.ProfileDeleteBody{Sid: ok}); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
}

func TestAProfileRemovalFailureIsReportedWithItsReason(t *testing.T) {
	r := profileRig(t)
	r.p.profErr = errString("access denied")
	runProfile(r, profSID)
	if r.state("p1") != agentv1.JobState_JOB_STATE_FAILED || !strings.Contains(r.rec.last("p1").Result.Message, "access denied") {
		t.Fatalf("%v %+v", r.state("p1"), r.rec.last("p1").Result)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
