package jobs

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

func (r *rig) agentUninstallEnv(id string) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
	env := &agentv1.JobEnvelope{Version: 1, JobId: id, OrgId: "o", DeviceId: "d", Type: agentv1.JobType_JOB_TYPE_AGENT_UNINSTALL,
		IssuedAt: r.now.Unix(), NotBefore: r.now.Unix(), ExpiresAt: r.now.Add(24 * time.Hour).Unix(), Nonce: make([]byte, 16),
		Body: &agentv1.JobEnvelope_AgentUninstall{AgentUninstall: &agentv1.AgentUninstallBody{Reason: "lost laptop", RequestedBy: "7d1e0000-0000-7000-8000-000000000001"}}}
	return r.sign(env), env
}

// The job ends as "succeeded" first, so the server hears it, and the removal starts in a process that waits a few seconds.
func TestTheAgentReportsDoneThenRemovesItselfLater(t *testing.T) {
	r := newRig(t)
	r.p.selfHow = "MSI package"
	se, env := r.agentUninstallEnv("a1")
	r.e.Accept(se, env)
	r.tick()
	res := r.rec.last("a1").Result
	if r.state("a1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.selfUninstall) != 1 || r.p.selfUninstall[0] < 10*time.Second ||
		!strings.Contains(res.Message, "MSI package") {
		t.Fatalf("%v waits=%v %+v", r.state("a1"), r.p.selfUninstall, res)
	}
}

func TestTheAgentSaysSoWhenItCannotStartItsOwnRemoval(t *testing.T) {
	r := newRig(t)
	r.p.selfErr = errors.New("access denied")
	se, env := r.agentUninstallEnv("a1")
	r.e.Accept(se, env)
	r.tick()
	if r.state("a1") != agentv1.JobState_JOB_STATE_FAILED || !strings.Contains(r.rec.last("a1").Result.Message, "access denied") {
		t.Fatalf("%v %+v", r.state("a1"), r.rec.last("a1").Result)
	}
}

// A user-scope job, or a body that is too long, is refused before anything runs.
func TestAnAgentRemovalIsMachineScopeAndBounded(t *testing.T) {
	r := newRig(t)
	_, env := r.agentUninstallEnv("a1")
	env.TargetUserSid = "S-1-5-21-1-2-3-1001"
	se := r.sign(env)
	r.e.Accept(se, env)
	r.tick()
	if len(r.p.selfUninstall) != 0 {
		t.Fatal("a user-scope removal must not run")
	}
	if err := ValidateAgentUninstall(&agentv1.AgentUninstallBody{Reason: strings.Repeat("x", 600)}); err == nil {
		t.Error("a reason that long must be refused")
	}
	if err := ValidateAgentUninstall(nil); err == nil {
		t.Error("a missing body must be refused")
	}
}

// The upgrade code in the agent must be the one in the installer, or the installed MSI would never be found.
func TestTheUpgradeCodeIsTheInstallersOwn(t *testing.T) {
	raw, err := os.ReadFile("../../../installer/windows/Package.wxs")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`UpgradeCode="([0-9A-Fa-f-]{36})"`).FindSubmatch(raw)
	if m == nil || !strings.EqualFold("{"+string(m[1])+"}", AgentUpgradeCode) {
		t.Fatalf("Package.wxs upgrade code %q, agent says %s", m, AgentUpgradeCode)
	}
}
