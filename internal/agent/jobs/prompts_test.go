package jobs

import (
	"context"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// promptRig is a rig whose clock moves when the engine sleeps, with Acme Tool "open" in a user session.
func promptRig(t *testing.T, pr *agentv1.InstallPrompts) *rig {
	r := newRig(t)
	r.e.Sleep = func(_ context.Context, d time.Duration) { r.now = r.now.Add(d) }
	r.p.procs = []Proc{{PID: 4242, Name: "Acme.exe", Session: 1}}
	r.installerRegisters("2.0", 0)
	se, env := r.installEnv("j1", func(_ *agentv1.JobEnvelope, b *agentv1.InstallBody) { b.Prompts = pr })
	r.e.Accept(se, env)
	return r
}

func prompts(a agentv1.InUseAction) *agentv1.InstallPrompts {
	return &agentv1.InstallPrompts{InUse: a, Processes: []string{"acme.exe"}, AskTimeoutS: 60, DeferMinutes: 30}
}

func TestOpenProgramsAreIgnoredByDefault(t *testing.T) {
	for _, pr := range []*agentv1.InstallPrompts{nil, {}, prompts(agentv1.InUseAction_IN_USE_ACTION_IGNORE)} {
		r := promptRig(t, pr)
		r.tick()
		if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.asks) != 0 || len(r.p.closed) != 0 {
			t.Fatalf("%v asks=%d closed=%d", r.state("j1"), len(r.p.asks), len(r.p.closed))
		}
	}
}

func TestSkipWaitsWithoutAskingAndDoesNotDownload(t *testing.T) {
	r := promptRig(t, prompts(agentv1.InUseAction_IN_USE_ACTION_SKIP))
	r.tick()
	u := r.rec.last("j1")
	if u.State != agentv1.JobState_JOB_STATE_WAITING || !strings.HasPrefix(u.Reason, "waiting_app_closed: Acme.exe") {
		t.Fatalf("%v %q", u.State, u.Reason)
	}
	if len(r.p.asks) != 0 || len(r.p.runs) != 0 || r.f.n != 0 {
		t.Fatalf("asks=%d runs=%d downloads=%d", len(r.p.asks), len(r.p.runs), r.f.n)
	}
	if rec := load(r.e.Store, "j1"); rec.Tries != 0 || rec.NextRun != r.now.Add(30*time.Minute).Unix() {
		t.Fatalf("a wait must not use a retry: tries=%d next=%d", rec.Tries, rec.NextRun)
	}
	// Still waiting before the time is up, even if the program closed.
	r.p.procs = nil
	r.now = r.now.Add(10 * time.Minute)
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_WAITING {
		t.Fatalf("ran too early: %v", r.state("j1"))
	}
	r.now = r.now.Add(21 * time.Minute)
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.runs) != 1 {
		t.Fatalf("%v runs=%d", r.state("j1"), len(r.p.runs))
	}
}

func TestWaitingForClosedProgramsEndsWhenTheJobExpires(t *testing.T) {
	r := promptRig(t, prompts(agentv1.InUseAction_IN_USE_ACTION_SKIP))
	for i := 0; i < 60; i++ { // 30 hours of 30-minute waits
		r.tick()
		r.now = r.now.Add(31 * time.Minute)
	}
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_EXPIRED || len(r.p.runs) != 0 {
		t.Fatalf("%v runs=%d", r.state("j1"), len(r.p.runs))
	}
}

func TestAskYesClosesTheProgramThenInstalls(t *testing.T) {
	r := promptRig(t, prompts(agentv1.InUseAction_IN_USE_ACTION_ASK))
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.runs) != 1 {
		t.Fatalf("%v runs=%d", r.state("j1"), len(r.p.runs))
	}
	if len(r.p.asks) != 1 || !r.p.asks[0].yesNo || r.p.asks[0].session != 1 || r.p.asks[0].timeout != time.Minute ||
		!strings.Contains(r.p.asks[0].message, "Acme Tool") || !strings.Contains(r.p.asks[0].message, "Acme.exe") {
		t.Fatalf("asks: %+v", r.p.asks)
	}
	if len(r.p.closed) != 1 || r.p.closed[0][0].PID != 4242 {
		t.Fatalf("closed: %+v", r.p.closed)
	}
}

func TestAskNoOrNoAnswerPostponesAndNeverCloses(t *testing.T) {
	for ans, reason := range map[Answer]string{AnswerNo: "postponed_by_user", AnswerTimeout: "no_answer_from_user"} {
		r := promptRig(t, prompts(agentv1.InUseAction_IN_USE_ACTION_ASK))
		r.p.answers = []Answer{ans}
		r.tick()
		u := r.rec.last("j1")
		if u.State != agentv1.JobState_JOB_STATE_WAITING || !strings.HasPrefix(u.Reason, reason) {
			t.Fatalf("%v: %v %q", ans, u.State, u.Reason)
		}
		if len(r.p.closed) != 0 || len(r.p.runs) != 0 || r.f.n != 0 {
			t.Fatalf("closed=%d runs=%d downloads=%d", len(r.p.closed), len(r.p.runs), r.f.n)
		}
	}
}

func TestAskIsNotRepeatedAfterYesWhenTheProgramReopens(t *testing.T) {
	r := promptRig(t, prompts(agentv1.InUseAction_IN_USE_ACTION_ASK))
	// The program is opened again while the installer downloads: it is closed without a second question.
	r.f.onOpen = func() { r.p.procs = []Proc{{PID: 77, Name: "acme.exe", Session: 1}} }
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.asks) != 1 || len(r.p.closed) != 1 || r.p.closed[0][0].PID != 77 {
		t.Fatalf("%v asks=%d closed=%+v", r.state("j1"), len(r.p.asks), r.p.closed)
	}
}

func TestCloseWarnsWaitsThenCloses(t *testing.T) {
	r := promptRig(t, prompts(agentv1.InUseAction_IN_USE_ACTION_CLOSE))
	start := r.now
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.runs) != 1 {
		t.Fatalf("%v runs=%d", r.state("j1"), len(r.p.runs))
	}
	if len(r.p.asks) != 1 || r.p.asks[0].yesNo {
		t.Fatalf("a warning, not a question, expected: %+v", r.p.asks)
	}
	if r.now.Sub(start) < time.Minute || len(r.p.closed) != 1 {
		t.Fatalf("the user must get the promised minute (%s) before programs are closed (%d)", r.now.Sub(start), len(r.p.closed))
	}
}

func TestCloseSkipsTheWaitWhenThePersonClosesTheProgram(t *testing.T) {
	r := promptRig(t, prompts(agentv1.InUseAction_IN_USE_ACTION_CLOSE))
	r.p.onAsk = func() { r.p.procs = nil } // closed right after the warning
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.closed) != 0 {
		t.Fatalf("%v closed=%d", r.state("j1"), len(r.p.closed))
	}
}

func TestProgramThatWillNotCloseDefersTheJob(t *testing.T) {
	r := promptRig(t, prompts(agentv1.InUseAction_IN_USE_ACTION_CLOSE))
	r.p.noClose = true
	r.tick()
	u := r.rec.last("j1")
	if u.State != agentv1.JobState_JOB_STATE_WAITING || !strings.HasPrefix(u.Reason, "app_would_not_close") || len(r.p.runs) != 0 {
		t.Fatalf("%v %q runs=%d", u.State, u.Reason, len(r.p.runs))
	}
}

func TestServiceSessionAndUnknownStateAreLeftAlone(t *testing.T) {
	r := promptRig(t, prompts(agentv1.InUseAction_IN_USE_ACTION_CLOSE))
	r.p.procs = []Proc{{PID: 9, Name: "acme.exe", Session: 0}}
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.asks) != 0 || len(r.p.closed) != 0 {
		t.Fatalf("session 0 must not be touched: %v asks=%d closed=%d", r.state("j1"), len(r.p.asks), len(r.p.closed))
	}
	r = promptRig(t, prompts(agentv1.InUseAction_IN_USE_ACTION_SKIP))
	r.p.procsErr = ErrUnsupported
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("a platform that cannot tell must install as before: %v", r.state("j1"))
	}
}

// ---- restart ----

func restartRig(t *testing.T, pr *agentv1.InstallPrompts) *rig {
	r := newRig(t)
	r.p.runFn = func(RunSpec, string) (RunResult, error) {
		r.p.machine.add(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AcmeTool`).vals["DisplayVersion"] = "2.0"
		return RunResult{ExitCode: 3010}, nil
	}
	se, env := r.installEnv("j1", func(_ *agentv1.JobEnvelope, b *agentv1.InstallBody) { b.Prompts = pr })
	r.e.Accept(se, env)
	return r
}

func TestRestartIsOnlyReportedByDefault(t *testing.T) {
	for _, pr := range []*agentv1.InstallPrompts{nil, {Restart: agentv1.RestartPrompt_RESTART_PROMPT_NONE}} {
		r := restartRig(t, pr)
		r.tick()
		if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED_REBOOT || len(r.p.reboots) != 0 || len(r.p.asks) != 0 {
			t.Fatalf("%v reboots=%d asks=%d", r.state("j1"), len(r.p.reboots), len(r.p.asks))
		}
	}
}

func TestRestartCountdownStartsAfterTheInstall(t *testing.T) {
	r := restartRig(t, &agentv1.InstallPrompts{Restart: agentv1.RestartPrompt_RESTART_PROMPT_COUNTDOWN, RestartNotifyMinutes: 7})
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED_REBOOT {
		t.Fatal(r.state("j1"))
	}
	if len(r.p.reboots) != 1 || r.p.reboots[0].delay != 7*time.Minute || !strings.Contains(r.p.reboots[0].message, "Acme Tool") {
		t.Fatalf("reboots: %+v", r.p.reboots)
	}
	if m := r.rec.last("j1").Result.Message; !strings.Contains(m, "restarting in 7 minute") {
		t.Fatalf("message %q", m)
	}
}

func TestRestartAsk(t *testing.T) {
	r := restartRig(t, &agentv1.InstallPrompts{Restart: agentv1.RestartPrompt_RESTART_PROMPT_ASK, AskTimeoutS: 90})
	r.tick()
	if len(r.p.asks) != 1 || !r.p.asks[0].yesNo || len(r.p.reboots) != 1 || r.p.reboots[0].delay != 5*time.Minute {
		t.Fatalf("asks=%+v reboots=%+v", r.p.asks, r.p.reboots)
	}

	r = restartRig(t, &agentv1.InstallPrompts{Restart: agentv1.RestartPrompt_RESTART_PROMPT_ASK})
	r.p.answers = []Answer{AnswerNo}
	r.tick()
	if len(r.p.asks) != 1 || len(r.p.reboots) != 0 || r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED_REBOOT {
		t.Fatalf("a No must leave the restart alone: asks=%d reboots=%d %v", len(r.p.asks), len(r.p.reboots), r.state("j1"))
	}

	r = restartRig(t, &agentv1.InstallPrompts{Restart: agentv1.RestartPrompt_RESTART_PROMPT_ASK})
	r.p.noSession = true
	r.tick()
	if len(r.p.asks) != 0 || len(r.p.reboots) != 0 {
		t.Fatalf("nobody signed in: asks=%d reboots=%d", len(r.p.asks), len(r.p.reboots))
	}
}

func TestNoRestartPromptWhenTheInstallerDoesNotNeedOne(t *testing.T) {
	r := promptRig(t, &agentv1.InstallPrompts{Restart: agentv1.RestartPrompt_RESTART_PROMPT_COUNTDOWN})
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.reboots) != 0 || len(r.p.asks) != 0 {
		t.Fatalf("%v reboots=%d asks=%d", r.state("j1"), len(r.p.reboots), len(r.p.asks))
	}
}

// ---- validation ----

func TestValidatePrompts(t *testing.T) {
	ok := func(p *agentv1.InstallPrompts) {
		t.Helper()
		if err := validatePrompts(p); err != nil {
			t.Fatalf("%+v: %v", p, err)
		}
	}
	bad := func(why string, p *agentv1.InstallPrompts) {
		t.Helper()
		if err := validatePrompts(p); err == nil {
			t.Fatalf("%s accepted: %+v", why, p)
		}
	}
	ok(nil)
	ok(&agentv1.InstallPrompts{})
	ok(prompts(agentv1.InUseAction_IN_USE_ACTION_CLOSE))
	ok(&agentv1.InstallPrompts{Restart: agentv1.RestartPrompt_RESTART_PROMPT_ASK, RestartNotifyMinutes: 1440})
	bad("no programs", &agentv1.InstallPrompts{InUse: agentv1.InUseAction_IN_USE_ACTION_ASK})
	bad("a path", &agentv1.InstallPrompts{InUse: agentv1.InUseAction_IN_USE_ACTION_ASK, Processes: []string{`C:\x\app.exe`}})
	bad("a wildcard", &agentv1.InstallPrompts{InUse: agentv1.InUseAction_IN_USE_ACTION_ASK, Processes: []string{"*.exe"}})
	bad("no extension", &agentv1.InstallPrompts{InUse: agentv1.InUseAction_IN_USE_ACTION_ASK, Processes: []string{"app"}})
	bad("windows itself", &agentv1.InstallPrompts{InUse: agentv1.InUseAction_IN_USE_ACTION_CLOSE, Processes: []string{"LSASS.exe"}})
	bad("the agent", &agentv1.InstallPrompts{InUse: agentv1.InUseAction_IN_USE_ACTION_CLOSE, Processes: []string{"librepatch-agent.exe"}})
	bad("too many", &agentv1.InstallPrompts{Processes: []string{"a.exe", "b.exe", "c.exe", "d.exe", "e.exe", "f.exe", "g.exe", "h.exe", "i.exe", "j.exe", "k.exe"}})
	bad("short question", &agentv1.InstallPrompts{AskTimeoutS: 5})
	bad("long wait", &agentv1.InstallPrompts{DeferMinutes: 5000})
	bad("unknown action", &agentv1.InstallPrompts{InUse: 99})
	bad("unknown restart", &agentv1.InstallPrompts{Restart: 99})
}
