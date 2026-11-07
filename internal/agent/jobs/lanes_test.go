package jobs

import (
	"strings"
	"testing"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/wu"
)

func (r *rig) rebootCount() int {
	r.p.mu.Lock()
	defer r.p.mu.Unlock()
	return len(r.p.reboots)
}

func (r *rig) eventually(what string, f func() bool) {
	r.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			r.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// A restart must not wait for a Windows Update scan that is still running: it only stores a plan and starts the
// system countdown.
func TestRestartIsNotHeldBackByARunningScan(t *testing.T) {
	r := newRig(t)
	r.p.wuc.scanGate, r.p.wuc.scanning = make(chan struct{}), make(chan struct{}, 1)
	r.e.init()
	scan, scanEnv := r.wuEnv("scan", agentv1.JobType_JOB_TYPE_WU_SCAN, nil)
	r.e.Accept(scan, scanEnv)
	done := make(chan struct{})
	go func() { r.e.tickLane(r.ctx, laneScan); close(done) }()
	select {
	case <-r.p.wuc.scanning:
	case <-time.After(5 * time.Second):
		t.Fatal("the scan never started")
	}

	rb, rbEnv := r.wuEnv("restart", agentv1.JobType_JOB_TYPE_REBOOT, nil)
	r.e.Accept(rb, rbEnv)
	r.e.tickLane(r.ctx, laneControl)
	if r.state("restart") != agentv1.JobState_JOB_STATE_SUCCEEDED || r.rebootCount() != 1 {
		t.Fatalf("restart state %v, countdowns started %d; want succeeded and 1 while the scan still runs", r.state("restart"), r.rebootCount())
	}
	if r.state("scan") != agentv1.JobState_JOB_STATE_RUNNING {
		t.Fatalf("scan state %v; it should still be running", r.state("scan"))
	}

	close(r.p.wuc.scanGate)
	<-done
	if r.state("scan") != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("scan state %v", r.state("scan"))
	}
	// The main loop leaves restart requests alone: no second countdown.
	r.e.tickLane(r.ctx, laneMain)
	if r.rebootCount() != 1 {
		t.Fatalf("%d countdowns; want 1", r.rebootCount())
	}
}

// A restart still waits for an installer (or update) that it would interrupt, as before, and starts as soon as that
// job ends.
func TestRestartWaitsForARunningInstaller(t *testing.T) {
	r := newRig(t)
	r.e.init()
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	r.installerRegisters("2.0", 0)
	inner := r.p.runFn
	r.p.runFn = func(s RunSpec, user string) (RunResult, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return inner(s, user)
	}
	r.f.data["https://v.example/i1.exe"] = []byte("MZ installer bytes i1")
	se, env := r.installEnv("i1", nil)
	r.e.Accept(se, env)
	done := make(chan struct{})
	go func() { r.e.tickLane(r.ctx, laneMain); close(done) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the installer never started")
	}

	rb, rbEnv := r.wuEnv("restart", agentv1.JobType_JOB_TYPE_REBOOT, nil)
	r.e.Accept(rb, rbEnv)
	r.e.tickLane(r.ctx, laneControl)
	if r.rebootCount() != 0 || r.state("restart") != agentv1.JobState_JOB_STATE_WAITING {
		t.Fatalf("restart state %v, countdowns %d; want waiting and none while an installer runs", r.state("restart"), r.rebootCount())
	}

	close(release)
	<-done
	r.eventually("the restart to be released", func() bool { return r.e.unsafe.Load() == 0 })
	r.e.tickLane(r.ctx, laneControl)
	if r.state("restart") != agentv1.JobState_JOB_STATE_SUCCEEDED || r.rebootCount() != 1 {
		t.Fatalf("restart state %v, countdowns %d; want succeeded and 1 after the installer ended", r.state("restart"), r.rebootCount())
	}
}

// Clicking Restart twice must restart the computer once. Windows refuses a second countdown while one runs
// (ERROR_SHUTDOWN_IS_SCHEDULED); the agent used to read that as a failure, keep the plan and start another
// countdown right after the computer came back.
func TestSecondRestartRequestDoesNotRestartTheComputerTwice(t *testing.T) {
	r := newRig(t)
	r.e.init()
	r.p.rebootReq = true

	a, aEnv := r.wuEnv("restart-a", agentv1.JobType_JOB_TYPE_REBOOT, nil)
	r.e.Accept(a, aEnv)
	r.tick()
	if r.rebootCount() != 1 || r.e.loadRebootPlan() == nil || r.e.loadRebootPlan().Fired == 0 {
		t.Fatalf("first restart: %d countdowns, plan %+v", r.rebootCount(), r.e.loadRebootPlan())
	}

	// The second click arrives while the first countdown is running.
	r.p.rebootErr = ErrRebootScheduled
	b, bEnv := r.wuEnv("restart-b", agentv1.JobType_JOB_TYPE_REBOOT, nil)
	r.e.Accept(b, bEnv)
	r.tick()
	if r.state("restart-b") != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("second restart request: %v; it should succeed because a restart is on its way", r.state("restart-b"))
	}
	if p := r.e.loadRebootPlan(); p == nil || p.Fired == 0 {
		t.Fatalf("the second request must join the running countdown, plan %+v", p)
	}

	// The computer restarts and comes back: nothing may start another countdown.
	r.p.rebootErr, r.p.rebootReq = nil, false
	r.now = r.now.Add(20 * time.Minute)
	r.tick()
	r.tick()
	if r.rebootCount() != 2 { // the first countdown and the refused second attempt, nothing after the restart
		t.Fatalf("%d countdown calls; want 2 (the second one was refused by Windows)", r.rebootCount())
	}
	if r.e.loadRebootPlan() != nil {
		t.Fatalf("the plan should be gone after the restart: %+v", r.e.loadRebootPlan())
	}
}

// The bug that made a Refresh click wait for an hour: jobs ran one at a time, so a removal whose uninstaller never finished
// held back everything behind it (D152). A refresh, a restart and a script now have lanes of their own.
func TestRefreshAndScriptsRunWhileAnUninstallerHangs(t *testing.T) {
	r := newRig(t)
	r.e.init()
	r.addProgram(code1, map[string]string{"DisplayName": "Acme", "UninstallString": "MsiExec.exe /X" + code1}, map[string]uint32{"WindowsInstaller": 1})
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	r.p.runFn = func(s RunSpec, user string) (RunResult, error) {
		if strings.HasSuffix(s.Exe, "msiexec.exe") { // the uninstaller
			select {
			case started <- struct{}{}:
			default:
			}
			<-release // never finishes on its own
			r.p.machine.add(uninstallKey).remove(code1)
			return RunResult{ExitCode: 0}, nil
		}
		return RunResult{ExitCode: 0, LogTail: "script output"}, nil // the script
	}
	un, unEnv := r.uninstallEnv("un", func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) { b.ItemKey = code1 })
	r.e.Accept(un, unEnv)
	unDone := make(chan struct{})
	go func() { r.e.tickLane(r.ctx, laneMain); close(unDone) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the uninstaller never started")
	}

	refreshed := 0
	r.e.InventoryNow = func() { refreshed++ }
	// Both arrive while the uninstaller is stuck.
	rf, rfEnv := r.wuEnv("refresh", agentv1.JobType_JOB_TYPE_INVENTORY_FULL, nil)
	r.e.Accept(rf, rfEnv)
	sc, scEnv := scriptEnv(r, "script", scriptBody("Write-Output hi"))
	r.e.ScriptsEnabled = true
	r.e.Accept(sc, scEnv)

	r.e.tickLane(r.ctx, laneInventory)
	r.e.tickLane(r.ctx, laneScript)
	if r.state("refresh") != agentv1.JobState_JOB_STATE_SUCCEEDED || refreshed < 1 {
		t.Fatalf("the refresh must not wait for the uninstaller: %v (refreshed %d)", r.state("refresh"), refreshed)
	}
	if r.state("script") != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("the script must not wait for the uninstaller: %v", r.state("script"))
	}
	if r.state("un") != agentv1.JobState_JOB_STATE_RUNNING {
		t.Fatalf("the uninstaller is still running: %v", r.state("un"))
	}

	close(release)
	<-unDone
	if r.state("un") != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("uninstall %v: %+v", r.state("un"), r.rec.last("un"))
	}
}

// Jobs that have to wait for the job in front of them say so, instead of sitting as "accepted" with no explanation.
func TestQueuedJobsSayWhatTheyWaitFor(t *testing.T) {
	r := newRig(t)
	r.e.init()
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	r.installerRegisters("2.0", 0)
	inner := r.p.runFn
	r.p.runFn = func(s RunSpec, user string) (RunResult, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return inner(s, user)
	}
	first, firstEnv := r.installEnv("first", nil)
	r.e.Accept(first, firstEnv)
	second, secondEnv := r.installEnv("second", nil)
	r.e.Accept(second, secondEnv)
	done := make(chan struct{})
	go func() { r.e.tickLane(r.ctx, laneMain); close(done) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the first installer never started")
	}
	if r.state("first") != agentv1.JobState_JOB_STATE_RUNNING {
		t.Fatalf("first: %v", r.state("first"))
	}
	r.eventually("the second job to say it is queued", func() bool { return r.state("second") == agentv1.JobState_JOB_STATE_WAITING })
	if reason := r.rec.last("second").Reason; reason != "waiting_other_job" {
		t.Fatalf("reason %q", reason)
	}
	close(release)
	<-done
	// The second one runs after the first (the installer is fake and registers the same product, so it is already satisfied).
	if r.state("first") != agentv1.JobState_JOB_STATE_SUCCEEDED || r.state("second") != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("first %v second %v", r.state("first"), r.state("second"))
	}
}

// A scan that never gets an answer from its update source ends at the time limit instead of running for hours.
func TestAScanEndsAtTheTimeLimit(t *testing.T) {
	old := scanTimeout
	scanTimeout = 50 * time.Millisecond
	defer func() { scanTimeout = old }()
	r := newRig(t)
	r.p.wuc.scanGate, r.p.wuc.scanning = make(chan struct{}), make(chan struct{}, 1) // never opened
	done := make(chan struct{})
	go func() { r.e.scanAndReport(r.ctx, wu.Options{}); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the scan did not end at the time limit")
	}
}
