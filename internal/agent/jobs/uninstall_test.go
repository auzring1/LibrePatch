package jobs

import (
	"errors"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

const (
	uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	code1        = "{11111111-2222-3333-4444-555555555555}"
)

func (r *rig) uninstallEnv(id string, mut func(*agentv1.JobEnvelope, *agentv1.UninstallBody)) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
	body := &agentv1.UninstallBody{PackageId: "Acme.Tool", Name: "Acme Tool", Scope: agentv1.InstallScope_INSTALL_SCOPE_MACHINE,
		ItemSource: "reg64", ItemKey: "AcmeTool", Method: agentv1.UninstallMethod_UNINSTALL_METHOD_AUTO}
	env := &agentv1.JobEnvelope{Version: 1, JobId: id, OrgId: "o", DeviceId: "d", Type: agentv1.JobType_JOB_TYPE_SOFTWARE_UNINSTALL,
		IssuedAt: r.now.Unix(), NotBefore: r.now.Unix(), ExpiresAt: r.now.Add(24 * time.Hour).Unix(), Nonce: make([]byte, 16),
		Body: &agentv1.JobEnvelope_Uninstall{Uninstall: body}}
	if mut != nil {
		mut(env, body)
	}
	return r.sign(env), env
}

func (r *rig) addProgram(key string, vals map[string]string, dw map[string]uint32) {
	k := r.p.machine.add(uninstallKey + `\` + key)
	for n, v := range vals {
		k.vals[n] = v
	}
	for n, v := range dw {
		k.dw[n] = v
	}
}

// removesKeyOnRun makes the fake uninstaller delete the program's Uninstall key.
func (r *rig) removesKeyOnRun(key string, exit int) {
	r.p.runFn = func(RunSpec, string) (RunResult, error) {
		if exit == 0 {
			r.p.machine.add(uninstallKey).remove(key)
		}
		return RunResult{ExitCode: exit}, nil
	}
}

func TestUninstallByProductCode(t *testing.T) {
	r := newRig(t)
	r.addProgram(code1, map[string]string{"DisplayName": "Acme", "UninstallString": "MsiExec.exe /X" + code1}, map[string]uint32{"WindowsInstaller": 1})
	r.removesKeyOnRun(code1, 0)
	se, env := r.uninstallEnv("u1", func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) { b.ItemKey = code1 })
	r.e.Accept(se, env)
	r.tick()
	if r.state("u1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.runs) != 1 {
		t.Fatalf("%v %+v", r.state("u1"), r.rec.last("u1"))
	}
	run := r.p.runs[0]
	if !strings.HasSuffix(run.Exe, "msiexec.exe") || run.Args[0] != "/x" || run.Args[1] != code1 || !contains(run.Args, "/qn") {
		t.Fatalf("command: %v %v", run.Exe, run.Args)
	}
}

func TestUninstallUsesQuietStringThenInnoSwitches(t *testing.T) {
	r := newRig(t)
	r.addProgram("AcmeTool", map[string]string{"QuietUninstallString": `"C:\Program Files\Acme\remove.exe" --quiet`}, nil)
	r.removesKeyOnRun("AcmeTool", 0)
	se, env := r.uninstallEnv("u1", nil)
	r.e.Accept(se, env)
	r.tick()
	if r.state("u1") != agentv1.JobState_JOB_STATE_SUCCEEDED || r.p.runs[0].Exe != `C:\Program Files\Acme\remove.exe` || r.p.runs[0].Args[0] != "--quiet" {
		t.Fatalf("%v %+v", r.state("u1"), r.p.runs)
	}
	r2 := newRig(t)
	r2.addProgram("Inno", map[string]string{"UninstallString": `"C:\Program Files\Inno\unins000.exe"`}, nil)
	r2.removesKeyOnRun("Inno", 0)
	se, env = r2.uninstallEnv("u2", func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) { b.ItemKey = "Inno" })
	r2.e.Accept(se, env)
	r2.tick()
	if r2.state("u2") != agentv1.JobState_JOB_STATE_SUCCEEDED || !contains(r2.p.runs[0].Args, "/VERYSILENT") {
		t.Fatalf("%v %+v", r2.state("u2"), r2.p.runs)
	}
}

func TestUninstallWithoutSilentCommandFailsClosed(t *testing.T) {
	r := newRig(t)
	r.addProgram("AcmeTool", map[string]string{"UninstallString": `"C:\Program Files\Acme\uninst.exe"`}, nil)
	se, env := r.uninstallEnv("u1", nil)
	r.e.Accept(se, env)
	r.tick()
	if r.state("u1") != agentv1.JobState_JOB_STATE_FAILED || len(r.p.runs) != 0 || !strings.Contains(r.rec.last("u1").Result.Message, "silent") {
		t.Fatalf("%v %+v", r.state("u1"), r.rec.last("u1").Result)
	}
	// An administrator can supply validated silent switches.
	se, env = r.uninstallEnv("u2", func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) { b.ExtraArgs = []string{"/S"} })
	r.removesKeyOnRun("AcmeTool", 0)
	r.e.Accept(se, env)
	r.tick()
	if r.state("u2") != agentv1.JobState_JOB_STATE_SUCCEEDED || r.p.runs[0].Args[0] != "/S" {
		t.Fatalf("%v", r.state("u2"))
	}
}

func TestUntrustedUninstallerIsNotRunAsService(t *testing.T) {
	r := newRig(t)
	r.addProgram("AcmeTool", map[string]string{"QuietUninstallString": `C:\Users\Public\evil.exe /S`}, nil)
	r.p.trusted = func(p string) error { return errors.New("located in a user-writable folder") }
	se, env := r.uninstallEnv("u1", nil)
	r.e.Accept(se, env)
	r.tick()
	if r.state("u1") != agentv1.JobState_JOB_STATE_FAILED || len(r.p.runs) != 0 {
		t.Fatalf("%v runs=%d", r.state("u1"), len(r.p.runs))
	}
}

func TestUninstallRelativePathRefused(t *testing.T) {
	r := newRig(t)
	r.addProgram("AcmeTool", map[string]string{"QuietUninstallString": `uninstall.exe /S`}, nil)
	se, env := r.uninstallEnv("u1", nil)
	r.e.Accept(se, env)
	r.tick()
	if r.state("u1") != agentv1.JobState_JOB_STATE_FAILED || len(r.p.runs) != 0 {
		t.Fatalf("%v", r.state("u1"))
	}
}

func TestUninstallAlreadyGoneAndStillListed(t *testing.T) {
	r := newRig(t)
	se, env := r.uninstallEnv("u1", nil)
	r.e.Accept(se, env)
	r.tick()
	if r.state("u1") != agentv1.JobState_JOB_STATE_SUCCEEDED || !r.rec.last("u1").Result.AlreadySatisfied {
		t.Fatalf("absent program: %v", r.state("u1"))
	}
	r.addProgram("AcmeTool", map[string]string{"QuietUninstallString": `"C:\Program Files\A\u.exe" /S`}, nil)
	recheckDelay, recheckTries = time.Millisecond, 2
	t.Cleanup(func() { recheckDelay, recheckTries = 1500*time.Millisecond, 10 })
	r.p.runFn = func(RunSpec, string) (RunResult, error) { return RunResult{ExitCode: 0}, nil } // claims success, removes nothing
	se, env = r.uninstallEnv("u2", nil)
	r.e.Accept(se, env)
	r.tick()
	if r.state("u2") != agentv1.JobState_JOB_STATE_FAILED || r.rec.last("u2").Reason != "failed_detection" {
		t.Fatalf("%v %q", r.state("u2"), r.rec.last("u2").Reason)
	}
}

func TestUserScopeUninstallRunsInUserContext(t *testing.T) {
	r := newRig(t)
	const sid = "S-1-5-21-1-2-3-1001"
	k := r.p.userRoot(sid).add(`Software\Microsoft\Windows\CurrentVersion\Uninstall\Tool`)
	k.vals["QuietUninstallString"] = `"C:\Users\a\AppData\Local\Tool\unins000.exe" /VERYSILENT`
	var ranAs string
	r.p.runFn = func(RunSpec, string) (RunResult, error) {
		ranAs = sid
		r.p.userRoot(sid).add(`Software\Microsoft\Windows\CurrentVersion\Uninstall`).remove("Tool")
		return RunResult{}, nil
	}
	se, env := r.uninstallEnv("u1", func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) {
		e.TargetUserSid, b.Scope, b.ItemSource, b.ItemKey = sid, agentv1.InstallScope_INSTALL_SCOPE_USER, "hku", "Tool"
	})
	r.e.Accept(se, env)
	r.tick()
	if r.state("u1") != agentv1.JobState_JOB_STATE_WAITING || len(r.p.runs) != 0 {
		t.Fatalf("must wait for the user: %v", r.state("u1"))
	}
	r.p.sessions[sid] = true
	r.tick()
	if r.state("u1") != agentv1.JobState_JOB_STATE_SUCCEEDED || ranAs != sid {
		t.Fatalf("%v ranAs=%q", r.state("u1"), ranAs)
	}
}

func TestUninstallBodyValidation(t *testing.T) {
	r := newRig(t)
	bad := map[string]func(*agentv1.JobEnvelope, *agentv1.UninstallBody){
		"unknown source":  func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) { b.ItemSource = "weird" },
		"hku for machine": func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) { b.ItemSource = "hku" },
		"bad guid":        func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) { b.ProductCode = "{nope}" },
		"msi non guid":    func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) { b.ItemSource, b.ItemKey = "msi", "AcmeTool" },
		"evil extra":      func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) { b.ExtraArgs = []string{"/S|calc"} },
		"empty key":       func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) { b.ItemKey = "" },
	}
	i := 0
	for name, mut := range bad {
		i++
		id := "x" + string(rune('a'+i))
		se, env := r.uninstallEnv(id, mut)
		r.e.Accept(se, env)
		if r.state(id) != agentv1.JobState_JOB_STATE_REJECTED {
			t.Errorf("%s: %v", name, r.state(id))
		}
	}
}

func TestCleanupUninstallOnlyRemovesOlderCopies(t *testing.T) {
	cleanup := func(b *agentv1.UninstallBody) { b.RemoveOlderThan = "26.04" }
	run := func(id string, mut func(*agentv1.JobEnvelope, *agentv1.UninstallBody)) *rig {
		r := newRig(t)
		r.removesKeyOnRun("AcmeTool", 0)
		return r
	}

	// An older copy is removed.
	r := run("c1", nil)
	r.addProgram("AcmeTool", map[string]string{"QuietUninstallString": `"C:\Program Files\Acme\u.exe" /S`, "DisplayVersion": "25.01"}, nil)
	se, env := r.uninstallEnv("c1", func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) { cleanup(b) })
	r.e.Accept(se, env)
	r.tick()
	if r.state("c1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.runs) != 1 {
		t.Fatalf("older copy: %v runs=%d", r.state("c1"), len(r.p.runs))
	}

	// A copy at or above the target (the new installer replaced it, or inventory was stale) is left alone.
	for _, v := range []string{"26.04", "26.10", ""} {
		r := run("c2", nil)
		r.addProgram("AcmeTool", map[string]string{"QuietUninstallString": `"C:\Program Files\Acme\u.exe" /S`, "DisplayVersion": v}, nil)
		se, env := r.uninstallEnv("c2", func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) { cleanup(b) })
		r.e.Accept(se, env)
		r.tick()
		if r.state("c2") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.runs) != 0 {
			t.Fatalf("version %q must be left alone: %v runs=%d", v, r.state("c2"), len(r.p.runs))
		}
	}

	// A copy that is already gone is success, even for an MSI row.
	r = run("c3", nil)
	se, env = r.uninstallEnv("c3", func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) {
		cleanup(b)
		b.ItemSource, b.ItemKey = "msi", code1
	})
	r.e.Accept(se, env)
	r.tick()
	if r.state("c3") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.runs) != 0 {
		t.Fatalf("gone: %v runs=%d", r.state("c3"), len(r.p.runs))
	}

	// A malformed target is rejected before anything runs.
	r = run("c4", nil)
	se, env = r.uninstallEnv("c4", func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) { b.RemoveOlderThan = "not a version" })
	r.e.Accept(se, env)
	r.tick()
	if r.state("c4") != agentv1.JobState_JOB_STATE_REJECTED {
		t.Fatalf("bad remove_older_than: %v", r.state("c4"))
	}
}

// userUninstall runs a per-user removal for a program whose Uninstall key holds vals, and returns the job's final state.
func userUninstall(t *testing.T, vals map[string]string, extra []string) (*rig, string) {
	t.Helper()
	r := newRig(t)
	const sid = "S-1-5-21-1-2-3-1001"
	r.p.sessions[sid] = true
	root := r.p.userRoot(sid)
	k := root.add(`Software\Microsoft\Windows\CurrentVersion\Uninstall\Tool`)
	for n, v := range vals {
		k.vals[n] = v
	}
	r.p.runFn = func(RunSpec, string) (RunResult, error) {
		root.add(`Software\Microsoft\Windows\CurrentVersion\Uninstall`).remove("Tool")
		return RunResult{}, nil
	}
	se, env := r.uninstallEnv("u1", func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) {
		e.TargetUserSid, b.Scope, b.ItemSource, b.ItemKey, b.ExtraArgs = sid, agentv1.InstallScope_INSTALL_SCOPE_USER, "hku", "Tool", extra
	})
	r.e.Accept(se, env)
	r.tick()
	return r, r.rec.last("u1").Reason
}

func TestPerUserUninstallExpandsTheUsersOwnFolders(t *testing.T) {
	// The user's hive stores %LOCALAPPDATA% unexpanded; the service must not reject that as "not an absolute path".
	r, _ := userUninstall(t, map[string]string{"QuietUninstallString": `"%LOCALAPPDATA%\Tool\unins000.exe" /VERYSILENT`}, nil)
	if r.state("u1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.runs) != 1 {
		t.Fatalf("%v %+v", r.state("u1"), r.rec.last("u1").Result)
	}
	if strings.Contains(r.p.runs[0].Exe, "%") || !strings.HasSuffix(r.p.runs[0].Exe, `\Tool\unins000.exe`) {
		t.Fatalf("not expanded: %q", r.p.runs[0].Exe)
	}
}

func TestPerUserUninstallKnowsSquirrelAndNSIS(t *testing.T) {
	r, _ := userUninstall(t, map[string]string{"UninstallString": `"C:\Users\a\AppData\Local\Tool\Update.exe" --uninstall`}, nil)
	if r.state("u1") != agentv1.JobState_JOB_STATE_SUCCEEDED || !contains(r.p.runs[0].Args, "-s") {
		t.Fatalf("squirrel: %v %+v", r.state("u1"), r.p.runs)
	}
	old := readHead
	defer func() { readHead = old }()
	readHead = func(string, int) ([]byte, error) { return []byte("MZ....Nullsoft Install System v3...."), nil }
	r, _ = userUninstall(t, map[string]string{"UninstallString": `"C:\Users\a\AppData\Local\Tool\Uninstall.exe"`}, nil)
	if r.state("u1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.runs[0].Args) != 2 || r.p.runs[0].Args[0] != "/S" ||
		r.p.runs[0].Args[1] != `_?=C:\Users\a\AppData\Local\Tool` {
		t.Fatalf("nsis: %v %+v", r.state("u1"), r.p.runs)
	}
	// An uninstaller that is not NSIS is never guessed at: /S could open a window nobody can see.
	readHead = func(string, int) ([]byte, error) { return []byte("MZ....something else"), nil }
	r, reason := userUninstall(t, map[string]string{"UninstallString": `"C:\Users\a\AppData\Local\Tool\Uninstall.exe"`}, nil)
	if r.state("u1") != agentv1.JobState_JOB_STATE_FAILED || reason != "no_silent_uninstall" || len(r.p.runs) != 0 {
		t.Fatalf("unknown: %v %q", r.state("u1"), reason)
	}
}

func TestProgramsWithoutASilentUninstallerSayWhy(t *testing.T) {
	r, reason := userUninstall(t, map[string]string{"UninstallString": `"C:\Program Files (x86)\Citrix\ICA Client\SelfServicePlugin\SelfService.exe" -uninstall Meditech`}, nil)
	msg := r.rec.last("u1").Result.Message
	if reason != "no_silent_uninstall" || !strings.Contains(msg, "Citrix") || len(r.p.runs) != 0 {
		t.Fatalf("%q %q", reason, msg)
	}
	r, reason = userUninstall(t, map[string]string{"UninstallString": `rundll32.exe dfshim.dll,ShArpMaintain app.application`}, nil)
	if reason != "no_silent_uninstall" || !strings.Contains(r.rec.last("u1").Result.Message, "ClickOnce") {
		t.Fatalf("%q %q", reason, r.rec.last("u1").Result.Message)
	}
}

func TestUninstallWaitsForAnUninstallerThatFinishesInTheBackground(t *testing.T) {
	r := newRig(t)
	r.addProgram("AcmeTool", map[string]string{"QuietUninstallString": `"C:\Program Files\A\u.exe" /S`}, nil)
	recheckDelay = time.Millisecond
	t.Cleanup(func() { recheckDelay = 1500 * time.Millisecond })
	calls := 0
	r.p.runFn = func(RunSpec, string) (RunResult, error) { return RunResult{ExitCode: 0}, nil }
	r.p.onRoots = func() {
		calls++
		if calls == 4 { // the background copy of the uninstaller finishes a moment later
			r.p.machine.add(uninstallKey).remove("AcmeTool")
		}
	}
	se, env := r.uninstallEnv("u1", nil)
	r.e.Accept(se, env)
	r.tick()
	if r.state("u1") != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("%v %q", r.state("u1"), r.rec.last("u1").Reason)
	}
}

const staleSID = "S-1-5-21-1-2-3-1001"

// staleProgram sets up a per-user program whose uninstaller file is gone (or not), runs the removal and returns the rig.
func staleProgram(t *testing.T, cmd string, gone bool, signedIn bool, mut func(*agentv1.UninstallBody)) *rig {
	t.Helper()
	recheckDelay = time.Millisecond
	t.Cleanup(func() { recheckDelay = 1500 * time.Millisecond })
	r := newRig(t)
	if signedIn {
		r.p.sessions[staleSID] = true
	}
	k := r.p.userRoot(staleSID).add(`Software\Microsoft\Windows\CurrentVersion\Uninstall\Tool`)
	k.vals["UninstallString"] = cmd
	r.p.gone = map[string]bool{}
	if gone {
		r.p.gone[`C:\Users\a\AppData\Local\Tool\uninst.exe`] = true
	}
	se, env := r.uninstallEnv("u1", func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) {
		e.TargetUserSid, b.Scope, b.ItemSource, b.ItemKey = staleSID, agentv1.InstallScope_INSTALL_SCOPE_USER, "hku", "Tool"
		if mut != nil {
			mut(b)
		}
	})
	r.e.Accept(se, env)
	r.tick()
	return r
}

func TestAStaleListEntryWhoseUninstallerIsGoneIsRemoved(t *testing.T) {
	r := staleProgram(t, `"C:\Users\a\AppData\Local\Tool\uninst.exe"`, true, true, nil)
	res := r.rec.last("u1").Result
	if r.state("u1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.runs) != 0 || len(r.p.deleted) != 1 || r.p.deleted[0] != "Tool" ||
		!res.DetectionPassed || !strings.Contains(res.Message, "no longer exists") {
		t.Fatalf("%v runs=%d deleted=%v %+v", r.state("u1"), len(r.p.runs), r.p.deleted, res)
	}
	// The variables in the user's own command are expanded first, so the file is looked for in the right place.
	r = staleProgram(t, `"%LOCALAPPDATA%\Tool\uninst.exe"`, true, true, nil)
	if r.state("u1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.deleted) != 1 {
		t.Fatalf("%v %v", r.state("u1"), r.p.deleted)
	}
}

func TestAStaleEntryOfSomeoneNotSignedInWaitsForThem(t *testing.T) {
	r := staleProgram(t, `"C:\Users\a\AppData\Local\Tool\uninst.exe"`, true, false, nil)
	if r.state("u1") != agentv1.JobState_JOB_STATE_WAITING || len(r.p.deleted) != 0 {
		t.Fatalf("their registry can only be changed while they are signed in: %v %v", r.state("u1"), r.p.deleted)
	}
}

func TestOnlyACertainlyMissingOrdinaryUninstallerCountsAsStale(t *testing.T) {
	// The file is there (or might be: an unmounted drive or a share is "not certain"): the normal removal is tried.
	r := staleProgram(t, `"C:\Users\a\AppData\Local\Tool\unins000.exe"`, false, true, nil)
	if len(r.p.deleted) != 0 || len(r.p.runs) != 1 {
		t.Fatalf("an uninstaller that may exist is run, not given up on: deleted=%v runs=%d", r.p.deleted, len(r.p.runs))
	}
	// A path that could not be expanded is never judged.
	r = staleProgram(t, `"%TEMP%\Tool\uninst.exe" /S`, true, true, nil)
	if len(r.p.deleted) != 0 {
		t.Fatalf("%v", r.p.deleted)
	}
	// An MSI product is removed by msiexec, whatever the command line says.
	r = staleProgram(t, `MsiExec.exe /X`+code1, true, true, func(b *agentv1.UninstallBody) { b.ProductCode = code1 })
	if len(r.p.deleted) != 0 {
		t.Fatalf("%v", r.p.deleted)
	}
	// A cleanup of an old copy during an update never deletes list entries.
	r = staleProgram(t, `"C:\Users\a\AppData\Local\Tool\uninst.exe"`, true, true, func(b *agentv1.UninstallBody) { b.RemoveOlderThan = "9.9.9" })
	if len(r.p.deleted) != 0 {
		t.Fatalf("%v", r.p.deleted)
	}
}

func TestAStaleMachineEntryIsRemovedToo(t *testing.T) {
	r := newRig(t)
	r.addProgram("AcmeTool", map[string]string{"UninstallString": `"C:\Program Files\Acme\gone.exe"`}, nil)
	r.p.gone = map[string]bool{`C:\Program Files\Acme\gone.exe`: true}
	se, env := r.uninstallEnv("u1", nil)
	r.e.Accept(se, env)
	r.tick()
	if r.state("u1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.runs) != 0 || len(r.p.deleted) != 1 {
		t.Fatalf("%v %+v", r.state("u1"), r.rec.last("u1").Result)
	}
}

func TestAStaleEntryThatCannotBeDeletedFailsWithTheReason(t *testing.T) {
	r := newRig(t)
	r.addProgram("AcmeTool", map[string]string{"UninstallString": `"C:\Program Files\Acme\gone.exe"`}, nil)
	r.p.gone = map[string]bool{`C:\Program Files\Acme\gone.exe`: true}
	r.p.deleteErr = errors.New("access denied")
	se, env := r.uninstallEnv("u1", nil)
	r.e.Accept(se, env)
	r.tick()
	if r.state("u1") != agentv1.JobState_JOB_STATE_FAILED || !strings.Contains(r.rec.last("u1").Result.Message, "access denied") {
		t.Fatalf("%v %+v", r.state("u1"), r.rec.last("u1").Result)
	}
}
