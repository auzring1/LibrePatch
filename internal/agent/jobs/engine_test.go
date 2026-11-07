package jobs

import (
	"strings"
	"testing"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

func TestInstallSucceedsAndCleansUp(t *testing.T) {
	r := newRig(t)
	r.installerRegisters("2.0", 0)
	se, env := r.installEnv("j1", nil)
	r.e.Accept(se, env)
	r.tick()
	if st := r.state("j1"); st != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("state %v: %+v", st, r.rec.last("j1"))
	}
	res := r.rec.last("j1").Result
	if !res.DetectionPassed || res.InstalledVersion != "2.0" || res.ExitCode != 0 {
		t.Fatalf("result: %+v", res)
	}
	if len(r.p.runs) != 1 || r.p.runs[0].Args[0] != "/silent" {
		t.Fatalf("runs: %+v", r.p.runs)
	}
	if ents, _ := osReadDir(r.p.root + "/stage"); len(ents) != 0 {
		t.Fatalf("staging not cleaned: %v", ents)
	}
	got := r.rec.states("j1")
	if got[0] != agentv1.JobState_JOB_STATE_ACCEPTED || got[len(got)-1] != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("state sequence: %v", got)
	}
}

func TestAlreadyInstalledDoesNotRun(t *testing.T) {
	r := newRig(t)
	k := r.p.machine.add(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AcmeTool`)
	k.vals["DisplayVersion"] = "2.5"
	se, env := r.installEnv("j1", nil)
	r.e.Accept(se, env)
	r.tick()
	res := r.rec.last("j1").Result
	if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED || !res.AlreadySatisfied || len(r.p.runs) != 0 {
		t.Fatalf("%v %+v runs=%d", r.state("j1"), res, len(r.p.runs))
	}
}

func TestOldVersionIsUpgraded(t *testing.T) {
	r := newRig(t)
	k := r.p.machine.add(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AcmeTool`)
	k.vals["DisplayVersion"] = "1.0"
	r.installerRegisters("2.0", 0)
	se, env := r.installEnv("j1", func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
		e.Type = agentv1.JobType_JOB_TYPE_SOFTWARE_UPDATE
		b.Update = true
	})
	r.e.Accept(se, env)
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.runs) != 1 {
		t.Fatalf("%v runs=%d", r.state("j1"), len(r.p.runs))
	}
}

func TestHashMismatchNeverRuns(t *testing.T) {
	r := newRig(t)
	se, env := r.installEnv("j1", nil)
	r.f.data["https://v.example/j1.exe"] = []byte("tampered")
	r.e.Accept(se, env)
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_FAILED || len(r.p.runs) != 0 {
		t.Fatalf("%v runs=%d", r.state("j1"), len(r.p.runs))
	}
	if len(r.rec.sec) == 0 || r.rec.sec[0] != agentv1.SecurityEventKind_SECURITY_EVENT_KIND_HASH_MISMATCH {
		t.Fatalf("no hash-mismatch security event: %v", r.rec.sec)
	}
}

func TestSecondSourceUsedWhenFirstFails(t *testing.T) {
	r := newRig(t)
	se, env := r.installEnv("j1", func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
		b.Installer.Sources = append([]*agentv1.ContentSource{{Kind: agentv1.ContentSourceKind_CONTENT_SOURCE_KIND_VENDOR, Url: "https://dead.example/x.exe"}}, b.Installer.Sources...)
	})
	r.installerRegisters("2.0", 0)
	r.e.Accept(se, env)
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("%v %+v", r.state("j1"), r.rec.last("j1"))
	}
}

func TestSuccessExitButNotDetectedIsFailure(t *testing.T) {
	r := newRig(t)
	r.p.runFn = func(RunSpec, string) (RunResult, error) { return RunResult{ExitCode: 0}, nil } // registers nothing
	se, env := r.installEnv("j1", nil)
	r.e.Accept(se, env)
	r.tick()
	u := r.rec.last("j1")
	if r.state("j1") != agentv1.JobState_JOB_STATE_FAILED || u.Reason != "failed_detection" {
		t.Fatalf("%v %q", r.state("j1"), u.Reason)
	}
}

func TestRebootRequiredAndFailureExitCodes(t *testing.T) {
	r := newRig(t)
	r.p.runFn = func(RunSpec, string) (RunResult, error) {
		k := r.p.machine.add(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AcmeTool`)
		k.vals["DisplayVersion"] = "2.0"
		return RunResult{ExitCode: 3010}, nil
	}
	se, env := r.installEnv("j1", nil)
	r.e.Accept(se, env)
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED_REBOOT || !r.rec.last("j1").Result.RebootRequired {
		t.Fatalf("%v", r.state("j1"))
	}
	r2 := newRig(t)
	r2.p.runFn = func(RunSpec, string) (RunResult, error) { return RunResult{ExitCode: 1603, LogTail: "boom"}, nil }
	se, env = r2.installEnv("j2", nil)
	r2.e.Accept(se, env)
	r2.tick()
	if r2.state("j2") != agentv1.JobState_JOB_STATE_FAILED || !strings.Contains(r2.rec.last("j2").Result.LogTail, "boom") {
		t.Fatalf("%v", r2.state("j2"))
	}
}

func TestRetryableIsRetriedWithBackoff(t *testing.T) {
	r := newRig(t)
	calls := 0
	r.p.runFn = func(RunSpec, string) (RunResult, error) {
		calls++
		if calls == 1 {
			return RunResult{ExitCode: 1618}, nil // MSI: another install in progress
		}
		k := r.p.machine.add(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AcmeTool`)
		k.vals["DisplayVersion"] = "2.0"
		return RunResult{ExitCode: 0}, nil
	}
	se, env := r.installEnv("j1", func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
		b.Installer.Type = agentv1.InstallerType_INSTALLER_TYPE_MSI
		b.MaxRetries, b.RetryBackoffS = 2, 30
	})
	r.e.Accept(se, env)
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_WAITING || r.rec.last("j1").Reason != "retry_backoff" {
		t.Fatalf("%v %q", r.state("j1"), r.rec.last("j1").Reason)
	}
	r.tick() // backoff not over: nothing happens
	if calls != 1 {
		t.Fatalf("retried too early: %d", calls)
	}
	r.now = r.now.Add(31 * time.Second)
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED || calls != 2 {
		t.Fatalf("%v calls=%d", r.state("j1"), calls)
	}
}

func TestRetriesExhausted(t *testing.T) {
	r := newRig(t)
	r.p.runFn = func(RunSpec, string) (RunResult, error) { return RunResult{ExitCode: 1618}, nil }
	se, env := r.installEnv("j1", func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
		b.Installer.Type = agentv1.InstallerType_INSTALLER_TYPE_MSI
		b.MaxRetries, b.RetryBackoffS = 1, 10
	})
	r.e.Accept(se, env)
	r.tick()
	r.now = r.now.Add(time.Minute)
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_FAILED || r.rec.last("j1").Reason != "retries_exhausted" {
		t.Fatalf("%v %q", r.state("j1"), r.rec.last("j1").Reason)
	}
}

func TestNotBeforeWindowAndExpiry(t *testing.T) {
	r := newRig(t)
	r.installerRegisters("2.0", 0)
	se, env := r.installEnv("j1", func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) { e.NotBefore = r.now.Add(time.Hour).Unix() })
	r.e.Accept(se, env)
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_WAITING || len(r.p.runs) != 0 {
		t.Fatal("ran before not_before")
	}
	r.now = r.now.Add(61 * time.Minute) // 13:01, but the window opens at 22:00 UTC
	se2, env2 := r.installEnv("j2", func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
		e.Window = &agentv1.MaintenanceWindow{StartMinute: 22 * 60, DurationMinutes: 120}
		e.ExpiresAt = r.now.Add(48 * time.Hour).Unix()
	})
	r.e.Accept(se2, env2)
	r.tick()
	if r.state("j2") != agentv1.JobState_JOB_STATE_WAITING || r.rec.last("j2").Reason != "waiting_window" {
		t.Fatalf("%v %q", r.state("j2"), r.rec.last("j2").Reason)
	}
	r.now = r.now.Add(9 * time.Hour) // 22:01 inside the window
	r.tick()
	if r.state("j2") != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("window did not open: %v", r.state("j2"))
	}
	se3, env3 := r.installEnv("j3", func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
		e.NotBefore = r.now.Add(time.Hour).Unix()
		e.ExpiresAt = r.now.Add(2 * time.Hour).Unix()
	})
	r.e.Accept(se3, env3)
	r.now = r.now.Add(3 * time.Hour)
	r.tick()
	if r.state("j3") != agentv1.JobState_JOB_STATE_EXPIRED {
		t.Fatalf("expected expiry: %v", r.state("j3"))
	}
}

func TestUserScopeWaitsForLogonThenRunsAsUser(t *testing.T) {
	r := newRig(t)
	const sid = "S-1-5-21-1-2-3-1001"
	var ranAs string
	r.p.runFn = func(s RunSpec, user string) (RunResult, error) {
		ranAs = user
		k := r.p.userRoot(sid).add(`Software\Microsoft\Windows\CurrentVersion\Uninstall\AcmeTool`)
		k.vals["DisplayVersion"] = "2.0"
		return RunResult{ExitCode: 0}, nil
	}
	se, env := r.installEnv("j1", func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
		e.TargetUserSid = sid
		b.Scope = agentv1.InstallScope_INSTALL_SCOPE_USER
		b.Installer.Type = agentv1.InstallerType_INSTALLER_TYPE_INNO
	})
	r.e.Accept(se, env)
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_WAITING || r.rec.last("j1").Reason != "waiting_user_logon" || len(r.p.runs) != 0 {
		t.Fatalf("%v %q", r.state("j1"), r.rec.last("j1").Reason)
	}
	r.p.sessions[sid] = true
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED || ranAs != sid {
		t.Fatalf("%v ranAs=%q", r.state("j1"), ranAs)
	}
	if !contains(r.p.runs[0].Args, "/CURRENTUSER") {
		t.Fatalf("user-scope inno args: %v", r.p.runs[0].Args)
	}
}

func TestRejections(t *testing.T) {
	r := newRig(t)
	// outside the local policy ceiling
	r.e.Allowed = map[string]bool{"software_uninstall": true}
	se, env := r.installEnv("j1", nil)
	r.e.Accept(se, env)
	if r.state("j1") != agentv1.JobState_JOB_STATE_REJECTED || len(r.rec.sec) == 0 || r.rec.sec[0] != agentv1.SecurityEventKind_SECURITY_EVENT_KIND_POLICY_CEILING {
		t.Fatalf("ceiling not enforced: %v %v", r.state("j1"), r.rec.sec)
	}
	r.e.Allowed = nil
	cases := map[string]func(*agentv1.JobEnvelope, *agentv1.InstallBody){
		"no hash": func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) { b.Installer.Sha256 = nil },
		"http source": func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
			b.Installer.Sources[0].Url = "http://v.example/a.exe"
		},
		"evil args":    func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) { b.Installer.Args = []string{"/S & calc"} },
		"path in name": func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) { b.Installer.FileName = `..\x.exe` },
		"machine+sid":  func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) { e.TargetUserSid = "S-1-5-21-1" },
		"user without sid": func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
			b.Scope = agentv1.InstallScope_INSTALL_SCOPE_USER
		},
		"msix without a package file or identity": func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
			b.Installer.Type = agentv1.InstallerType_INSTALLER_TYPE_MSIX
		},
		"huge timeout": func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) { b.TimeoutS = 99999 },
		"bad window": func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
			e.Window = &agentv1.MaintenanceWindow{StartMinute: 5000, DurationMinutes: 5}
		},
	}
	i := 0
	for name, mut := range cases {
		i++
		id := "r" + string(rune('a'+i))
		se, env := r.installEnv(id, mut)
		r.e.Accept(se, env)
		if r.state(id) != agentv1.JobState_JOB_STATE_REJECTED {
			t.Errorf("%s: state %v", name, r.state(id))
		}
	}
	if len(r.p.runs) != 0 {
		t.Fatal("a rejected job ran")
	}
}

func TestReofferedJobIsNotRunTwice(t *testing.T) {
	r := newRig(t)
	r.installerRegisters("2.0", 0)
	se, env := r.installEnv("j1", nil)
	r.e.Accept(se, env)
	r.tick()
	n := len(r.rec.updates)
	r.e.Accept(se, env) // the server never saw our result and offers the job again
	r.tick()
	if len(r.p.runs) != 1 || len(r.rec.updates) != n+1 || r.rec.last("j1").State != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("runs=%d updates=%d last=%v", len(r.p.runs), len(r.rec.updates), r.rec.last("j1").State)
	}
}

func TestSignerPin(t *testing.T) {
	r := newRig(t)
	r.installerRegisters("2.0", 0)
	r.p.sig = Signature{Signed: true, Valid: true, Subject: "Other Corp"}
	se, env := r.installEnv("j1", func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
		b.Installer.SignerPin = &agentv1.SignerPin{Subject: "Acme Inc."}
	})
	r.e.Accept(se, env)
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_FAILED || len(r.p.runs) != 0 ||
		r.rec.sec[len(r.rec.sec)-1] != agentv1.SecurityEventKind_SECURITY_EVENT_KIND_SIGNER_MISMATCH {
		t.Fatalf("%v runs=%d sec=%v", r.state("j1"), len(r.p.runs), r.rec.sec)
	}
	r.p.sig = Signature{Signed: true, Valid: true, Subject: "acme inc."}
	se, env = r.installEnv("j2", func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
		b.Installer.SignerPin = &agentv1.SignerPin{Subject: "Acme Inc."}
	})
	r.e.Accept(se, env)
	r.tick()
	if r.state("j2") != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("matching pin refused: %v", r.state("j2"))
	}
	// A broken signature is refused even without a pin.
	r.p.machine.add(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`).remove("AcmeTool")
	r.p.sig = Signature{Signed: true, Valid: false, Detail: "hash mismatch"}
	se, env = r.installEnv("j3", nil)
	r.e.Accept(se, env)
	r.tick()
	if r.state("j3") != agentv1.JobState_JOB_STATE_FAILED {
		t.Fatalf("invalid signature accepted: %v", r.state("j3"))
	}
}

func TestPreconditions(t *testing.T) {
	r := newRig(t)
	se, env := r.installEnv("j1", func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
		b.Preconditions = &agentv1.Preconditions{OsBuildMin: 99999}
	})
	r.e.Accept(se, env)
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_FAILED {
		t.Fatalf("OS build precondition ignored: %v", r.state("j1"))
	}
	r.p.freeMB = 1
	se, env = r.installEnv("j2", nil)
	r.e.Accept(se, env)
	r.tick()
	if r.state("j2") != agentv1.JobState_JOB_STATE_FAILED || !strings.Contains(r.rec.last("j2").Result.Message, "disk space") {
		t.Fatalf("free-space precondition ignored: %+v", r.rec.last("j2").Result)
	}
}

func TestCancelQueuedJob(t *testing.T) {
	r := newRig(t)
	se, env := r.installEnv("j1", func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) { e.NotBefore = r.now.Add(time.Hour).Unix() })
	r.e.Accept(se, env)
	cenv := &agentv1.JobEnvelope{Version: 1, JobId: "c1", OrgId: "o", DeviceId: "d", Type: agentv1.JobType_JOB_TYPE_CANCEL,
		IssuedAt: r.now.Unix(), ExpiresAt: r.now.Add(time.Hour).Unix(), Nonce: make([]byte, 16),
		Body: &agentv1.JobEnvelope_Cancel{Cancel: &agentv1.CancelBody{JobId: "j1"}}}
	r.e.Accept(r.sign(cenv), cenv)
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_CANCELLED {
		t.Fatalf("%v", r.state("j1"))
	}
}

func TestInventoryJob(t *testing.T) {
	r := newRig(t)
	rescans := 0
	r.e.InventoryNow = func() { rescans++ }
	env := &agentv1.JobEnvelope{Version: 1, JobId: "i1", OrgId: "o", DeviceId: "d", Type: agentv1.JobType_JOB_TYPE_INVENTORY_FULL,
		IssuedAt: r.now.Unix(), NotBefore: r.now.Unix(), ExpiresAt: r.now.Add(time.Hour).Unix(), Nonce: make([]byte, 16),
		Body: &agentv1.JobEnvelope_Inventory{Inventory: &agentv1.InventoryBody{}}}
	r.e.Accept(r.sign(env), env)
	r.tick()
	if r.state("i1") != agentv1.JobState_JOB_STATE_SUCCEEDED || rescans != 1 {
		t.Fatalf("%v rescans=%d", r.state("i1"), rescans)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestAbsWin(t *testing.T) {
	for p, want := range map[string]bool{`C:\a\b.exe`: true, `c:/a/b.exe`: true, `\\server\share\x.exe`: true, `a\b.exe`: false, `.\x.exe`: false, `\x.exe`: false, `C:x.exe`: false, ``: false} {
		if isAbsWin(p) != want {
			t.Errorf("isAbsWin(%q) != %v", p, want)
		}
	}
}
