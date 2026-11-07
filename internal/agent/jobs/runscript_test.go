package jobs

import (
	"crypto/sha256"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

func scriptBody(content string) *agentv1.RunScriptBody {
	sum := sha256.Sum256([]byte(content))
	return &agentv1.RunScriptBody{Name: "Clear cache", Version: 3, Interpreter: agentv1.ScriptInterpreter_SCRIPT_INTERPRETER_POWERSHELL,
		Content: content, Sha256: sum[:], TimeoutS: 60, RunId: "run-1"}
}

func scriptEnv(r *rig, id string, b *agentv1.RunScriptBody) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
	env := &agentv1.JobEnvelope{Version: 1, JobId: id, OrgId: "o", DeviceId: "d", Type: agentv1.JobType_JOB_TYPE_RUN_SCRIPT,
		IssuedAt: r.now.Unix(), NotBefore: r.now.Unix(), ExpiresAt: r.now.Add(time.Hour).Unix(), Nonce: make([]byte, 16),
		Body: &agentv1.JobEnvelope_RunScript{RunScript: b}}
	return r.sign(env), env
}

func TestScriptsAreRefusedWhenTheOwnerSwitchedThemOff(t *testing.T) {
	r := newRig(t) // ScriptsEnabled is false: the computer's owner switched scripts off (--no-scripts)
	se, env := scriptEnv(r, "s1", scriptBody("Write-Output hi"))
	r.e.Accept(se, env)
	u := r.rec.last("s1")
	if u.State != agentv1.JobState_JOB_STATE_REJECTED || !strings.Contains(u.Reason, "switched off") || len(r.p.runs) != 0 {
		t.Fatalf("%v %q runs=%d", u.State, u.Reason, len(r.p.runs))
	}
	if len(r.rec.sec) == 0 || r.rec.sec[0] != agentv1.SecurityEventKind_SECURITY_EVENT_KIND_POLICY_CEILING {
		t.Fatalf("a refused script is a security event: %v", r.rec.sec)
	}
}

func TestAnEmptyCeilingDoesNotSwitchScriptsOnAndASetOneMustNameThem(t *testing.T) {
	r := newRig(t)
	r.e.ScriptsEnabled = true
	r.e.Allowed = map[string]bool{"inventory": true}
	se, env := scriptEnv(r, "s1", scriptBody("x"))
	r.e.Accept(se, env)
	if r.state("s1") != agentv1.JobState_JOB_STATE_REJECTED {
		t.Fatalf("a ceiling without run_script: %v", r.state("s1"))
	}
	r.e.Allowed = map[string]bool{"inventory": true, "run_script": true}
	se, env = scriptEnv(r, "s2", scriptBody("x"))
	r.e.Accept(se, env)
	if r.state("s2") != agentv1.JobState_JOB_STATE_ACCEPTED {
		t.Fatalf("a ceiling with run_script: %v", r.state("s2"))
	}
	// An agent without any ceiling that did not switch scripts on still refuses them (the empty ceiling means "everything else").
	r2 := newRig(t)
	se, env = scriptEnv(r2, "s3", scriptBody("x"))
	r2.e.Accept(se, env)
	if r2.state("s3") != agentv1.JobState_JOB_STATE_REJECTED {
		t.Fatal("scripts ran on an agent that did not opt in")
	}
}

func TestAScriptRunsPrivatelyAndItsOutputComesBack(t *testing.T) {
	r := newRig(t)
	r.e.ScriptsEnabled = true
	var written string
	r.p.runFn = func(s RunSpec, _ string) (RunResult, error) {
		b, err := os.ReadFile(s.Args[len(s.Args)-1])
		if err != nil {
			return RunResult{}, err
		}
		written = string(b)
		return RunResult{ExitCode: 0, LogTail: "hello from the script"}, nil
	}
	se, env := scriptEnv(r, "s1", scriptBody("Write-Output 'é'"))
	r.e.Accept(se, env)
	r.tick()
	res := r.rec.last("s1").Result
	if r.state("s1") != agentv1.JobState_JOB_STATE_SUCCEEDED || res.LogTail != "hello from the script" || res.ExitCode != 0 {
		t.Fatalf("%v %+v", r.state("s1"), res)
	}
	if !strings.HasPrefix(written, "\xef\xbb\xbf") || !strings.HasSuffix(written, "Write-Output 'é'") {
		t.Fatalf("PowerShell 5.1 needs the byte order mark: %q", written)
	}
	if len(r.p.runs) != 1 || !strings.HasSuffix(r.p.runs[0].Exe, "powershell.exe") || r.p.runs[0].Timeout != time.Minute {
		t.Fatalf("%+v", r.p.runs)
	}
	if ents, _ := os.ReadDir(r.p.root + "/stage"); len(ents) != 0 {
		t.Fatalf("the script was left behind: %v", ents)
	}
}

func TestAFailingOrSlowScriptFailsTheJobWithoutRetry(t *testing.T) {
	r := newRig(t)
	r.e.ScriptsEnabled = true
	r.p.runFn = func(RunSpec, string) (RunResult, error) { return RunResult{ExitCode: 7, LogTail: "boom"}, nil }
	se, env := scriptEnv(r, "s1", scriptBody("exit 7"))
	r.e.Accept(se, env)
	r.tick()
	u := r.rec.last("s1")
	if u.State != agentv1.JobState_JOB_STATE_FAILED || u.Reason != "script_failed" || u.Result.LogTail != "boom" || u.Result.ExitCode != 7 {
		t.Fatalf("%v %q %+v", u.State, u.Reason, u.Result)
	}
	r.p.runFn = func(RunSpec, string) (RunResult, error) { return RunResult{ExitCode: -1, TimedOut: true}, nil }
	se, env = scriptEnv(r, "s2", scriptBody("Start-Sleep 999"))
	r.e.Accept(se, env)
	r.tick()
	if u := r.rec.last("s2"); u.Reason != "script_timeout" || u.State != agentv1.JobState_JOB_STATE_FAILED {
		t.Fatalf("%v %q", u.State, u.Reason)
	}
	if len(r.p.runs) != 2 {
		t.Fatalf("a script must never run twice: %d runs", len(r.p.runs))
	}
}

func TestScriptBodiesAreValidated(t *testing.T) {
	good := scriptBody("Get-Date")
	if err := ValidateRunScript(good); err != nil {
		t.Fatal(err)
	}
	mut := func(f func(b *agentv1.RunScriptBody)) *agentv1.RunScriptBody {
		b := scriptBody("Get-Date")
		f(b)
		return b
	}
	big := strings.Repeat("a", MaxScriptBytes+1)
	for name, b := range map[string]*agentv1.RunScriptBody{
		"nil":          nil,
		"no language":  mut(func(b *agentv1.RunScriptBody) { b.Interpreter = 0 }),
		"empty":        scriptBody(""),
		"too big":      scriptBody(big),
		"changed text": mut(func(b *agentv1.RunScriptBody) { b.Content += " ; Remove-Item C:\\ -Recurse" }),
		"no hash":      mut(func(b *agentv1.RunScriptBody) { b.Sha256 = nil }),
		"nul":          scriptBody("a\x00b"),
		"bad utf8":     scriptBody("a\xffb"),
		"short limit":  mut(func(b *agentv1.RunScriptBody) { b.TimeoutS = 1 }),
		"long limit":   mut(func(b *agentv1.RunScriptBody) { b.TimeoutS = 99999 }),
	} {
		if err := ValidateRunScript(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A script is machine-scope: a job aimed at a user is refused.
	r := newRig(t)
	r.e.ScriptsEnabled = true
	_, env := scriptEnv(r, "s1", good)
	env.TargetUserSid = "S-1-5-21-1-2-3-1001"
	se := r.sign(env)
	r.e.Accept(se, env)
	if r.state("s1") != agentv1.JobState_JOB_STATE_REJECTED {
		t.Fatalf("%v", r.state("s1"))
	}
}
