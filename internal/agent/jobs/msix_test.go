package jobs

import (
	"os"
	"strings"
	"testing"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// msixInstallEnv is an install job for the MSIX package Contoso.Terminal, 1.25.2733.0.
func (r *rig) msixInstallEnv(id string, mut func(*agentv1.JobEnvelope, *agentv1.InstallBody)) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
	return r.installEnv(id, func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
		url := "https://v.example/" + id + ".msixbundle"
		payload := []byte("PK msix bundle bytes " + id)
		r.f.data[url] = payload
		b.Version = "1.25.2733.0"
		b.Installer = &agentv1.Installer{Type: agentv1.InstallerType_INSTALLER_TYPE_MSIX, Sha256: sum(payload), Size: uint64(len(payload)),
			FileName: id + ".msixbundle", Sources: []*agentv1.ContentSource{{Kind: agentv1.ContentSourceKind_CONTENT_SOURCE_KIND_VENDOR, Url: url}}}
		b.Detection = []*agentv1.Detection{{Kind: agentv1.DetectionKind_DETECTION_KIND_APPX, Key: "Contoso.Terminal_", Version: "1.25.2733.0", Cmp: agentv1.VersionCmp_VERSION_CMP_GE}}
		if mut != nil {
			mut(e, b)
		}
	})
}

func TestMSIXPackageIsInstalledByTheAgentsOwnScript(t *testing.T) {
	r := newRig(t)
	var script []byte
	r.p.runFn = func(s RunSpec, user string) (RunResult, error) {
		// The first argument that names a .ps1 file is the script the agent wrote; read it while the staging directory exists.
		for _, a := range s.Args {
			if strings.HasSuffix(a, "msix-install.ps1") {
				script, _ = os.ReadFile(a)
			}
		}
		return RunResult{ExitCode: 0, LogTail: "Contoso.Terminal 1.25.2733.0 is provisioned for all users."}, nil
	}
	se, env := r.msixInstallEnv("m1", nil)
	r.e.Accept(se, env)
	r.tick()
	if st := r.state("m1"); st != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("state %v: %+v", st, r.rec.last("m1"))
	}
	if len(r.p.runs) != 1 {
		t.Fatalf("runs: %+v", r.p.runs)
	}
	run := r.p.runs[0]
	if !strings.HasSuffix(strings.ToLower(run.Exe), "powershell.exe") {
		t.Fatalf("the package is installed through PowerShell, not by running the package: %s", run.Exe)
	}
	// The package path, identity name and version are parameters after the script file, never part of the script text.
	joined := strings.Join(run.Args, "\n")
	for _, want := range []string{"-Package\n", "m1.msixbundle", "-Name\nContoso.Terminal\n", "-Version\n1.25.2733.0"} {
		if !strings.Contains(joined+"\n", want) {
			t.Errorf("arguments lack %q: %q", want, run.Args)
		}
	}
	if !strings.Contains(string(script), "Add-AppxProvisionedPackage") || strings.Contains(string(script), "Contoso") || strings.Contains(string(script), "m1.msixbundle") {
		t.Errorf("the script must be the agent's fixed text, got %q", script)
	}
	if !strings.HasPrefix(string(script), "\xef\xbb\xbfparam(") {
		t.Errorf("the script starts with a byte order mark and its parameters: %q", script[:20])
	}
	res := r.rec.last("m1").Result
	if res.InstalledVersion != "1.25.2733.0" || !res.DetectionPassed || !strings.Contains(res.LogTail, "provisioned") {
		t.Fatalf("result: %+v", res)
	}
	if ents, _ := osReadDir(r.p.root + "/stage"); len(ents) != 0 {
		t.Fatalf("staging not cleaned: %v", ents)
	}
}

func TestMSIXFailureShowsWindowsReason(t *testing.T) {
	r := newRig(t)
	r.p.runFn = func(RunSpec, string) (RunResult, error) {
		return RunResult{ExitCode: 1, LogTail: "Windows could not install the package: 0x80073CF3 dependency"}, nil
	}
	se, env := r.msixInstallEnv("m2", nil)
	r.e.Accept(se, env)
	r.tick()
	if st := r.state("m2"); st != agentv1.JobState_JOB_STATE_FAILED {
		t.Fatalf("state %v: %+v", st, r.rec.last("m2"))
	}
	if res := r.rec.last("m2").Result; !strings.Contains(res.LogTail, "0x80073CF3") {
		t.Fatalf("the reason must reach the console: %+v", res)
	}
}

func TestMSIXJobsAreChecked(t *testing.T) {
	r := newRig(t)
	for name, mut := range map[string]func(*agentv1.JobEnvelope, *agentv1.InstallBody){
		"user scope": func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
			b.Scope = agentv1.InstallScope_INSTALL_SCOPE_USER
			e.TargetUserSid = "S-1-5-21-1-2-3-1001"
		},
		"not a package file": func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) { b.Installer.FileName = "setup.exe" },
		"no identity":        func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) { b.Detection = nil },
		"hostile identity": func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
			b.Detection[0].Key = "x'; calc; '_"
		},
	} {
		id := "bad" + strings.ReplaceAll(name, " ", "")
		se, env := r.msixInstallEnv(id, mut)
		r.e.Accept(se, env)
		if st := r.state(id); st != agentv1.JobState_JOB_STATE_REJECTED {
			t.Errorf("%s: state %v", name, st)
		}
	}
	if len(r.p.runs) != 0 {
		t.Fatalf("nothing may run for a refused job: %+v", r.p.runs)
	}
}

func TestMSIXPackageIsRemovedForAllUsers(t *testing.T) {
	r := newRig(t)
	var script []byte
	r.p.runFn = func(s RunSpec, user string) (RunResult, error) {
		for _, a := range s.Args {
			if strings.HasSuffix(a, "msix-remove.ps1") {
				script, _ = os.ReadFile(a)
			}
		}
		return RunResult{ExitCode: 0, LogTail: "Contoso.Terminal was removed."}, nil
	}
	se, env := r.uninstallEnv("u1", func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) {
		b.ItemSource, b.ItemKey = "appx", "Contoso.Terminal_1.25.2733.0_x64__contosopub001"
	})
	r.e.Accept(se, env)
	r.tick()
	if st := r.state("u1"); st != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("state %v: %+v", st, r.rec.last("u1"))
	}
	run := r.p.runs[0]
	if !contains(run.Args, "-Name") || !contains(run.Args, "Contoso.Terminal") {
		t.Fatalf("the package name is a parameter: %v", run.Args)
	}
	if !strings.Contains(string(script), "Remove-AppxPackage") || strings.Contains(string(script), "Contoso") {
		t.Fatalf("the script must be the fixed text: %q", script)
	}

	for name, mut := range map[string]func(*agentv1.JobEnvelope, *agentv1.UninstallBody){
		"bad full name": func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) { b.ItemKey = "x'; calc" },
		"user scope": func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) {
			b.Scope = agentv1.InstallScope_INSTALL_SCOPE_USER
			e.TargetUserSid = "S-1-5-21-1-2-3-1001"
		},
	} {
		id := "ub" + strings.ReplaceAll(name, " ", "")
		se, env := r.uninstallEnv(id, func(e *agentv1.JobEnvelope, b *agentv1.UninstallBody) {
			b.ItemSource, b.ItemKey = "appx", "Contoso.Terminal_1.25.2733.0_x64__contosopub001"
			mut(e, b)
		})
		r.e.Accept(se, env)
		if st := r.state(id); st != agentv1.JobState_JOB_STATE_REJECTED {
			t.Errorf("%s: state %v", name, st)
		}
	}
}
