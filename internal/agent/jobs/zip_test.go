package jobs

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

func zipBytes(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, c := range files {
		w, _ := zw.Create(n)
		_, _ = w.Write([]byte(c))
	}
	_ = zw.Close()
	return buf.Bytes()
}

func zipEnv(r *rig, id string, z []byte, nested string) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
	return r.installEnv(id, func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
		r.f.data["https://v.example/"+id+".exe"] = z
		b.Installer.Type = agentv1.InstallerType_INSTALLER_TYPE_ZIP
		b.Installer.NestedType = agentv1.InstallerType_INSTALLER_TYPE_INNO
		b.Installer.NestedPath = nested
		b.Installer.Sha256, b.Installer.Size, b.Installer.FileName = sum(z), uint64(len(z)), id+".zip"
		b.Installer.Sources[0].Url = "https://v.example/" + id + ".exe"
	})
}

func TestZipNestedInstaller(t *testing.T) {
	r := newRig(t)
	z := zipBytes(t, map[string]string{"setup/setup.exe": "MZ nested"})
	var ran string
	r.p.runFn = func(s RunSpec, _ string) (RunResult, error) {
		ran = s.Exe
		b, err := os.ReadFile(s.Exe)
		if err != nil || string(b) != "MZ nested" {
			t.Errorf("nested installer not extracted at %s: %v", s.Exe, err)
		}
		r.p.machine.add(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AcmeTool`).vals["DisplayVersion"] = "2.0"
		return RunResult{}, nil
	}
	se, env := zipEnv(r, "z1", z, "setup/setup.exe")
	r.e.Accept(se, env)
	r.tick()
	if r.state("z1") != agentv1.JobState_JOB_STATE_SUCCEEDED || ran == "" {
		t.Fatalf("%v %+v", r.state("z1"), r.rec.last("z1").Result)
	}
	// Missing nested path and traversal inside the archive both fail without running anything.
	r.p.machine.add(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`).remove("AcmeTool")
	r.p.runs = nil
	se, env = zipEnv(r, "z2", z, "setup/other.exe")
	r.e.Accept(se, env)
	r.tick()
	if r.state("z2") != agentv1.JobState_JOB_STATE_FAILED || len(r.p.runs) != 0 {
		t.Fatalf("missing nested: %v", r.state("z2"))
	}
	evil := zipBytes(t, map[string]string{"../evil.exe": "MZ"})
	se, env = zipEnv(r, "z3", evil, "evil.exe")
	r.e.Accept(se, env)
	r.tick()
	if r.state("z3") != agentv1.JobState_JOB_STATE_FAILED || len(r.p.runs) != 0 {
		t.Fatalf("zip-slip archive: %v", r.state("z3"))
	}
}

func TestPortableCopy(t *testing.T) {
	r := newRig(t)
	se, env := r.installEnv("p1", func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
		b.Installer.Type = agentv1.InstallerType_INSTALLER_TYPE_PORTABLE
		b.Installer.FileName = "tool.exe"
		b.Detection = []*agentv1.Detection{{Kind: agentv1.DetectionKind_DETECTION_KIND_FILE, Key: "%ProgramFiles%/LibrePatch/Portable/Acme.Tool/tool.exe"}}
	})
	// the fake reports a file as present once the engine copied it
	r.e.Accept(se, env)
	target := filepath.Join(r.p.Env("", "", "PROGRAMFILES"), "LibrePatch", "Portable", "Acme.Tool", "tool.exe")
	r.tick()
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("portable file not copied: %v (%v)", err, r.rec.last("p1").Result)
	}
	if r.state("p1") != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("portable install: %v %+v", r.state("p1"), r.rec.last("p1").Result)
	}
	// user-scope portable is refused
	se, env = r.installEnv("p2", func(e *agentv1.JobEnvelope, b *agentv1.InstallBody) {
		b.Installer.Type = agentv1.InstallerType_INSTALLER_TYPE_PORTABLE
		b.Scope, e.TargetUserSid = agentv1.InstallScope_INSTALL_SCOPE_USER, "S-1-5-21-1-2-3-1001"
	})
	r.p.sessions["S-1-5-21-1-2-3-1001"] = true
	r.e.Accept(se, env)
	r.tick()
	if r.state("p2") != agentv1.JobState_JOB_STATE_FAILED {
		t.Fatalf("user-scope portable: %v", r.state("p2"))
	}
}
