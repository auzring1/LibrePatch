package jobs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/pki"
	"github.com/auzring1/librepatch/internal/shared/envelope"
	"github.com/auzring1/librepatch/internal/shared/pkix"
)

type helperRig struct {
	h    *pki.Hierarchy
	now  time.Time
	task HelperTask
	env  HelperEnv
	ran  []RunSpec
}

const hsid = "S-1-5-21-1-2-3-1001"

func newHelperRig(t *testing.T, mut func(*agentv1.JobEnvelope)) *helperRig {
	h, err := pki.NewHierarchy("T", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r := &helperRig{h: h, now: time.Now()}
	payload := []byte("MZ")
	env := &agentv1.JobEnvelope{Version: 1, JobId: "j", OrgId: "o", DeviceId: "d", TargetUserSid: hsid, Type: agentv1.JobType_JOB_TYPE_SOFTWARE_INSTALL,
		IssuedAt: r.now.Unix(), NotBefore: r.now.Unix(), ExpiresAt: r.now.Add(time.Hour).Unix(), Nonce: make([]byte, 16),
		Body: &agentv1.JobEnvelope_Install{Install: &agentv1.InstallBody{Scope: agentv1.InstallScope_INSTALL_SCOPE_USER,
			Installer: &agentv1.Installer{Sha256: sum(payload), Size: 2, FileName: "a.exe"}}}}
	if mut != nil {
		mut(env)
	}
	se, err := envelope.Sign(h.JobSigning.Key.(ed25519.PrivateKey), pkix.KeyID(h.JobSigning.Cert), env)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := proto.Marshal(se)
	r.task = HelperTask{Signed: raw, Root: h.Root.Cert.Raw, SigningDER: [][]byte{h.JobSigning.Cert.Raw}, DeviceID: "d", OrgID: "o", Now: r.now.Unix(),
		SID: hsid, StageDir: `C:\ProgramData\LibrePatchStage\` + hsid + `\j`, File: `C:\ProgramData\LibrePatchStage\` + hsid + `\j\a.exe`,
		Exe: `C:\ProgramData\LibrePatchStage\` + hsid + `\j\a.exe`, Args: []string{"/VERYSILENT"}, Dir: `C:\ProgramData\LibrePatchStage\` + hsid + `\j`, TimeoutS: 60}
	r.env = HelperEnv{CurrentSID: hsid, StageRoot: `C:\ProgramData\LibrePatchStage\` + hsid,
		Run: func(_ context.Context, s RunSpec) (RunResult, error) {
			r.ran = append(r.ran, s)
			return RunResult{ExitCode: 0, LogTail: "ok"}, nil
		},
		OpenLocked: func(string) (LockedFile, error) { return nopFile{bytes.NewReader(payload)}, nil }}
	return r
}

type nopFile struct{ *bytes.Reader }

func (nopFile) Close() error { return nil }

func (r *helperRig) serve(t *testing.T) HelperResult {
	b, _ := json.Marshal(r.task)
	var out bytes.Buffer
	if err := ServeHelper(context.Background(), bytes.NewReader(b), &out, r.env); err != nil {
		t.Fatal(err)
	}
	var res HelperResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	return res
}

func TestHelperRunsAVerifiedTask(t *testing.T) {
	r := newHelperRig(t, nil)
	res := r.serve(t)
	if res.Error != "" || res.ExitCode != 0 || res.LogTail != "ok" || len(r.ran) != 1 || r.ran[0].Exe != r.task.Exe || r.ran[0].Timeout != time.Minute {
		t.Fatalf("%+v ran=%v", res, r.ran)
	}
}

func TestHelperRefusals(t *testing.T) {
	cases := map[string]func(*helperRig){
		"wrong user":        func(r *helperRig) { r.env.CurrentSID = "S-1-5-21-1-2-3-1002" },
		"no SID":            func(r *helperRig) { r.env.CurrentSID = "" },
		"tampered envelope": func(r *helperRig) { r.task.Signed[len(r.task.Signed)/2] ^= 0xff },
		"foreign root": func(r *helperRig) {
			h2, _ := pki.NewHierarchy("evil", time.Now())
			r.task.Root = h2.Root.Cert.Raw
		},
		"wrong device":       func(r *helperRig) { r.task.DeviceID = "other" },
		"expired":            func(r *helperRig) { r.task.Now = time.Now().Add(48 * time.Hour).Unix() },
		"staging outside":    func(r *helperRig) { r.task.StageDir = `C:\Users\Public\x` },
		"file outside stage": func(r *helperRig) { r.task.File = `C:\Users\Public\a.exe` },
		"exe outside stage":  func(r *helperRig) { r.task.Exe = `C:\Windows\System32\cmd.exe` },
		"traversal":          func(r *helperRig) { r.task.Exe = r.task.StageDir + `\..\..\evil.exe` },
		"other users stage": func(r *helperRig) {
			o := `C:\ProgramData\LibrePatchStage\S-1-5-21-1-2-3-1002\j`
			r.task.StageDir, r.task.File, r.task.Exe = o, o+`\a.exe`, o+`\a.exe`
		},
		"hash mismatch": func(r *helperRig) {
			r.env.OpenLocked = func(string) (LockedFile, error) { return nopFile{bytes.NewReader([]byte("tampered"))}, nil }
		},
		"zero timeout": func(r *helperRig) { r.task.TimeoutS = 0 },
		"huge timeout": func(r *helperRig) { r.task.TimeoutS = 100 * 3600 },
	}
	for name, mut := range cases {
		r := newHelperRig(t, nil)
		mut(r)
		if res := r.serve(t); res.Error == "" || len(r.ran) != 0 {
			t.Errorf("%s: not refused: %+v", name, res)
		}
	}
	// A machine-scope job or another job type is never run in the user's context.
	r := newHelperRig(t, func(e *agentv1.JobEnvelope) {
		e.GetInstall().Scope = agentv1.InstallScope_INSTALL_SCOPE_MACHINE
	})
	if res := r.serve(t); res.Error == "" || len(r.ran) != 0 {
		t.Errorf("machine-scope install: %+v", res)
	}
	r = newHelperRig(t, func(e *agentv1.JobEnvelope) { e.Type, e.Body = agentv1.JobType_JOB_TYPE_REBOOT, nil })
	if res := r.serve(t); res.Error == "" {
		t.Errorf("reboot job: %+v", res)
	}
	// An envelope for a different SID than the helper's token is refused even if the task claims the right one.
	r = newHelperRig(t, func(e *agentv1.JobEnvelope) { e.TargetUserSid = "S-1-5-21-1-2-3-1002" })
	if res := r.serve(t); res.Error == "" {
		t.Errorf("envelope for another user: %+v", res)
	}
}

func TestHelperUninstallTask(t *testing.T) {
	r := newHelperRig(t, func(e *agentv1.JobEnvelope) {
		e.Type = agentv1.JobType_JOB_TYPE_SOFTWARE_UNINSTALL
		e.Body = &agentv1.JobEnvelope_Uninstall{Uninstall: &agentv1.UninstallBody{Scope: agentv1.InstallScope_INSTALL_SCOPE_USER, ItemSource: "hku", ItemKey: "Tool"}}
	})
	r.task.File, r.task.Exe, r.task.Args = "", `C:\Users\alice\AppData\Local\Tool\unins000.exe`, []string{"/VERYSILENT"}
	if res := r.serve(t); res.Error != "" || len(r.ran) != 1 {
		t.Fatalf("%+v", res)
	}
	r = newHelperRig(t, func(e *agentv1.JobEnvelope) {
		e.Type = agentv1.JobType_JOB_TYPE_SOFTWARE_UNINSTALL
		e.Body = &agentv1.JobEnvelope_Uninstall{Uninstall: &agentv1.UninstallBody{Scope: agentv1.InstallScope_INSTALL_SCOPE_USER, ItemSource: "hku", ItemKey: "Tool"}}
	})
	r.task.File, r.task.Exe = "", `unins000.exe`
	if res := r.serve(t); res.Error == "" {
		t.Fatal("relative uninstaller path accepted")
	}
}

func TestHelperPathContainment(t *testing.T) {
	root := `C:\ProgramData\LibrePatchStage\S-1`
	for p, want := range map[string]bool{root: true, root + `\j\a.exe`: true, strings.ToLower(root) + `\J`: true, root + `x\a`: false, `C:\ProgramData\LibrePatchStage`: false,
		root + `\..\S-2\a`: false, root + `\j\..`: false, ``: false} {
		if underPath(p, root) != want {
			t.Errorf("underPath(%q) != %v", p, want)
		}
	}
	_ = x509.Certificate{}
}

// The user may read and execute in the staging directory but not write there, so the helper captures the output and the
// installer's log in a folder of its own and points the installer's log argument there (D145).
func TestHelperKeepsTheOutputAndTheLogOutOfTheStagingDirectory(t *testing.T) {
	r := newHelperRig(t, nil)
	log := r.task.Dir + `\install.log`
	r.task.LogPath = log
	r.task.Args = []string{"/VERYSILENT", "/LOG=" + log, "/l*v", log}
	if res := r.serve(t); res.Error != "" {
		t.Fatalf("%+v", res)
	}
	got := r.ran[0]
	if got.OutDir == "" || strings.Contains(got.OutDir, "ProgramData") {
		t.Fatalf("output goes to the user's own folder: %q", got.OutDir)
	}
	if !strings.HasPrefix(got.LogPath, got.OutDir) || !strings.HasSuffix(got.LogPath, "install.log") {
		t.Fatalf("the log moves with it: %q", got.LogPath)
	}
	for _, a := range got.Args {
		if strings.Contains(a, "ProgramData") {
			t.Fatalf("no argument still points into the staging directory: %q", got.Args)
		}
	}
	if got.Args[1] != "/LOG="+got.LogPath || got.Args[3] != got.LogPath {
		t.Fatalf("args: %q", got.Args)
	}
	if got.Dir != r.task.Dir {
		t.Fatalf("the installer still starts from the staging directory: %q", got.Dir)
	}
	if _, err := os.Stat(got.OutDir); err == nil {
		t.Fatal("the folder is removed afterwards")
	}
}
