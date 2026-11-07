package jobs

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/shared/envelope"
)

// The user-context helper (docs/ARCHITECTURE.md §8) is the agent binary started
// in the user's session with the user's own token. It receives exactly one task
// over an anonymous pipe, re-verifies everything it can with the same pinned
// keys, runs the command and writes a size-capped result.

// Limits on the pipe protocol.
const (
	maxTaskBytes   = 1 << 20
	maxResultBytes = 64 << 10
)

// HelperTask is the service's request to the helper.
type HelperTask struct {
	Signed     []byte   `json:"signed"`      // serialized SignedEnvelope
	Root       []byte   `json:"root"`        // DER of the pinned root
	SigningDER [][]byte `json:"signing_der"` // DER of job-signing certificates
	DeviceID   string   `json:"device_id"`
	OrgID      string   `json:"org_id"`
	Now        int64    `json:"now"` // server-corrected unix time
	SID        string   `json:"sid"` // the user the job targets
	StageDir   string   `json:"stage_dir"`
	File       string   `json:"file,omitempty"` // staged installer to re-hash (install jobs)
	Exe        string   `json:"exe"`
	Args       []string `json:"args"`
	Dir        string   `json:"dir"`
	LogPath    string   `json:"log_path,omitempty"`
	TimeoutS   int64    `json:"timeout_s"`
}

// HelperResult is the helper's answer; the service treats it as untrusted.
type HelperResult struct {
	ExitCode int    `json:"exit_code"`
	TimedOut bool   `json:"timed_out"`
	LogTail  string `json:"log_tail"`
	Error    string `json:"error,omitempty"`
}

// HelperEnv is what the helper process provides about itself.
type HelperEnv struct {
	// CurrentSID is the SID of the token the helper runs under.
	CurrentSID string
	// StageRoot is the only directory tree staged files may live in (per-user staging root).
	StageRoot  string
	Run        func(ctx context.Context, spec RunSpec) (RunResult, error)
	OpenLocked func(path string) (LockedFile, error)
}

// baseName is the last element of a Windows or slash path.
func baseName(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	return p[strings.LastIndex(p, "/")+1:]
}

func underPath(p, root string) bool {
	n := func(s string) string { return strings.ToLower(path.Clean(strings.ReplaceAll(s, `\`, "/"))) }
	pp, rr := n(p), n(root)
	if strings.Contains(strings.ReplaceAll(p, `\`, "/"), "/../") || strings.HasSuffix(strings.ReplaceAll(p, `\`, "/"), "/..") {
		return false
	}
	return pp == rr || strings.HasPrefix(pp, rr+"/")
}

// ServeHelper reads one task from in, verifies and runs it, and writes the
// result to out. It returns an error only for protocol failures; refusals are
// reported in the result so the service can log why.
func ServeHelper(ctx context.Context, in io.Reader, out io.Writer, env HelperEnv) error {
	raw, err := io.ReadAll(io.LimitReader(in, maxTaskBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxTaskBytes {
		return errors.New("task too large")
	}
	var task HelperTask
	if err := json.Unmarshal(raw, &task); err != nil {
		return fmt.Errorf("bad task: %w", err)
	}
	res := runTask(ctx, &task, env)
	b, err := json.Marshal(res)
	if err != nil {
		return err
	}
	if len(b) > maxResultBytes {
		res.LogTail = res.LogTail[:len(res.LogTail)/2]
		b, _ = json.Marshal(res)
	}
	_, err = out.Write(b)
	return err
}

func refuse(format string, a ...any) HelperResult {
	return HelperResult{ExitCode: -1, Error: fmt.Sprintf(format, a...)}
}

func runTask(ctx context.Context, t *HelperTask, e HelperEnv) HelperResult {
	if e.CurrentSID == "" || t.SID != e.CurrentSID {
		return refuse("the task is for %q but the helper runs as %q", t.SID, e.CurrentSID)
	}
	root, err := x509.ParseCertificate(t.Root)
	if err != nil {
		return refuse("bad root certificate")
	}
	var certs []*x509.Certificate
	for _, d := range t.SigningDER {
		if c, err := x509.ParseCertificate(d); err == nil {
			certs = append(certs, c)
		}
	}
	se := &agentv1.SignedEnvelope{}
	if err := proto.Unmarshal(t.Signed, se); err != nil {
		return refuse("bad envelope")
	}
	v := &envelope.Verifier{Root: root, DeviceID: t.DeviceID, OrgID: t.OrgID, SigningCerts: certs, Now: func() time.Time { return time.Unix(t.Now, 0) }}
	env, err := v.Open(se)
	if err != nil {
		return refuse("envelope verification failed: %v", err)
	}
	if env.TargetUserSid != e.CurrentSID {
		return refuse("the envelope targets another user")
	}
	var stageOK bool
	switch env.Type {
	case agentv1.JobType_JOB_TYPE_SOFTWARE_INSTALL, agentv1.JobType_JOB_TYPE_SOFTWARE_UPDATE:
		in := env.GetInstall()
		if in == nil || in.Installer == nil || in.Scope != agentv1.InstallScope_INSTALL_SCOPE_USER {
			return refuse("not a user-scope install")
		}
		stageOK = true
		if !underPath(t.StageDir, e.StageRoot) || !underPath(t.File, t.StageDir) || !underPath(t.Exe, t.StageDir) {
			return refuse("staged files are outside the user's staging directory")
		}
		f, err := e.OpenLocked(t.File)
		if err != nil {
			return refuse("cannot open the staged installer: %v", err)
		}
		sum, herr := hashLocked(f)
		_ = f.Close()
		if herr != nil || !bytes.Equal(sum, in.Installer.Sha256) {
			return refuse("the staged installer does not match the signed SHA-256")
		}
	case agentv1.JobType_JOB_TYPE_SOFTWARE_UNINSTALL:
		if env.GetUninstall() == nil || env.GetUninstall().Scope != agentv1.InstallScope_INSTALL_SCOPE_USER {
			return refuse("not a user-scope uninstall")
		}
		if !isAbsWin(t.Exe) {
			return refuse("the uninstaller path is not absolute")
		}
		stageOK = true
	default:
		return refuse("job type %s does not run in user context", env.Type)
	}
	if !stageOK {
		return refuse("unsupported task")
	}
	timeout := time.Duration(t.TimeoutS) * time.Second
	if timeout <= 0 || timeout > MaxTimeout {
		return refuse("timeout out of range")
	}
	// The user may read and execute in the staging directory but not write there, so the output and the installer's log go to a
	// folder of the user's own (their temp folder) for the length of the run (D145).
	scratch, err := os.MkdirTemp("", "librepatch-")
	if err != nil {
		return refuse("cannot make a folder for the installer's output: %v", err)
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	spec := RunSpec{Exe: t.Exe, Args: t.Args, Dir: t.Dir, OutDir: scratch, Timeout: timeout, LogPath: t.LogPath}
	if t.LogPath != "" {
		spec.LogPath = filepath.Join(scratch, baseName(t.LogPath))
		spec.Args = make([]string, len(t.Args))
		for i, a := range t.Args {
			spec.Args[i] = strings.ReplaceAll(a, t.LogPath, spec.LogPath)
		}
	}
	rr, err := e.Run(ctx, spec)
	if err != nil {
		return refuse("could not run: %v", err)
	}
	return HelperResult{ExitCode: rr.ExitCode, TimedOut: rr.TimedOut, LogTail: tail(rr.LogTail)}
}
