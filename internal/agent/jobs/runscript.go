package jobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/shared/installer"
)

// Scripts from the console (D127). The most powerful thing the agent can be asked to do, so it is the one thing that is off
// until the person who installed the agent switched it on (--allow-scripts), whatever the server says.

// Limits of a script job.
const (
	MaxScriptBytes   = 64 << 10
	MinScriptTimeout = 10
	MaxScriptTimeout = 3600
)

// ScriptHost says how a script of one interpreter is run on this platform. Args contain %FILE%, replaced by the script's path.
type ScriptHost struct {
	FileName string // name of the script file in the staging directory
	Exe      string // absolute path of the interpreter
	Args     []string
	BOM      bool // the file must start with a UTF-8 byte order mark (Windows PowerShell 5.1 reads ANSI without one)
}

// ValidateRunScript checks a script job body.
func ValidateRunScript(b *agentv1.RunScriptBody) error {
	if b == nil {
		return bad("missing body")
	}
	if b.Interpreter != agentv1.ScriptInterpreter_SCRIPT_INTERPRETER_POWERSHELL {
		return bad("unknown script language")
	}
	if len(b.Content) == 0 || len(b.Content) > MaxScriptBytes || !utf8.ValidString(b.Content) || strings.ContainsRune(b.Content, 0) {
		return bad("a script is 1 to %d bytes of text", MaxScriptBytes)
	}
	sum := sha256.Sum256([]byte(b.Content))
	if !bytes.Equal(sum[:], b.Sha256) {
		return bad("the script does not match its fingerprint")
	}
	if b.TimeoutS < MinScriptTimeout || b.TimeoutS > MaxScriptTimeout {
		return bad("the time limit of a script is %d to %d seconds", MinScriptTimeout, MaxScriptTimeout)
	}
	if len(b.Name) > 200 || len(b.RunId) > 64 {
		return bad("descriptive fields too long")
	}
	return nil
}

func (e *Engine) runScript(ctx context.Context, r *Record, env *agentv1.JobEnvelope) *outcome {
	b := env.GetRunScript()
	host, err := e.P.ScriptHost(b.Interpreter)
	if err != nil {
		return fail("this computer cannot run that kind of script: %v", err)
	}
	dir, err := e.P.StagingDir(installer.Machine, "", r.JobID) // machine scope: SYSTEM only
	if err != nil {
		return fail("cannot create the staging directory: %v", err)
	}
	defer func() { _ = e.P.RemoveAll(dir) }()
	path := filepath.Join(dir, host.FileName)
	content := []byte(b.Content)
	if host.BOM {
		content = append([]byte("\xef\xbb\xbf"), content...)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return fail("cannot write the script: %v", err)
	}
	args := make([]string, len(host.Args))
	for i, a := range host.Args {
		args[i] = strings.ReplaceAll(a, "%FILE%", path)
	}
	e.log().Info("script run", "job", r.JobID, "run", b.RunId, "name", b.Name, "version", b.Version, "sha256", fmt.Sprintf("%x", b.Sha256[:6]))
	rr, err := e.P.Run(ctx, RunSpec{Exe: host.Exe, Args: args, Dir: dir, Timeout: time.Duration(b.TimeoutS) * time.Second})
	if err != nil {
		if ctx.Err() != nil {
			return &outcome{res: &agentv1.JobResult{}, cancelled: true}
		}
		return fail("could not start the script: %v", err)
	}
	res := &agentv1.JobResult{ExitCode: int32(rr.ExitCode), LogTail: tail(rr.LogTail), DetectionPassed: true, // #nosec G115 -- exit codes fit int32
		Message: fmt.Sprintf("script exit code %d", rr.ExitCode)}
	switch {
	case rr.TimedOut:
		res.Outcome, res.Message = agentv1.JobOutcome_JOB_OUTCOME_FAILED, fmt.Sprintf("the script exceeded its time limit of %d seconds and was stopped", b.TimeoutS)
		return &outcome{res: res, reason: "script_timeout"}
	case rr.ExitCode != 0:
		res.Outcome = agentv1.JobOutcome_JOB_OUTCOME_FAILED
		return &outcome{res: res, reason: "script_failed"}
	}
	res.Outcome = agentv1.JobOutcome_JOB_OUTCOME_SUCCESS
	return &outcome{res: res}
}
