package jobs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/shared/installer"
)

// MSIX / AppX packages (D151): installed, updated and removed by fixed PowerShell scripts of the agent's own
// (installer.MSIXInstallScript, installer.MSIXRemoveScript). The server supplies only the package file (verified like every
// installer: SHA-256, optional signer pin) and the package's identity name and version, which are validated here and handed
// to the script as parameters, never pasted into its text.

// msixName finds the package identity name in the detection rules of an install job.
func msixName(rules []*agentv1.Detection) (string, error) {
	for _, r := range rules {
		if r.Kind == agentv1.DetectionKind_DETECTION_KIND_APPX {
			if n, ok := installer.AppxNameFromDetectionKey(r.Key); ok {
				return n, nil
			}
		}
	}
	return "", errors.New("an MSIX/AppX package needs a detection rule that names the package (the manifest's PackageFamilyName)")
}

// runPowerShellScript writes script (fixed text) into dir and runs it with the platform's PowerShell and the given
// parameters.
func (e *Engine) runPowerShellScript(ctx context.Context, dir, fileName, script string, params []string, timeout time.Duration) (RunResult, error) {
	host, err := e.P.ScriptHost(agentv1.ScriptInterpreter_SCRIPT_INTERPRETER_POWERSHELL)
	if err != nil {
		return RunResult{}, fmt.Errorf("this computer cannot run PowerShell: %w", err)
	}
	path := filepath.Join(dir, fileName)
	content := []byte(script)
	if host.BOM {
		content = append([]byte("\xef\xbb\xbf"), content...)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return RunResult{}, fmt.Errorf("cannot write the script: %w", err)
	}
	args := make([]string, 0, len(host.Args)+len(params))
	for _, a := range host.Args {
		args = append(args, strings.ReplaceAll(a, "%FILE%", path))
	}
	args = append(args, params...)
	return e.P.Run(ctx, RunSpec{Exe: host.Exe, Args: args, Dir: dir, Timeout: timeout})
}

// installMSIX provisions the verified package file for every user of the computer.
func (e *Engine) installMSIX(ctx context.Context, b *agentv1.InstallBody, dir, file string, timeout time.Duration) (RunResult, error) {
	name, err := msixName(b.Detection)
	if err != nil {
		return RunResult{}, err
	}
	version := b.Version
	if version == "" {
		version = "0"
	}
	return e.runPowerShellScript(ctx, dir, "msix-install.ps1", installer.MSIXInstallScript,
		[]string{"-Package", file, "-Name", name, "-Version", version}, timeout)
}

// uninstallAppx removes an MSIX/AppX package, named by the full name an inventory row carries, for all users.
func (e *Engine) uninstallAppx(ctx context.Context, r *Record, env *agentv1.JobEnvelope) *outcome {
	b := env.GetUninstall()
	name, ok := installer.AppxNameFromFullName(b.ItemKey)
	if !ok {
		return fail("the package full name is not valid")
	}
	timeout, _ := timeoutOf(b.TimeoutS)
	dir, err := e.P.StagingDir(installer.Machine, "", r.JobID)
	if err != nil {
		return fail("cannot create the working directory: %v", err)
	}
	defer func() { _ = e.P.RemoveAll(dir) }()
	rr, err := e.runPowerShellScript(ctx, dir, "msix-remove.ps1", installer.MSIXRemoveScript, []string{"-Name", name}, timeout)
	if err != nil {
		if ctx.Err() != nil {
			return &outcome{res: &agentv1.JobResult{}, cancelled: true}
		}
		return fail("could not remove the package: %v", err)
	}
	res := &agentv1.JobResult{ExitCode: int32(rr.ExitCode), LogTail: tail(rr.LogTail), DetectionPassed: rr.ExitCode == 0, // #nosec G115 -- exit codes fit int32
		Message: fmt.Sprintf("removal script exit code %d", rr.ExitCode)}
	switch {
	case rr.TimedOut:
		res.Outcome, res.Message = agentv1.JobOutcome_JOB_OUTCOME_FAILED, "the removal exceeded its time limit and was stopped"
		return &outcome{res: res, reason: "uninstaller_failed"}
	case rr.ExitCode != 0:
		res.Outcome = agentv1.JobOutcome_JOB_OUTCOME_FAILED
		return &outcome{res: res, reason: "uninstaller_failed"}
	}
	res.Outcome = agentv1.JobOutcome_JOB_OUTCOME_SUCCESS
	return &outcome{res: res}
}
