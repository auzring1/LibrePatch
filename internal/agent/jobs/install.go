package jobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"io"
	"os"
	"path/filepath"
	"strings"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/shared/installer"
)

const logTailMax = 16 << 10

func tail(s string) string {
	if len(s) > logTailMax {
		s = s[len(s)-logTailMax:]
	}
	return strings.ToValidUTF8(s, "�")
}

// install runs the install pipeline (docs/ARCHITECTURE.md §7.3):
// preconditions, pre-detection, stage, verify, run, map exit code, post-detection.
func (e *Engine) install(ctx context.Context, r *Record, env *agentv1.JobEnvelope) *outcome {
	b := env.GetInstall()
	scope, _ := scopeOf(b.Scope)
	sid := env.TargetUserSid
	in := b.Installer
	t := typeNames[in.Type]
	if (t == installer.Portable || t == installer.Zip) && scope == installer.User {
		return fail("portable and ZIP packages can only be installed machine-wide in this version")
	}

	// 1. Preconditions.
	if p := b.Preconditions; p != nil {
		if p.OsBuildMin > 0 && e.P.OSBuild() < p.OsBuildMin {
			return fail("Windows build %d is older than the required %d", e.P.OSBuild(), p.OsBuildMin)
		}
	}

	// 2. Already satisfied? (install: present; update: present at the target version.) An MSIX/AppX package is judged by its
	// own script, which asks Windows (D151).
	var det Detection
	var known bool
	var derr error
	if t != installer.MSIX {
		det, known, derr = e.Detect(b.Detection, scope, sid)
	}
	if derr != nil {
		e.log().Warn("pre-detection failed", "job", r.JobID, "err", derr)
	} else if known && det.Present {
		return &outcome{res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, DetectionPassed: true,
			AlreadySatisfied: true, InstalledVersion: det.Version, Message: "already installed; nothing to do"}}
	}

	// 2b. Programs the update replaces are open (only when the deployment asked for it, D124): wait, or ask.
	var consent bool
	if o := e.inUseGate(ctx, b, sid, false, &consent); o != nil {
		return o
	}

	// 3. Stage.
	dir, err := e.P.StagingDir(scope, sid, r.JobID)
	if err != nil {
		return fail("cannot create the staging directory: %v", err)
	}
	defer func() { _ = e.P.RemoveAll(dir) }()
	if p := b.Preconditions; p != nil || in.Size > 0 {
		free, ferr := e.P.FreeSpaceMB(dir)
		need := uint64(2*in.Size/(1<<20)) + 64
		if in.Size == 0 {
			need = 1024 // size unknown: ask for 1 GiB of headroom
		}
		if p != nil && uint64(p.MinFreeMb) > need {
			need = uint64(p.MinFreeMb)
		}
		if ferr == nil && free < need {
			return fail("not enough free disk space: %d MB available, %d MB needed", free, need)
		}
	}
	file := filepath.Join(dir, in.FileName)
	mism, err := e.download(ctx, r.JobID, in, file)
	if err != nil {
		if mism > 0 && e.Security != nil {
			e.Security(agentv1.SecurityEventKind_SECURITY_EVENT_KIND_HASH_MISMATCH, fmt.Sprintf("job %s: downloaded content did not match the signed SHA-256", r.JobID))
		}
		if ctx.Err() != nil {
			return &outcome{res: &agentv1.JobResult{}, cancelled: true}
		}
		o := fail("download failed: %v", err)
		if mism == 0 {
			o.res.Outcome = agentv1.JobOutcome_JOB_OUTCOME_RETRYABLE // network trouble is worth retrying
		}
		return o
	}

	// 4. Verify: re-hash from a locked handle, check the signature and pin.
	lf, err := e.P.OpenLocked(file)
	if err != nil {
		return fail("cannot lock the staged installer: %v", err)
	}
	defer lf.Close()
	sum, err := hashLocked(lf)
	if err != nil || !bytes.Equal(sum, in.Sha256) {
		if e.Security != nil {
			e.Security(agentv1.SecurityEventKind_SECURITY_EVENT_KIND_HASH_MISMATCH, fmt.Sprintf("job %s: staged file changed after download", r.JobID))
		}
		return fail("the staged installer changed after it was verified")
	}
	if e.CacheFile != nil {
		e.CacheFile(file, in.Sha256)
	}
	sig, serr := e.P.VerifySignature(file)
	sigNote := "unsigned"
	switch {
	case serr != nil:
		sigNote = "signature check unavailable"
	case sig.Signed && sig.Valid:
		sigNote = "signed by " + sig.Subject
	case sig.Signed:
		sigNote = "INVALID signature: " + sig.Detail
	}
	if pin := in.SignerPin; pin != nil && (pin.Subject != "" || len(pin.ThumbprintSha256) > 0) {
		okPin := serr == nil && sig.Signed && sig.Valid &&
			(pin.Subject == "" || strings.EqualFold(sig.Subject, pin.Subject)) &&
			(len(pin.ThumbprintSha256) == 0 || bytes.Equal(pin.ThumbprintSha256, sig.Thumbprint))
		if !okPin {
			if e.Security != nil {
				e.Security(agentv1.SecurityEventKind_SECURITY_EVENT_KIND_SIGNER_MISMATCH, fmt.Sprintf("job %s: expected signer %q, got %s", r.JobID, pin.Subject, sigNote))
			}
			return fail("the installer's signature does not match the pinned signer (%s)", sigNote)
		}
	} else if sig.Signed && !sig.Valid && t != installer.MSIX {
		return fail("the installer has an invalid digital signature: %s", sig.Detail)
	}

	// 5-7. Run. Programs that are still open, or were opened again during the download, are dealt with first.
	if o := e.inUseGate(ctx, b, sid, true, &consent); o != nil {
		return o
	}
	timeout, _ := timeoutOf(b.TimeoutS)
	var rr RunResult
	switch t {
	case installer.Portable:
		msg, perr := e.installPortable(b, file)
		if perr != nil {
			return fail("%v", perr)
		}
		rr = RunResult{ExitCode: 0, LogTail: msg}
	case installer.MSIX:
		// Windows itself refuses a package whose signature it does not trust, so an unverifiable signature here is only a note.
		var merr error
		rr, merr = e.installMSIX(ctx, b, dir, file, timeout)
		if merr != nil {
			if ctx.Err() != nil {
				return &outcome{res: &agentv1.JobResult{}, cancelled: true}
			}
			return fail("could not install the MSIX package: %v", merr)
		}
	default:
		path, rt := file, t
		if t == installer.Zip {
			xdir := filepath.Join(dir, "x")
			if err := os.MkdirAll(xdir, 0o700); err != nil {
				return fail("%v", err)
			}
			if err := installer.ExtractZip(file, xdir); err != nil {
				return fail("%v", err)
			}
			path = filepath.Join(xdir, filepath.FromSlash(in.NestedPath))
			if !strings.HasPrefix(path, xdir+string(filepath.Separator)) {
				return fail("nested installer path escapes the archive")
			}
			if _, err := os.Stat(path); err != nil {
				return fail("the nested installer %q is not in the archive", in.NestedPath)
			}
			rt = typeNames[in.NestedType]
		}
		log := filepath.Join(dir, "install.log")
		exe, args, err := installer.Command(installer.Spec{Type: rt, Scope: scope, Path: path, LogPath: log, Extra: in.Args})
		if err != nil {
			return fail("%v", err)
		}
		if exe == "msiexec.exe" {
			exe = e.P.MsiExec()
		}
		spec := RunSpec{Exe: exe, Args: args, Dir: filepath.Dir(path), Timeout: timeout, LogPath: log}
		if scope == installer.User {
			spec.Helper = e.helperTask(r, dir, file)
			rr, err = e.P.RunAsUser(ctx, sid, spec)
			if errors.Is(err, ErrNoSession) {
				return &outcome{waitUser: true, res: &agentv1.JobResult{}}
			}
		} else {
			rr, err = e.P.Run(ctx, spec)
		}
		if err != nil {
			if ctx.Err() != nil {
				return &outcome{res: &agentv1.JobResult{}, cancelled: true}
			}
			return fail("could not run the installer: %v", err)
		}
		t = rt
	}
	_ = lf.Close()

	cm := map[int]installer.Outcome{}
	for code, o := range in.CodeMap {
		cm[int(code)] = installer.Outcome(o)
	}
	var success []int
	for _, c := range in.SuccessCodes {
		success = append(success, int(c))
	}
	oc := installer.Resolve(t, rr.ExitCode, success, cm)
	if rr.TimedOut {
		oc = installer.Failed
	}
	res := &agentv1.JobResult{ExitCode: int32(rr.ExitCode), LogTail: tail(rr.LogTail), // #nosec G115 -- exit codes fit int32
		Message: fmt.Sprintf("installer exit code %d (%s); %s", rr.ExitCode, oc, sigNote)}
	if rr.TimedOut {
		res.Message = fmt.Sprintf("the installer exceeded its time limit of %s and was stopped; %s", timeout, sigNote)
	}
	switch oc {
	case installer.Success:
		res.Outcome = agentv1.JobOutcome_JOB_OUTCOME_SUCCESS
	case installer.RebootRequired:
		res.Outcome = agentv1.JobOutcome_JOB_OUTCOME_REBOOT_REQUIRED
	case installer.Retryable:
		res.Outcome = agentv1.JobOutcome_JOB_OUTCOME_RETRYABLE
	default:
		res.Outcome = agentv1.JobOutcome_JOB_OUTCOME_FAILED
	}
	if res.Outcome == agentv1.JobOutcome_JOB_OUTCOME_FAILED || res.Outcome == agentv1.JobOutcome_JOB_OUTCOME_RETRYABLE {
		return &outcome{res: res, reason: "installer_failed"}
	}

	// 8. Post-detection: success without the product present is not success. (The MSIX script has already checked.)
	if t == installer.MSIX {
		res.DetectionPassed, res.InstalledVersion = true, b.Version
		return &outcome{res: res}
	}
	d2, known2, derr2 := e.Detect(b.Detection, scope, sid)
	res.DetectionPassed = !known2 || (derr2 == nil && d2.Present)
	res.InstalledVersion = d2.Version
	if known2 && derr2 == nil && !d2.Present {
		res.Outcome = agentv1.JobOutcome_JOB_OUTCOME_FAILED
		res.Message = short("the installer reported success but the product was not detected afterwards; " + res.Message)
		return &outcome{res: res, reason: "failed_detection"}
	}
	if res.Outcome == agentv1.JobOutcome_JOB_OUTCOME_REBOOT_REQUIRED {
		if note := e.restartAfterInstall(ctx, b, sid); note != "" {
			res.Message = short(res.Message + "; " + note)
		}
	}
	return &outcome{res: res}
}

// installPortable copies a single portable executable into the machine-wide
// legacy "LibrePatch" portable directory (the folder name is kept so that existing installs keep finding their portable programs).
func (e *Engine) installPortable(b *agentv1.InstallBody, file string) (string, error) {
	root := e.P.Env(installer.Machine, "", "PROGRAMFILES")
	if root == "" {
		return "", errors.New("the Program Files location is unknown")
	}
	id := safeID(b.PackageId)
	if id == "" {
		return "", errors.New("portable package needs a package identifier")
	}
	dest := filepath.Join(root, brand.FolderName, "Portable", id)
	if err := os.MkdirAll(dest, 0o755); err != nil { // #nosec G301 -- machine-wide, administrator-owned parent
		return "", err
	}
	target := filepath.Join(dest, b.Installer.FileName)
	in, err := os.Open(file) // #nosec G304 -- staged file
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755) // #nosec G302 G304 -- must be executable; path built from validated parts
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	return "copied to " + target, nil
}

func safeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() > 100 {
		return b.String()[:100]
	}
	return b.String()
}
