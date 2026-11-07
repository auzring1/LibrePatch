package jobs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/selfupdate"
	"github.com/auzring1/librepatch/internal/shared/installer"
	"github.com/auzring1/librepatch/internal/shared/release"
)

// RequestServiceRestart makes the running service process exit so the service manager starts it
// again (set by main to winsvc.RequestRestart on Windows).
var RequestServiceRestart func()

// ValidateAgentUpdate checks the shape of an AGENT_UPDATE body (the manifest itself is verified
// cryptographically when the job runs).
func ValidateAgentUpdate(env *agentv1.JobEnvelope) error {
	b := env.GetAgentUpdate()
	if env.TargetUserSid != "" {
		return bad("agent updates are machine-scope")
	}
	if b == nil || len(b.Manifest) == 0 || len(b.Manifest) > release.MaxManifestBytes || len(b.Signature) != ed25519.SignatureSize || len(b.KeyId) > 32 {
		return bad("bad agent update body")
	}
	if b.TimeoutS > 3600 {
		return bad("agent update timeout over one hour")
	}
	return nil
}

func (e *Engine) releaseKeys() []ed25519.PublicKey {
	if e.ReleaseKeys != nil {
		return e.ReleaseKeys
	}
	return release.TrustedKeys()
}

func (e *Engine) rollbackWindow() time.Duration {
	if e.RollbackWindow > 0 {
		return e.RollbackWindow
	}
	return selfupdate.RollbackWindow
}

// agentUpdate downloads, verifies and stages a vendor-signed agent release and switches the
// service to it. It returns a deferred outcome: the job is finished by SelfUpdateHealthy (new
// version proved itself) or SelfUpdateStartup (the safety net rolled back).
func (e *Engine) agentUpdate(ctx context.Context, r *Record, env *agentv1.JobEnvelope) *outcome {
	up := e.P.SelfUpdater()
	if up == nil || e.DataDir == "" || e.Version == "" {
		return fail("self-update is not available on this agent")
	}
	b := env.GetAgentUpdate()
	m, err := release.Verify(e.releaseKeys(), b.Manifest, b.Signature, hex.EncodeToString(b.KeyId))
	if err != nil {
		if e.Security != nil {
			e.Security(agentv1.SecurityEventKind_SECURITY_EVENT_KIND_BAD_SIGNATURE, fmt.Sprintf("job %s: release manifest rejected: %v", r.JobID, err))
		}
		return fail("the release is not trusted: %v", err)
	}
	if err := m.CheckApplicable(e.Version, runtime.GOOS, runtime.GOARCH); err != nil {
		return fail("%v", err)
	}
	if st, err := selfupdate.Load(e.DataDir); err == nil && st.Status == selfupdate.StatusSwitching && st.JobID != r.JobID {
		return fail("another agent update (to %s) is still being confirmed", st.ToVersion)
	}
	curSlot, curExe, err := up.Current()
	if err != nil {
		return fail("cannot determine the running slot: %v", err)
	}

	dir, err := e.P.StagingDir(installer.Machine, "", r.JobID)
	if err != nil {
		return fail("cannot create the staging directory: %v", err)
	}
	defer func() { _ = e.P.RemoveAll(dir) }()
	if free, ferr := e.P.FreeSpaceMB(dir); ferr == nil && free < 2*m.Size/(1<<20)+64 {
		return fail("not enough free disk space for the update")
	}
	file := filepath.Join(dir, "librepatch-agent.exe")
	in := &agentv1.Installer{Sha256: m.SHA256Bytes(), Size: m.Size, FileName: "librepatch-agent.exe",
		Sources: []*agentv1.ContentSource{{Kind: agentv1.ContentSourceKind_CONTENT_SOURCE_KIND_SERVER}}}
	mism, err := e.download(ctx, r.JobID, in, file)
	if err != nil {
		if mism > 0 && e.Security != nil {
			e.Security(agentv1.SecurityEventKind_SECURITY_EVENT_KIND_HASH_MISMATCH, fmt.Sprintf("job %s: agent binary did not match the signed manifest", r.JobID))
		}
		if ctx.Err() != nil {
			return &outcome{res: &agentv1.JobResult{}, cancelled: true}
		}
		o := fail("download failed: %v", err)
		if mism == 0 {
			o.res.Outcome = agentv1.JobOutcome_JOB_OUTCOME_RETRYABLE
		}
		return o
	}
	lf, err := e.P.OpenLocked(file)
	if err != nil {
		return fail("cannot lock the staged binary: %v", err)
	}
	defer lf.Close()
	if sum, err := hashLocked(lf); err != nil || !bytes.Equal(sum, in.Sha256) {
		if e.Security != nil {
			e.Security(agentv1.SecurityEventKind_SECURITY_EVENT_KIND_HASH_MISMATCH, fmt.Sprintf("job %s: staged agent binary changed after download", r.JobID))
		}
		return fail("the staged binary changed after it was verified")
	}
	if m.AuthenticodeSubject != "" {
		sig, serr := e.P.VerifySignature(file)
		if serr != nil || !sig.Signed || !sig.Valid || !strings.EqualFold(sig.Subject, m.AuthenticodeSubject) {
			if e.Security != nil {
				e.Security(agentv1.SecurityEventKind_SECURITY_EVENT_KIND_SIGNER_MISMATCH, fmt.Sprintf("job %s: agent binary is not signed by %q", r.JobID, m.AuthenticodeSubject))
			}
			return fail("the agent binary is not signed by the release's pinned signer (%s)", m.AuthenticodeSubject)
		}
	}
	// The binary must say it is the version the manifest promised (catches a wrong file early,
	// before the service is pointed at it).
	if run, err := e.P.Run(ctx, RunSpec{Exe: file, Args: []string{"version"}, Dir: dir, Timeout: time.Minute}); err != nil || run.ExitCode != 0 ||
		!strings.HasPrefix(strings.TrimSpace(run.LogTail), brand.VersionBanner+" "+m.Version+" ") {
		return fail("the staged binary does not report version %s", m.Version)
	}

	slot, exe, err := up.StageInactive(file)
	if err != nil {
		return fail("cannot stage the new version: %v", err)
	}
	now := e.now()
	st := &selfupdate.State{JobID: r.JobID, FromVersion: e.Version, ToVersion: m.Version, FromSlot: curSlot, ToSlot: slot,
		FromExe: curExe, ToExe: exe, StartedAt: now.Unix(), Deadline: now.Add(e.rollbackWindow()).Unix(), Status: selfupdate.StatusSwitching}
	// Never switch without the safety net: arm the rollback first, and fail if that is impossible.
	if err := selfupdate.Save(e.DataDir, st); err != nil {
		return fail("cannot record the update: %v", err)
	}
	if err := up.ScheduleRollback(time.Unix(st.Deadline, 0), curExe); err != nil {
		_ = selfupdate.Clear(e.DataDir)
		return fail("cannot arm the rollback safety net, update not started: %v", err)
	}
	if err := up.Switch(slot); err != nil {
		_ = up.CancelRollback()
		_ = selfupdate.Clear(e.DataDir)
		return fail("cannot switch the service to the new version: %v", err)
	}
	e.log().Info("agent update staged; restarting into the new version", "from", e.Version, "to", m.Version, "slot", slot)
	r.AwaitRestart = true
	e.setState(r, agentv1.JobState_JOB_STATE_RUNNING, "restarting_into_"+m.Version, nil)
	if err := up.Restart(); err != nil {
		// Could not restart ourselves: the service now points at the new slot and will switch at
		// its next start; the safety net still covers us.
		e.log().Warn("restart request failed; the new version starts at the next service restart", "err", err)
	}
	return &outcome{deferred: true}
}

// finishAwait ends a job that was waiting for the restart.
func (e *Engine) finishAwait(jobID string, ok bool, msg string) {
	r := load(e.Store, jobID)
	if r == nil || !r.AwaitRestart {
		return
	}
	r.AwaitRestart = false
	r.Finished = e.now().Unix()
	if ok {
		e.setState(r, agentv1.JobState_JOB_STATE_SUCCEEDED, "", &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS,
			Message: short(msg), InstalledVersion: e.Version, StartedAt: r.Started, FinishedAt: r.Finished})
		return
	}
	e.setState(r, agentv1.JobState_JOB_STATE_FAILED, "rolled_back", &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_FAILED,
		Message: short(msg), StartedAt: r.Started, FinishedAt: r.Finished})
}

// SelfUpdateStartup runs when the agent starts: it reports the outcome of an update that was
// rolled back, and clears stale state.
func (e *Engine) SelfUpdateStartup() {
	if e.DataDir == "" {
		return
	}
	st, err := selfupdate.Load(e.DataDir)
	if err != nil {
		return
	}
	switch {
	case st.Status == selfupdate.StatusRolledBack && e.Version == st.FromVersion:
		e.log().Warn("the agent update was rolled back", "to", st.ToVersion, "reason", st.Message)
		e.finishAwait(st.JobID, false, st.Message)
		_ = selfupdate.Clear(e.DataDir)
	case st.Status == selfupdate.StatusHealthy && e.Version == st.ToVersion:
		// Healthy was recorded but the report may not have been; finish it now (idempotent).
		e.finishAwait(st.JobID, true, "updated from "+st.FromVersion+" to "+st.ToVersion)
		_ = selfupdate.Clear(e.DataDir)
	case st.Status == selfupdate.StatusSwitching && e.Version != st.ToVersion && e.Version != st.FromVersion:
		// Neither of the versions involved: the state is stale (manual reinstall). Drop it.
		if up := e.P.SelfUpdater(); up != nil {
			_ = up.CancelRollback()
		}
		e.finishAwait(st.JobID, false, "the agent was replaced while an update was in progress")
		_ = selfupdate.Clear(e.DataDir)
	}
}

// SelfUpdateHealthy is called by the agent core after the first successful server handshake of
// this process. If this process is the version an update switched to, the update is confirmed:
// the rollback task is disarmed and the job succeeds.
func (e *Engine) SelfUpdateHealthy() {
	if e.DataDir == "" {
		return
	}
	st, err := selfupdate.Load(e.DataDir)
	if err != nil || st.Status != selfupdate.StatusSwitching || st.ToVersion != e.Version {
		return
	}
	st.Status = selfupdate.StatusHealthy
	if err := selfupdate.Save(e.DataDir, st); err != nil {
		e.log().Error("record healthy update", "err", err)
		return
	}
	if up := e.P.SelfUpdater(); up != nil {
		if err := up.CancelRollback(); err != nil {
			e.log().Warn("could not remove the rollback task", "err", err)
		}
	}
	e.log().Info("agent update confirmed", "from", st.FromVersion, "to", st.ToVersion)
	e.finishAwait(st.JobID, true, "updated from "+st.FromVersion+" to "+st.ToVersion)
	_ = selfupdate.Clear(e.DataDir)
}
