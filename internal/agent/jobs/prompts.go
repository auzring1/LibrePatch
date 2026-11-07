package jobs

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"github.com/auzring1/librepatch/internal/shared/installer"
)

// Optional messages to the signed-in user during a software installation (D124). Everything here is opt-in: a job
// without InstallPrompts, or with in_use IGNORE and restart NONE, runs exactly as before, silently.

// Limits of InstallPrompts.
const (
	defaultAskTimeout = 5 * time.Minute
	defaultDefer      = time.Hour
	defaultRestartMin = 5
	closeGrace        = 30 * time.Second // how long a program gets to close itself before it is ended
)

// validatePrompts checks the optional prompts of an install body.
func validatePrompts(p *agentv1.InstallPrompts) error {
	if p == nil {
		return nil
	}
	switch p.InUse {
	case agentv1.InUseAction_IN_USE_ACTION_UNSPECIFIED, agentv1.InUseAction_IN_USE_ACTION_IGNORE:
	case agentv1.InUseAction_IN_USE_ACTION_SKIP, agentv1.InUseAction_IN_USE_ACTION_ASK, agentv1.InUseAction_IN_USE_ACTION_CLOSE:
		if len(p.Processes) == 0 {
			return bad("name the programs to wait for, ask about or close")
		}
	default:
		return bad("unknown in-use action")
	}
	switch p.Restart {
	case agentv1.RestartPrompt_RESTART_PROMPT_UNSPECIFIED, agentv1.RestartPrompt_RESTART_PROMPT_NONE,
		agentv1.RestartPrompt_RESTART_PROMPT_ASK, agentv1.RestartPrompt_RESTART_PROMPT_COUNTDOWN:
	default:
		return bad("unknown restart prompt")
	}
	if err := installer.ValidateProcessNames(p.Processes); err != nil {
		return bad("%v", err)
	}
	if p.AskTimeoutS != 0 && (p.AskTimeoutS < 30 || p.AskTimeoutS > 3600) {
		return bad("the question stays up 30 to 3600 seconds")
	}
	if p.DeferMinutes != 0 && (p.DeferMinutes < 5 || p.DeferMinutes > 1440) {
		return bad("the wait before looking again is 5 to 1440 minutes")
	}
	if p.RestartNotifyMinutes > 1440 {
		return bad("restart notice over 24 hours")
	}
	return nil
}

func askTimeout(p *agentv1.InstallPrompts) time.Duration {
	if p.GetAskTimeoutS() == 0 {
		return defaultAskTimeout
	}
	return time.Duration(p.AskTimeoutS) * time.Second
}

func deferFor(p *agentv1.InstallPrompts) time.Duration {
	if p.GetDeferMinutes() == 0 {
		return defaultDefer
	}
	return time.Duration(p.DeferMinutes) * time.Minute
}

// sleep waits d or until ctx ends.
func (e *Engine) sleep(ctx context.Context, d time.Duration) {
	if e.Sleep != nil {
		e.Sleep(ctx, d)
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (e *Engine) pollEvery() time.Duration {
	if e.PromptPoll > 0 {
		return e.PromptPoll
	}
	return 5 * time.Second
}

// openPrograms lists the named programs that are running in a signed-in user's session (session 0 belongs to
// services and is never touched). A platform that cannot tell reports nothing, and the install goes ahead as it
// always did.
func (e *Engine) openPrograms(p *agentv1.InstallPrompts, sid string) []Proc {
	procs, err := e.P.RunningProcesses(p.Processes, sid)
	if err != nil {
		e.log().Warn("cannot list running programs; installing without waiting for them", "err", err)
		return nil
	}
	var out []Proc
	for _, x := range procs {
		if x.Session != 0 && !installer.ProtectedProcess(x.Name) {
			out = append(out, x)
		}
	}
	return out
}

func procNames(procs []Proc) string {
	seen := map[string]bool{}
	var names []string
	for _, p := range procs {
		k := strings.ToLower(p.Name)
		if !seen[k] {
			seen[k] = true
			names = append(names, p.Name)
		}
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func sessionsOf(procs []Proc) []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	for _, p := range procs {
		if !seen[p.Session] {
			seen[p.Session] = true
			out = append(out, p.Session)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// later is the outcome of a job that has to wait for the programs to be closed. It does not use up a retry: the
// job keeps looking until it expires.
func (e *Engine) later(p *agentv1.InstallPrompts, reason string, procs []Proc) *outcome {
	return &outcome{res: &agentv1.JobResult{}, waitUntil: e.now().Add(deferFor(p)).Unix(), waitReason: reason + ": " + text40(procNames(procs))}
}

func text40(s string) string {
	if len(s) > 80 {
		return s[:80]
	}
	return s
}

func appLabel(b *agentv1.InstallBody) string {
	if b.Name != "" {
		return b.Name
	}
	return b.PackageId
}

// inUseGate handles programs that are open while a package is about to be installed. It returns nil to go on with
// the installation, or an outcome that waits for later (or fails). The first call runs before the download, where
// only the cheap decisions are made (SKIP waits, ASK asks); the second runs right before the installer, where
// ASK-approved and CLOSE programs are closed. consent carries the user's Yes from the first call to the second.
func (e *Engine) inUseGate(ctx context.Context, b *agentv1.InstallBody, sid string, late bool, consent *bool) *outcome {
	p := b.Prompts
	act := p.GetInUse()
	if act == agentv1.InUseAction_IN_USE_ACTION_UNSPECIFIED || act == agentv1.InUseAction_IN_USE_ACTION_IGNORE || len(p.Processes) == 0 {
		return nil
	}
	if !late && act == agentv1.InUseAction_IN_USE_ACTION_CLOSE {
		return nil // closing happens once the installer is ready
	}
	procs := e.openPrograms(p, sid)
	if len(procs) == 0 {
		return nil
	}
	switch act {
	case agentv1.InUseAction_IN_USE_ACTION_SKIP:
		return e.later(p, "waiting_app_closed", procs)
	case agentv1.InUseAction_IN_USE_ACTION_ASK:
		if !*consent {
			for _, s := range sessionsOf(procs) {
				msg := fmt.Sprintf("%s needs to be updated, and %s must be closed first.\n\nSave your work, then choose Yes to close %s and update now. Choose No to update later.",
					appLabel(b), procNames(procs), procNames(procs))
				ans, err := e.P.Ask(ctx, s, brand.Name, msg, askTimeout(p), true)
				if ctx.Err() != nil {
					return &outcome{res: &agentv1.JobResult{}, cancelled: true}
				}
				if err != nil || ans != AnswerYes {
					reason := "postponed_by_user"
					if err != nil || ans == AnswerTimeout {
						reason = "no_answer_from_user"
					}
					return e.later(p, reason, procs)
				}
			}
			*consent = true
		}
		if !late {
			return nil
		}
		return e.closeOpen(ctx, p, procs)
	case agentv1.InUseAction_IN_USE_ACTION_CLOSE:
		for _, s := range sessionsOf(procs) {
			msg := fmt.Sprintf("%s is being updated. %s will be closed in %d minute(s) so the update can finish.\n\nPlease save your work now.",
				appLabel(b), procNames(procs), int((askTimeout(p)+59*time.Second)/time.Minute))
			_, _ = e.P.Ask(ctx, s, brand.Name, msg, askTimeout(p), false)
		}
		// Give people the time they were promised, but stop as soon as the programs are closed.
		deadline := e.now().Add(askTimeout(p))
		for e.now().Before(deadline) && ctx.Err() == nil {
			e.sleep(ctx, e.pollEvery())
			if procs = e.openPrograms(p, sid); len(procs) == 0 {
				return nil
			}
		}
		if ctx.Err() != nil {
			return &outcome{res: &agentv1.JobResult{}, cancelled: true}
		}
		return e.closeOpen(ctx, p, procs)
	}
	return nil
}

// closeOpen asks the programs to close and ends what is still open after a short grace period.
func (e *Engine) closeOpen(ctx context.Context, p *agentv1.InstallPrompts, procs []Proc) *outcome {
	left, err := e.P.CloseProcesses(ctx, procs, closeGrace)
	if ctx.Err() != nil {
		return &outcome{res: &agentv1.JobResult{}, cancelled: true}
	}
	if err != nil || len(left) > 0 {
		if err != nil {
			e.log().Warn("could not close programs", "err", err)
		}
		if len(left) == 0 {
			left = procs
		}
		return e.later(p, "app_would_not_close", left)
	}
	return nil
}

// restartAfterInstall applies the restart prompt of a package whose installer asked for a restart, and returns a
// sentence for the job message ("" = nothing was done, the machine just reports "restart required").
func (e *Engine) restartAfterInstall(ctx context.Context, b *agentv1.InstallBody, sid string) string {
	p := b.Prompts
	mins := p.GetRestartNotifyMinutes()
	if mins == 0 {
		mins = defaultRestartMin
	}
	reason := fmt.Sprintf("%s was updated and a restart is needed to finish.", appLabel(b))
	switch p.GetRestart() {
	case agentv1.RestartPrompt_RESTART_PROMPT_COUNTDOWN:
		return e.scheduleReboot(&agentv1.RebootPolicy{Allow: agentv1.RebootAllow_REBOOT_ALLOW_NOW, NotifyMinutes: mins}, reason, true)
	case agentv1.RestartPrompt_RESTART_PROMPT_ASK:
		session, ok := e.P.UserSession(sid)
		if !ok {
			return "restart needed; nobody is signed in to ask, so it was left for later"
		}
		msg := fmt.Sprintf("%s was updated. Your computer needs to restart to finish.\n\nSave your work, then choose Yes to restart in %d minute(s). Choose No to restart later.", appLabel(b), mins)
		ans, err := e.P.Ask(ctx, session, brand.Name, msg, askTimeout(p), true)
		if err != nil || ans != AnswerYes {
			return "restart needed; the user chose to restart later"
		}
		return e.scheduleReboot(&agentv1.RebootPolicy{Allow: agentv1.RebootAllow_REBOOT_ALLOW_NOW, NotifyMinutes: mins}, reason, true)
	}
	return ""
}
