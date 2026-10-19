package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/wu"
)

// Windows Update jobs (docs/ARCHITECTURE.md §9): scan, install exactly the listed updates, hide or
// unhide, and restart according to the signed reboot policy.

const (
	metaWUOpts = "wu_opts" // the options of the last scan/install job, reused by the automatic scan
	metaWUNext = "wu_next" // unix time of the next automatic scan
)

func wuOptions(service agentv1.WuService, drivers bool) wu.Options {
	return wu.Options{Service: service, IncludeDrivers: drivers}
}

// storedWUOptions returns the options of the last WU job (default: the machine's own source, no drivers).
func (e *Engine) storedWUOptions() wu.Options {
	var b agentv1.WuScanBody
	if raw := e.Store.GetMeta(metaWUOpts); len(raw) > 0 && proto.Unmarshal(raw, &b) == nil {
		return wuOptions(b.Service, b.IncludeDrivers)
	}
	return wuOptions(agentv1.WuService_WU_SERVICE_DEFAULT, false)
}

func (e *Engine) saveWUOptions(o wu.Options) {
	if raw, err := proto.Marshal(&agentv1.WuScanBody{Service: o.Service, IncludeDrivers: o.IncludeDrivers}); err == nil {
		_ = e.Store.SetMeta(metaWUOpts, raw)
	}
}

// scanAndReport scans and hands the snapshot (also a failed one, carrying the error) to the agent
// core for delivery. It returns the snapshot.
func (e *Engine) scanAndReport(ctx context.Context, o wu.Options) *agentv1.WuInventory {
	c := e.P.WindowsUpdate()
	ups, err := c.Scan(ctx, o)
	snap := wu.Snapshot(ups, c.Policy(), e.P.RebootRequired(), o, err, e.now())
	if e.WUReport != nil {
		e.WUReport(snap)
	}
	return snap
}

func (e *Engine) wuScan(ctx context.Context, env *agentv1.JobEnvelope) *outcome {
	b := env.GetWuScan()
	o := wuOptions(b.Service, b.IncludeDrivers)
	if !b.OneOff { // a one-off check must not change what the daily scan uses
		e.saveWUOptions(o)
	}
	snap := e.scanAndReport(ctx, o)
	if snap.ScanError != "" {
		return &outcome{reason: "wu_scan_failed", res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_FAILED, Message: short("scan failed: " + snap.ScanError)}}
	}
	var missing, hidden int
	for _, u := range snap.Updates {
		switch u.State {
		case agentv1.WuUpdateState_WU_UPDATE_STATE_HIDDEN:
			hidden++
		case agentv1.WuUpdateState_WU_UPDATE_STATE_PENDING_REBOOT:
		default:
			missing++
		}
	}
	return &outcome{res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, DetectionPassed: true, RebootRequired: snap.RebootRequired,
		Message: fmt.Sprintf("%d update(s) available, %d hidden", missing, hidden)}}
}

func (e *Engine) wuInstall(ctx context.Context, env *agentv1.JobEnvelope) *outcome {
	b := env.GetWuInstall()
	o := wuOptions(b.Service, b.IncludeDrivers)
	if !b.OneOff {
		e.saveWUOptions(o)
	}
	timeout, _ := timeoutOf(b.TimeoutS)
	ictx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, err := e.P.WindowsUpdate().Install(ictx, o, b.Updates)
	if err != nil {
		switch {
		case ctx.Err() != nil:
			return &outcome{res: &agentv1.JobResult{}, cancelled: true}
		case errors.Is(ictx.Err(), context.DeadlineExceeded):
			return fail("the installation did not finish within %s", timeout)
		case errors.Is(err, wu.ErrUnavailable):
			return &outcome{reason: "wu_unavailable", res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_RETRYABLE, Message: short(err.Error())}}
		}
		return fail("Windows Update failed: %v", err)
	}
	var installed, failed, na, dlfail int
	for _, r := range res.Results {
		switch r.Result {
		case agentv1.WuResult_WU_RESULT_INSTALLED, agentv1.WuResult_WU_RESULT_INSTALLED_REBOOT:
			installed++
		case agentv1.WuResult_WU_RESULT_NOT_APPLICABLE:
			na++
		case agentv1.WuResult_WU_RESULT_DOWNLOAD_FAILED:
			dlfail++
			failed++
		default:
			failed++
		}
	}
	jr := &agentv1.JobResult{WuResults: res.Results, DetectionPassed: failed == 0}
	msg := fmt.Sprintf("%d installed, %d failed, %d no longer applicable", installed, failed, na)
	reboot := res.RebootRequired || e.P.RebootRequired()
	if reboot && installed > 0 {
		jr.RebootRequired = true
		msg += "; a restart is required"
		if when := e.scheduleReboot(b.Reboot, "Windows updates were installed and a restart is needed to finish.", false); when != "" {
			msg += " (" + when + ")"
		}
	}
	jr.Message = short(msg)
	// Show the new state without waiting for the next scheduled scan.
	e.scanAndReport(ctx, o)
	switch {
	case failed > 0 && installed == 0 && dlfail == failed:
		jr.Outcome = agentv1.JobOutcome_JOB_OUTCOME_RETRYABLE // nothing could be downloaded: likely the network
		return &outcome{res: jr, reason: "wu_download_failed"}
	case failed > 0:
		jr.Outcome = agentv1.JobOutcome_JOB_OUTCOME_FAILED
		return &outcome{res: jr, reason: "wu_partial_failure"}
	case jr.RebootRequired:
		jr.Outcome = agentv1.JobOutcome_JOB_OUTCOME_REBOOT_REQUIRED
	default:
		jr.Outcome = agentv1.JobOutcome_JOB_OUTCOME_SUCCESS
		jr.AlreadySatisfied = installed == 0
	}
	return &outcome{res: jr}
}

func (e *Engine) wuHide(ctx context.Context, env *agentv1.JobEnvelope) *outcome {
	b := env.GetWuHide()
	o := wuOptions(b.Service, false)
	if err := e.P.WindowsUpdate().Hide(ctx, o, b.Updates, b.Hide); err != nil {
		return fail("could not change visibility: %v", err)
	}
	e.scanAndReport(ctx, e.storedWUOptions())
	verb := "hidden"
	if !b.Hide {
		verb = "unhidden"
	}
	return &outcome{res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, DetectionPassed: true, Message: fmt.Sprintf("%d update(s) %s", len(b.Updates), verb)}}
}

func (e *Engine) rebootJob(env *agentv1.JobEnvelope) *outcome {
	b := env.GetReboot()
	reason := b.Reason
	if reason == "" {
		reason = "An administrator requested a restart."
	}
	when := e.scheduleReboot(b.Reboot, reason, true)
	if when == "" {
		return fail("the reboot policy does not allow a restart")
	}
	return &outcome{res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, DetectionPassed: true, Message: short("restart scheduled: " + when)}}
}

// autoScan runs the periodic scan (default every 24 h, first one a few minutes after start) so the
// console knows what each device is missing without anyone asking. It returns when to look again.
func (e *Engine) autoScan(ctx context.Context) time.Time {
	every := e.WUScanEvery
	if every <= 0 || !e.allowedName("wu_scan") {
		return time.Time{}
	}
	now := e.now()
	if raw := e.Store.GetMeta(metaWUNext); len(raw) > 0 {
		at, _ := strconv.ParseInt(string(raw), 10, 64) // unreadable = scan now
		if t := time.Unix(at, 0); now.Before(t) {
			return t
		}
	} else {
		first := now.Add(time.Duration(30+rand.IntN(270)) * time.Second) // #nosec G404 -- jitter, not security
		_ = e.Store.SetMeta(metaWUNext, []byte(fmt.Sprint(first.Unix())))
		return first
	}
	e.scanAndReport(ctx, e.storedWUOptions())
	next := now.Add(every + time.Duration(rand.Int64N(int64(every/12)+1))) // #nosec G404 -- jitter, not security
	_ = e.Store.SetMeta(metaWUNext, []byte(fmt.Sprint(next.Unix())))
	return next
}

// ScanNow runs a scan immediately with the stored options (used when the server's snapshot is stale).
func (e *Engine) ScanNow(ctx context.Context) *agentv1.WuInventory {
	if !e.allowedName("wu_scan") {
		return nil
	}
	return e.scanAndReport(ctx, e.storedWUOptions())
}

func (e *Engine) allowedName(name string) bool {
	return len(e.Allowed) == 0 || e.Allowed[name]
}

// ---- restart plan ----

const metaRebootPlan = "reboot_plan"

// rebootPlan is a restart the agent has promised to perform, kept across service restarts.
type rebootPlan struct {
	Due       int64    `json:"due"`        // unix seconds at which the countdown starts
	NotifyMin uint32   `json:"notify_min"` // countdown length
	Reason    string   `json:"reason"`
	Force     bool     `json:"force"`            // an administrator asked for it: do not cancel when nothing is pending
	Active    []uint32 `json:"active,omitempty"` // active hours [start, end] checked again when the plan fires
	Fired     int64    `json:"fired,omitempty"`
}

func (e *Engine) loadRebootPlan() *rebootPlan {
	raw := e.Store.GetMeta(metaRebootPlan)
	if len(raw) == 0 {
		return nil
	}
	var p rebootPlan
	if jsonUnmarshal(raw, &p) != nil {
		return nil
	}
	return &p
}

func (e *Engine) saveRebootPlan(p *rebootPlan) {
	if p == nil {
		_ = e.Store.SetMeta(metaRebootPlan, nil)
		return
	}
	if raw, err := jsonMarshal(p); err == nil {
		_ = e.Store.SetMeta(metaRebootPlan, raw)
	}
}

// scheduleReboot records the restart that policy allows and returns a human description of when it
// will happen ("" = the policy forbids a restart). Without force an existing earlier plan wins.
func (e *Engine) scheduleReboot(pol *agentv1.RebootPolicy, reason string, force bool) string {
	if pol == nil {
		return ""
	}
	e.rebootMu.Lock()
	defer e.rebootMu.Unlock()
	now := e.now()
	notify := pol.NotifyMinutes
	if notify == 0 {
		notify = 5
	}
	var due time.Time
	var active []uint32
	switch pol.Allow {
	case agentv1.RebootAllow_REBOOT_ALLOW_NOW:
		due = now
	case agentv1.RebootAllow_REBOOT_ALLOW_OUTSIDE_ACTIVE_HOURS:
		due = wu.NextOutsideActiveHours(pol.ActiveHours, now, e.local())
		if pol.ActiveHours != nil {
			active = []uint32{pol.ActiveHours.StartMinute, pol.ActiveHours.EndMinute}
		}
	case agentv1.RebootAllow_REBOOT_ALLOW_DEADLINE:
		due = time.Unix(pol.DeadlineAt, 0).Add(-time.Duration(notify) * time.Minute)
		if due.Before(now) {
			due = now
		}
	default:
		return ""
	}
	if cur := e.loadRebootPlan(); cur != nil && cur.Fired == 0 && time.Unix(cur.Due, 0).Before(due) && !force {
		return "a restart is already scheduled for " + time.Unix(cur.Due, 0).In(e.local()).Format("Mon 15:04")
	}
	e.saveRebootPlan(&rebootPlan{Due: due.Unix(), NotifyMin: notify, Reason: reason, Force: force, Active: active})
	if !due.After(now) {
		return fmt.Sprintf("restarting in %d minute(s)", notify)
	}
	return "restart scheduled for " + due.In(e.local()).Format("Mon 15:04")
}

// checkReboot starts the countdown of a due plan and returns when the next plan comes due.
func (e *Engine) checkReboot() time.Time {
	if e.unsafe.Load() > 0 {
		return time.Time{} // an installer or update is running; runJob wakes the loops when it ends
	}
	e.rebootMu.Lock()
	defer e.rebootMu.Unlock()
	p := e.loadRebootPlan()
	if p == nil {
		return time.Time{}
	}
	now := e.now()
	if p.Fired > 0 {
		// The restart was started. Once the service is running again (or the countdown was aborted
		// and nothing is pending) the plan has served its purpose.
		if now.Unix()-p.Fired > int64((2*time.Hour).Seconds()) || !e.P.RebootRequired() {
			e.saveRebootPlan(nil)
		}
		return time.Time{}
	}
	if !p.Force && !e.P.RebootRequired() {
		e.saveRebootPlan(nil) // the user restarted already
		return time.Time{}
	}
	if due := time.Unix(p.Due, 0); now.Before(due) {
		return due
	}
	if len(p.Active) == 2 { // never start the countdown inside active hours
		ah := &agentv1.ActiveHours{StartMinute: p.Active[0], EndMinute: p.Active[1]}
		if wu.InActiveHours(ah, now, e.local()) {
			next := wu.NextOutsideActiveHours(ah, now, e.local())
			p.Due = next.Unix()
			e.saveRebootPlan(p)
			return next
		}
	}
	msg := strings.TrimSpace(p.Reason)
	if msg == "" {
		msg = "Your computer will restart to finish installing updates."
	}
	msg = fmt.Sprintf("%s Please save your work. The restart starts in %d minute(s).", msg, p.NotifyMin)
	switch err := e.P.Reboot(time.Duration(p.NotifyMin)*time.Minute, msg); {
	case err == nil:
		e.log().Info("restart countdown started", "minutes", p.NotifyMin)
	case errors.Is(err, ErrRebootScheduled):
		// A countdown is already running (the same restart asked for twice). Starting another would restart the
		// computer a second time after it comes back, so this plan simply joins the running one.
		e.log().Info("a restart is already scheduled; not starting another")
	default:
		e.log().Error("restart failed", "err", err)
		p.Due = now.Add(10 * time.Minute).Unix() // try again later
		e.saveRebootPlan(p)
		return time.Unix(p.Due, 0)
	}
	p.Fired = now.Unix()
	e.saveRebootPlan(p)
	return time.Time{}
}

func jsonMarshal(v any) ([]byte, error)   { return json.Marshal(v) }
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
