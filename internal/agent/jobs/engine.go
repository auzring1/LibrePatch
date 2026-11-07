package jobs

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/shared/text"
)

// Reporter delivers job updates to the server. The agent core implements it on
// top of the persistent outbox, so updates survive reconnects and restarts.
type Reporter interface {
	Report(u *agentv1.JobUpdate)
}

// Engine runs accepted jobs one at a time.
type Engine struct {
	P      Platform
	Store  Store
	Report Reporter
	Fetch  Fetcher
	Log    *slog.Logger
	// Now is the server-corrected clock.
	Now func() time.Time
	// Local is the device time zone for maintenance windows (default time.Local).
	Local *time.Location
	// Allowed is the local policy ceiling (job type names). Empty = all implemented types.
	Allowed map[string]bool
	// Security reports a security event (hash or signer mismatch, ceiling violation).
	Security func(kind agentv1.SecurityEventKind, detail string)
	// InventoryNow requests an immediate software rescan (after installs and on INVENTORY_FULL jobs).
	InventoryNow func()
	// WUReport delivers a Windows Update snapshot (after a scan or install) to the agent core.
	WUReport func(snap *agentv1.WuInventory)
	// WUScanEvery is the interval of the automatic Windows Update scan (0 = off).
	WUScanEvery time.Duration
	// PollUserJobs is the fallback interval for waiting-for-logon jobs (default 15 min).
	PollUserJobs time.Duration
	// MaxIdle bounds how long the loop sleeps without any wake source (default 5 min).
	MaxIdle time.Duration
	// DataDir, Version and ReleaseKeys support agent self-update. ReleaseKeys defaults to the
	// vendor keys compiled into the binary (tests inject their own).
	DataDir     string
	Version     string
	ReleaseKeys []ed25519.PublicKey
	// RollbackWindow overrides the time a new version has to become healthy (tests).
	RollbackWindow time.Duration
	// LocalNets and SendUDP are the network of this computer and how a packet leaves it (Wake-on-LAN; tests replace both).
	LocalNets func() []LocalNet
	SendUDP   func(local net.IP, dest string, pkt []byte) error
	// ScriptsEnabled: running scripts is not switched off on this computer (Config.NoScripts). Without it every script job is
	// refused, whatever the ceiling says.
	ScriptsEnabled bool
	// CacheFile, if set, is told about every installer that passed the hash check, so it can be kept for other computers.
	CacheFile func(path string, sha []byte)
	// Sleep waits d (default: a timer that ends with ctx). Tests replace it to move a fake clock.
	Sleep func(ctx context.Context, d time.Duration)
	// PromptPoll is how often the engine looks whether programs it asked a user to close are gone (default 5 s).
	PromptPoll time.Duration
	// Trust returns the pinned root, job-signing certificates and identity the
	// user-context helper needs to re-verify a job.
	Trust func() (root []byte, signing [][]byte, deviceID, orgID string)

	mu       sync.Mutex
	wakes    map[lane]chan struct{} // wake one loop per lane (see lane)
	cancels  map[string]context.CancelFunc
	rebootMu sync.Mutex   // guards the stored restart plan: both loops read and write it
	unsafe   atomic.Int32 // jobs running now that a restart would interrupt (installs, uninstalls, updates)
}

// lane selects which accepted jobs a loop works on (D152). Jobs that have nothing to do with each other run side by side:
// a click on Refresh must not wait for an uninstaller, a restart request must not wait for a Windows Update scan, and a
// script must not hold up either. Within one lane jobs run one at a time, in the order they were due.
//
// The installing lane is one on purpose: installers, removals, Windows Update installs and agent updates all drive the
// same Windows Installer / servicing machinery, which allows one of them at a time (a second one is answered with "another
// installation is in progress").
type lane uint8

const (
	laneAll       lane = iota // every job: single-step use and tests
	laneMain                  // installs, updates, removals, Windows Update installs and hiding, agent updates
	laneControl               // restart requests and the restart countdown, wake-up packets, read-only views
	laneInventory             // "refresh device information"
	laneScan                  // Windows Update scans, and the daily one
	laneScript                // scripts
)

// workLanes are the lanes that run on a loop of their own.
var workLanes = []lane{laneMain, laneControl, laneInventory, laneScan, laneScript}

// laneOf says which lane a job type belongs to.
func laneOf(t agentv1.JobType) lane {
	switch t {
	case agentv1.JobType_JOB_TYPE_REBOOT, agentv1.JobType_JOB_TYPE_WAKE, agentv1.JobType_JOB_TYPE_INSPECT:
		return laneControl
	case agentv1.JobType_JOB_TYPE_INVENTORY_FULL:
		return laneInventory
	case agentv1.JobType_JOB_TYPE_WU_SCAN:
		return laneScan
	case agentv1.JobType_JOB_TYPE_RUN_SCRIPT:
		return laneScript
	}
	return laneMain
}

func (l lane) handles(t agentv1.JobType) bool { return l == laneAll || laneOf(t) == l }

// interruptedByRestart reports whether a restart would break a job of this type halfway.
func interruptedByRestart(t agentv1.JobType) bool {
	switch t {
	case agentv1.JobType_JOB_TYPE_SOFTWARE_INSTALL, agentv1.JobType_JOB_TYPE_SOFTWARE_UPDATE, agentv1.JobType_JOB_TYPE_SOFTWARE_UNINSTALL,
		agentv1.JobType_JOB_TYPE_WU_INSTALL, agentv1.JobType_JOB_TYPE_AGENT_UPDATE, agentv1.JobType_JOB_TYPE_RUN_SCRIPT, agentv1.JobType_JOB_TYPE_PROFILE_DELETE:
		return true
	}
	return false
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}

func (e *Engine) local() *time.Location {
	if e.Local != nil {
		return e.Local
	}
	return time.Local
}

func (e *Engine) init() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.wakes == nil {
		e.wakes = map[lane]chan struct{}{}
		for _, l := range workLanes {
			e.wakes[l] = make(chan struct{}, 1)
		}
		e.cancels = map[string]context.CancelFunc{}
	}
}

// Wake makes every loop re-evaluate its queue.
func (e *Engine) Wake() {
	e.init()
	for _, l := range workLanes {
		e.wakeLane(l)
	}
}

// wakeLane makes one loop re-evaluate its queue: a new job only needs to wake the lane it will run in.
func (e *Engine) wakeLane(l lane) {
	e.init()
	select {
	case e.wakes[l] <- struct{}{}:
	default:
	}
}

func (e *Engine) allowed(t agentv1.JobType) bool {
	name := ceilingName(t)
	if name == "" {
		return false
	}
	if t == agentv1.JobType_JOB_TYPE_RUN_SCRIPT {
		// Scripts are on unless the computer's owner switched them off, but a ceiling that is set must name them.
		return e.ScriptsEnabled && (len(e.Allowed) == 0 || e.Allowed[name])
	}
	if len(e.Allowed) == 0 {
		return true
	}
	return e.Allowed[name]
}

func (e *Engine) report(r *Record, res *agentv1.JobResult) {
	if e.Report == nil {
		return
	}
	e.Report.Report(&agentv1.JobUpdate{JobId: r.JobID, Attempt: r.Attempt, State: r.state(), Reason: r.Reason, Result: res})
}

func (e *Engine) setState(r *Record, st agentv1.JobState, reason string, res *agentv1.JobResult) {
	changed := r.state() != st || r.Reason != reason
	r.State, r.Reason = int32(st), reason
	if res != nil {
		if b, err := marshal(res); err == nil {
			r.Result = b
		}
	}
	if err := save(e.Store, r); err != nil {
		e.log().Error("persist job", "job", r.JobID, "err", err)
	}
	if changed || res != nil {
		e.report(r, res)
	}
}

// Accept takes a verified envelope. It validates the body, applies the policy
// ceiling, persists the job and reports ACCEPTED (or REJECTED). A job that is
// already known is not an attack: the server re-offers jobs whose
// acknowledgement it never saw, so the current state is simply reported again.
func (e *Engine) Accept(se *agentv1.SignedEnvelope, env *agentv1.JobEnvelope) {
	e.init()
	if r := load(e.Store, env.JobId); r != nil {
		e.report(r, r.result())
		return
	}
	r := &Record{JobID: env.JobId, Type: int32(env.Type), SID: env.TargetUserSid, Attempt: env.Attempt, Accepted: e.now().Unix(),
		NotBefore: env.NotBefore, Expires: env.ExpiresAt, Keep: env.ExpiresAt + int64((24 * time.Hour).Seconds())}
	if b, err := marshalSigned(se); err == nil {
		r.Signed = b
	}
	reject := func(reason string, kind agentv1.SecurityEventKind) {
		e.log().Warn("job rejected", "job", env.JobId, "reason", reason)
		if kind != agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED && e.Security != nil {
			e.Security(kind, reason)
		}
		e.setState(r, agentv1.JobState_JOB_STATE_REJECTED, short(reason), &agentv1.JobResult{
			Outcome: agentv1.JobOutcome_JOB_OUTCOME_FAILED, Message: short(reason), FinishedAt: e.now().Unix()})
	}
	if env.Type == agentv1.JobType_JOB_TYPE_CANCEL {
		e.cancelJob(env.GetCancel().GetJobId(), r)
		return
	}
	if ceilingName(env.Type) == "" {
		reject(fmt.Sprintf("this agent version does not support job type %s; install the current agent", env.Type), agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED)
		return
	}
	if !e.allowed(env.Type) {
		why := "job type not allowed by the local policy ceiling"
		if env.Type == agentv1.JobType_JOB_TYPE_RUN_SCRIPT && !e.ScriptsEnabled {
			why = "scripts are switched off on this computer (the agent was installed with --no-scripts)"
		}
		reject(why, agentv1.SecurityEventKind_SECURITY_EVENT_KIND_POLICY_CEILING)
		return
	}
	if err := ValidateWindow(env.Window); err != nil {
		reject(err.Error(), agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED)
		return
	}
	switch env.Type {
	case agentv1.JobType_JOB_TYPE_INVENTORY_FULL:
		e.setState(r, agentv1.JobState_JOB_STATE_ACCEPTED, "", nil)
	case agentv1.JobType_JOB_TYPE_SOFTWARE_INSTALL, agentv1.JobType_JOB_TYPE_SOFTWARE_UPDATE:
		if err := ValidateInstall(env.GetInstall(), env.TargetUserSid); err != nil {
			reject(err.Error(), agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED)
			return
		}
		e.setState(r, agentv1.JobState_JOB_STATE_ACCEPTED, "", nil)
	case agentv1.JobType_JOB_TYPE_SOFTWARE_UNINSTALL:
		if err := ValidateUninstall(env.GetUninstall(), env.TargetUserSid); err != nil {
			reject(err.Error(), agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED)
			return
		}
		e.setState(r, agentv1.JobState_JOB_STATE_ACCEPTED, "", nil)
	case agentv1.JobType_JOB_TYPE_WU_SCAN, agentv1.JobType_JOB_TYPE_WU_INSTALL, agentv1.JobType_JOB_TYPE_WU_HIDE, agentv1.JobType_JOB_TYPE_REBOOT:
		if err := ValidateWU(env); err != nil {
			reject(err.Error(), agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED)
			return
		}
		e.setState(r, agentv1.JobState_JOB_STATE_ACCEPTED, "", nil)
	case agentv1.JobType_JOB_TYPE_AGENT_UPDATE:
		if err := ValidateAgentUpdate(env); err != nil {
			reject(err.Error(), agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED)
			return
		}
		e.setState(r, agentv1.JobState_JOB_STATE_ACCEPTED, "", nil)
	case agentv1.JobType_JOB_TYPE_WAKE:
		if env.TargetUserSid != "" {
			reject("wake jobs are machine-scope", agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED)
			return
		}
		if err := ValidateWake(env.GetWake()); err != nil {
			reject(err.Error(), agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED)
			return
		}
		e.setState(r, agentv1.JobState_JOB_STATE_ACCEPTED, "", nil)
	case agentv1.JobType_JOB_TYPE_AGENT_UNINSTALL:
		if env.TargetUserSid != "" {
			reject("removing the agent is machine-scope", agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED)
			return
		}
		if err := ValidateAgentUninstall(env.GetAgentUninstall()); err != nil {
			reject(err.Error(), agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED)
			return
		}
		e.setState(r, agentv1.JobState_JOB_STATE_ACCEPTED, "", nil)
	case agentv1.JobType_JOB_TYPE_PROFILE_DELETE:
		if env.TargetUserSid != "" {
			reject("profile removal is machine-scope", agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED)
			return
		}
		if err := ValidateProfileDelete(env.GetProfileDelete()); err != nil {
			reject(err.Error(), agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED)
			return
		}
		e.setState(r, agentv1.JobState_JOB_STATE_ACCEPTED, "", nil)
	case agentv1.JobType_JOB_TYPE_INSPECT:
		if env.TargetUserSid != "" {
			reject("inspect jobs are machine-scope", agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED)
			return
		}
		if err := ValidateInspect(env.GetInspect()); err != nil {
			reject(err.Error(), agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED)
			return
		}
		e.setState(r, agentv1.JobState_JOB_STATE_ACCEPTED, "", nil)
	case agentv1.JobType_JOB_TYPE_RUN_SCRIPT:
		if env.TargetUserSid != "" {
			reject("script jobs are machine-scope", agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED)
			return
		}
		if err := ValidateRunScript(env.GetRunScript()); err != nil {
			reject(err.Error(), agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED)
			return
		}
		e.setState(r, agentv1.JobState_JOB_STATE_ACCEPTED, "", nil)
	default:
		reject("unsupported job type", agentv1.SecurityEventKind_SECURITY_EVENT_KIND_UNSPECIFIED)
		return
	}
	e.wakeLane(laneOf(env.Type))
}

// cancelJob handles a CANCEL envelope (itself recorded as a finished job).
func (e *Engine) cancelJob(target string, self *Record) {
	e.mu.Lock()
	cancel := e.cancels[target]
	e.mu.Unlock()
	if t := load(e.Store, target); t != nil && !t.terminal() {
		t.Cancel = true
		_ = save(e.Store, t)
		if cancel != nil {
			cancel()
		}
		e.Wake()
	}
	e.setState(self, agentv1.JobState_JOB_STATE_SUCCEEDED, "cancel_requested", &agentv1.JobResult{
		Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, FinishedAt: e.now().Unix()})
}

// Run processes the queue until ctx ends: one loop per lane, so unrelated jobs run side by side. The installing lane runs on
// this goroutine and is also woken when someone signs in (jobs that wait for a person).
func (e *Engine) Run(ctx context.Context) {
	e.init()
	e.SelfUpdateStartup()
	for _, l := range workLanes {
		if l != laneMain {
			go e.loop(ctx, l, e.wakes[l], nil)
		}
	}
	var sessions <-chan struct{}
	if e.P != nil {
		sessions = e.P.SessionEvents()
	}
	e.loop(ctx, laneMain, e.wakes[laneMain], sessions)
}

func (e *Engine) loop(ctx context.Context, l lane, wake, sessions <-chan struct{}) {
	for ctx.Err() == nil {
		wait := e.tickLane(ctx, l)
		maxIdle := e.MaxIdle
		if maxIdle == 0 {
			maxIdle = 5 * time.Minute
		}
		if wait <= 0 || wait > maxIdle {
			wait = maxIdle
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-wake:
		case <-sessions:
		case <-t.C:
		}
		t.Stop()
	}
}

// tick runs every job that is eligible now and returns how long to wait for the next one.
func (e *Engine) tick(ctx context.Context) time.Duration { return e.tickLane(ctx, laneAll) }

func (e *Engine) tickLane(ctx context.Context, l lane) time.Duration {
	recs, err := loadAll(e.Store)
	if err != nil {
		e.log().Error("read jobs", "err", err)
		return time.Minute
	}
	sort.Slice(recs, func(i, j int) bool {
		if recs[i].NotBefore != recs[j].NotBefore {
			return recs[i].NotBefore < recs[j].NotBefore
		}
		return recs[i].JobID < recs[j].JobID
	})
	var next time.Time
	soonest := func(t time.Time) {
		if next.IsZero() || t.Before(next) {
			next = t
		}
	}
	if l == laneScan || l == laneAll { // the daily scan belongs to the lane of scans: it waits for nothing and holds nothing up
		if t := e.autoScan(ctx); !t.IsZero() {
			soonest(t)
		}
	}
	if l == laneControl || l == laneMain || l == laneAll {
		if t := e.checkReboot(); !t.IsZero() {
			soonest(t)
		}
	}
	userPoll := e.PollUserJobs
	if userPoll == 0 {
		userPoll = 15 * time.Minute
	}
	for i, r := range recs {
		if ctx.Err() != nil {
			return 0
		}
		if !l.handles(agentv1.JobType(r.Type)) {
			continue
		}
		now := e.now()
		if r.terminal() {
			if r.Keep > 0 && now.Unix() > r.Keep {
				_ = e.Store.JobDelete(r.JobID)
			}
			continue
		}
		if r.AwaitRestart {
			// An agent update waits for the restart. If the outcome never arrives (state lost), do
			// not leave the job hanging forever.
			if r.Started > 0 && now.Unix() > r.Started+3600 {
				e.finishAwait(r.JobID, false, "the outcome of the agent update is unknown")
			}
			continue
		}
		if now.Unix() > r.Expires {
			e.setState(r, agentv1.JobState_JOB_STATE_EXPIRED, "expired", &agentv1.JobResult{
				Outcome: agentv1.JobOutcome_JOB_OUTCOME_FAILED, Message: "the job expired before it could run", FinishedAt: now.Unix()})
			continue
		}
		if r.Cancel {
			e.setState(r, agentv1.JobState_JOB_STATE_CANCELLED, "cancelled", &agentv1.JobResult{
				Outcome: agentv1.JobOutcome_JOB_OUTCOME_FAILED, Message: "cancelled by an administrator", FinishedAt: now.Unix()})
			continue
		}
		if t := time.Unix(r.NotBefore, 0); now.Before(t) {
			e.setState(r, agentv1.JobState_JOB_STATE_WAITING, "waiting_not_before", nil)
			soonest(t)
			continue
		}
		if t := time.Unix(r.NextRun, 0); r.NextRun > 0 && now.Before(t) {
			soonest(t)
			continue
		}
		_, env, err := r.envelope()
		if err != nil {
			e.setState(r, agentv1.JobState_JOB_STATE_FAILED, "corrupt_record", &agentv1.JobResult{
				Outcome: agentv1.JobOutcome_JOB_OUTCOME_FAILED, Message: "stored job could not be read", FinishedAt: now.Unix()})
			continue
		}
		if open, at := WindowOpen(env.Window, now, e.local()); !open {
			e.setState(r, agentv1.JobState_JOB_STATE_WAITING, "waiting_window", nil)
			soonest(at)
			continue
		}
		if r.SID != "" && !e.P.HasSession(r.SID) {
			e.setState(r, agentv1.JobState_JOB_STATE_WAITING, "waiting_user_logon", nil)
			soonest(now.Add(userPoll))
			continue
		}
		if l == laneControl && agentv1.JobType(r.Type) == agentv1.JobType_JOB_TYPE_REBOOT && e.unsafe.Load() > 0 {
			// An installer or update is running: the restart starts when it has finished (runJob wakes this loop).
			e.setState(r, agentv1.JobState_JOB_STATE_WAITING, "waiting_install_finish", nil)
			continue
		}
		e.markQueued(recs[i+1:], l)
		e.runJob(ctx, r, env)
		if r.state() == agentv1.JobState_JOB_STATE_WAITING && r.NextRun > 0 {
			soonest(time.Unix(r.NextRun, 0))
		}
	}
	// A job in this pass may have scheduled a restart that is already due.
	if l == laneControl || l == laneMain || l == laneAll {
		if t := e.checkReboot(); !t.IsZero() {
			soonest(t)
		}
	}
	if next.IsZero() {
		return 0
	}
	return next.Sub(e.now()) + time.Second
}

// markQueued tells the console that jobs of this lane which are ready to run are waiting for the one that is about to run,
// instead of leaving them looking as if nothing had happened to them (they stay "accepted" otherwise).
func (e *Engine) markQueued(later []*Record, l lane) {
	now := e.now()
	for _, q := range later {
		if !l.handles(agentv1.JobType(q.Type)) || q.terminal() || q.AwaitRestart || q.Cancel || q.state() != agentv1.JobState_JOB_STATE_ACCEPTED {
			continue
		}
		if now.Unix() > q.Expires || now.Before(time.Unix(q.NotBefore, 0)) {
			continue
		}
		e.setState(q, agentv1.JobState_JOB_STATE_WAITING, "waiting_other_job", nil)
	}
}

func (e *Engine) runJob(ctx context.Context, r *Record, env *agentv1.JobEnvelope) {
	if interruptedByRestart(env.Type) {
		e.unsafe.Add(1)
		defer func() {
			e.unsafe.Add(-1)
			e.Wake() // a restart that waited for this job can start now
		}()
	}
	jctx, cancel := context.WithCancel(ctx)
	e.mu.Lock()
	e.cancels[r.JobID] = cancel
	e.mu.Unlock()
	defer func() {
		cancel()
		e.mu.Lock()
		delete(e.cancels, r.JobID)
		e.mu.Unlock()
	}()
	started := e.now()
	r.Started = started.Unix()
	// These lines are what to read in agent.log when an action seems slow: how long the job waited after the agent
	// took it, and how long it ran.
	var waited int64
	if r.Accepted > 0 { // jobs stored by an older agent have no acceptance time
		waited = max(started.Unix()-r.Accepted, 0)
	}
	e.log().Info("job running", "job", r.JobID, "type", env.Type.String(), "waited_s", waited)
	defer func() {
		e.log().Info("job finished", "job", r.JobID, "type", env.Type.String(), "state", r.state().String(), "ran_ms", e.now().Sub(started).Milliseconds())
	}()
	e.setState(r, agentv1.JobState_JOB_STATE_RUNNING, "", nil)

	var out *outcome
	switch env.Type {
	case agentv1.JobType_JOB_TYPE_INVENTORY_FULL:
		if e.InventoryNow != nil {
			e.InventoryNow()
		}
		out = &outcome{res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, DetectionPassed: true}}
	case agentv1.JobType_JOB_TYPE_SOFTWARE_INSTALL, agentv1.JobType_JOB_TYPE_SOFTWARE_UPDATE:
		out = e.install(jctx, r, env)
	case agentv1.JobType_JOB_TYPE_SOFTWARE_UNINSTALL:
		out = e.uninstall(jctx, r, env)
	case agentv1.JobType_JOB_TYPE_WU_SCAN:
		out = e.wuScan(jctx, env)
	case agentv1.JobType_JOB_TYPE_PROFILE_DELETE:
		out = e.profileDelete(env)
	case agentv1.JobType_JOB_TYPE_AGENT_UNINSTALL:
		out = e.agentUninstall()
	case agentv1.JobType_JOB_TYPE_WU_INSTALL:
		out = e.wuInstall(jctx, env)
	case agentv1.JobType_JOB_TYPE_WU_HIDE:
		out = e.wuHide(jctx, env)
	case agentv1.JobType_JOB_TYPE_REBOOT:
		out = e.rebootJob(env)
	case agentv1.JobType_JOB_TYPE_AGENT_UPDATE:
		out = e.agentUpdate(jctx, r, env)
	case agentv1.JobType_JOB_TYPE_WAKE:
		out = e.sendWake(jctx, env)
	case agentv1.JobType_JOB_TYPE_INSPECT:
		out = e.inspect(jctx, env)
	case agentv1.JobType_JOB_TYPE_RUN_SCRIPT:
		out = e.runScript(jctx, r, env)
	}
	if out == nil {
		out = fail("unsupported job type")
	}
	if out.deferred { // the service is restarting into a new version; the job ends after that
		return
	}
	now := e.now()
	if r.Cancel || (errors.Is(jctx.Err(), context.Canceled) && ctx.Err() == nil) {
		out = &outcome{res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_FAILED, Message: "cancelled by an administrator"}, cancelled: true}
	}
	if ctx.Err() != nil { // shutting down: leave the job to be retried after restart
		r.State = int32(agentv1.JobState_JOB_STATE_ACCEPTED)
		_ = save(e.Store, r)
		return
	}
	out.res.StartedAt, out.res.FinishedAt = r.Started, now.Unix()
	r.Finished = now.Unix()

	switch {
	case out.waitUntil > 0:
		r.NextRun, r.Finished = out.waitUntil, 0
		e.setState(r, agentv1.JobState_JOB_STATE_WAITING, out.waitReason, nil)
		return
	case out.waitUser:
		e.setState(r, agentv1.JobState_JOB_STATE_WAITING, "waiting_user_logon", nil)
		return
	case out.cancelled:
		e.setState(r, agentv1.JobState_JOB_STATE_CANCELLED, "cancelled", out.res)
		return
	case out.res.Outcome == agentv1.JobOutcome_JOB_OUTCOME_RETRYABLE:
		max, backoff := retryPolicy(env)
		if r.Tries < max && now.Unix() < r.Expires {
			r.Tries++
			d := time.Duration(backoff) * time.Second * (1 << (r.Tries - 1))
			r.NextRun = now.Add(d).Unix()
			e.log().Info("job will retry", "job", r.JobID, "try", r.Tries, "in", d)
			e.setState(r, agentv1.JobState_JOB_STATE_WAITING, "retry_backoff", nil)
			return
		}
		out.res.Outcome = agentv1.JobOutcome_JOB_OUTCOME_FAILED
		out.res.Message = short("retries exhausted: " + out.res.Message)
		e.setState(r, agentv1.JobState_JOB_STATE_FAILED, "retries_exhausted", out.res)
	case out.res.Outcome == agentv1.JobOutcome_JOB_OUTCOME_REBOOT_REQUIRED:
		out.res.RebootRequired = true
		e.setState(r, agentv1.JobState_JOB_STATE_SUCCEEDED_REBOOT, "reboot_required", out.res)
	case out.res.Outcome == agentv1.JobOutcome_JOB_OUTCOME_SUCCESS:
		e.setState(r, agentv1.JobState_JOB_STATE_SUCCEEDED, "", out.res)
	default:
		e.setState(r, agentv1.JobState_JOB_STATE_FAILED, out.reason, out.res)
	}
	if env.Type != agentv1.JobType_JOB_TYPE_INVENTORY_FULL && e.InventoryNow != nil && !isWUType(env.Type) {
		e.InventoryNow() // reflect the change in the fleet inventory without waiting for the debounce
	}
}

func retryPolicy(env *agentv1.JobEnvelope) (max uint32, backoffS uint32) {
	var b, bo uint32
	switch {
	case env.GetInstall() != nil:
		b, bo = env.GetInstall().MaxRetries, env.GetInstall().RetryBackoffS
	case env.GetUninstall() != nil:
		b, bo = env.GetUninstall().MaxRetries, env.GetUninstall().RetryBackoffS
	case env.GetWuInstall() != nil:
		b, bo = env.GetWuInstall().MaxRetries, env.GetWuInstall().RetryBackoffS
	}
	if bo == 0 {
		bo = 60
	}
	return b, bo
}

// outcome is what a pipeline returns to runJob.
type outcome struct {
	res       *agentv1.JobResult
	reason    string
	waitUser  bool
	cancelled bool
	deferred  bool // the job outcome is reported later (agent update waiting for its restart)
	// waitUntil, when set (unix seconds), puts the job back to WAITING until then without using up a retry:
	// programs the update replaces are open (see inUseGate). waitReason is shown as the status reason.
	waitUntil  int64
	waitReason string
}

func fail(format string, a ...any) *outcome {
	msg := fmt.Sprintf(format, a...)
	return &outcome{reason: "failed", res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_FAILED, Message: short(msg)}}
}

func short(s string) string { return text.Truncate(s, 1024) }

// helperTask prepares the re-verification material for a user-scope run.
func (e *Engine) helperTask(r *Record, stageDir, file string) *HelperTask {
	t := &HelperTask{Signed: r.Signed, SID: r.SID, StageDir: stageDir, File: file, Now: e.now().Unix()}
	if e.Trust != nil {
		t.Root, t.SigningDER, t.DeviceID, t.OrgID = e.Trust()
	}
	return t
}
