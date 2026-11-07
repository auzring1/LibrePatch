package loadsim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Run executes one scenario and returns its report. A nil error means the run completed; whether it
// met its success criteria is Report.Pass.
func Run(ctx context.Context, cfg Config) (*Report, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	started := time.Now()
	f := &fleet{cfg: &cfg, log: cfg.Log, quietLog: slog.New(slog.NewTextHandler(io.Discard, nil)),
		fx: NewFixture(cfg.InventorySize), jobs: NewJobTracker(), enrollH: NewHist(), cache: map[int]*Identity{}}
	if cfg.API != "" && cfg.APIToken != "" {
		f.api = NewAPI(cfg.API, cfg.APIToken)
	}
	f.startPhase("ramp")
	if err := f.resolveEnrollment(ctx); err != nil {
		return nil, err
	}
	f.runID = randHex(3)
	if cfg.IdentityCache != "" {
		id, ids, tr, sig := loadCache(cfg.IdentityCache, f.rootPin)
		if id != "" {
			f.runID, f.cache = id, ids
			f.trustV.Store(tr)
			f.acceptSigningCertsRaw(sig)
			cfg.Log.Info("identity cache loaded", "identities", len(ids))
		}
	}
	f.agents = make([]*simAgent, cfg.Agents)
	for i := range f.agents {
		f.agents[i] = newSimAgent(f, i)
	}

	sctx, stopSamplers := context.WithCancel(ctx)
	defer stopSamplers()
	self := newProcSampler("self", true)
	self.pid = strconv.Itoa(os.Getpid())
	go self.run(sctx, f, 2*time.Second)
	var server *procSampler
	if cfg.ServerPID > 0 {
		server = newProcSampler(strconv.Itoa(cfg.ServerPID), false)
		go server.run(sctx, f, 2*time.Second)
	}
	var db *dbSampler
	if cfg.PGURL != "" {
		db = newDBSampler(cfg.PGURL)
		go db.run(sctx, f, 5*time.Second)
	}
	series := NewSeries(time.Second)
	t0 := time.Now()
	go func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case now := <-t.C:
				series.Add(now, now.Sub(t0).Seconds(), float64(f.connected.Load()))
			}
		}
	}()

	actx, stopAgents := context.WithCancel(ctx)
	var agentsWG sync.WaitGroup
	rep := &Report{Tool: "librepatch-loadsim", Scenario: cfg.Scenario, StartedAt: started, Agents: cfg.Agents, RampS: -1,
		Params: params(&cfg)}

	// Ramp: start agents at the requested rate.
	go func() {
		batch := max(1, int(cfg.RampPerSec/50)) // up to 50 wake-ups per second
		gap := time.Duration(float64(time.Second) * float64(batch) / cfg.RampPerSec)
		for i := 0; i < len(f.agents); i += batch {
			for j := i; j < min(i+batch, len(f.agents)); j++ {
				a := f.agents[j]
				agentsWG.Add(1)
				go func() { defer agentsWG.Done(); a.run(actx) }()
			}
			if !sleep(actx, gap) {
				return
			}
		}
	}()

	need := int(math.Ceil(0.99 * float64(cfg.Agents)))
	rampStart := time.Now()
	for int(f.connected.Load()) < need && time.Since(rampStart) < cfg.RampTimeout && ctx.Err() == nil {
		time.Sleep(100 * time.Millisecond)
	}
	if int(f.connected.Load()) >= need {
		rep.RampS = time.Since(rampStart).Seconds()
		// Connected is not onboarded: wait for the first inventory reports to be acknowledged, so that
		// the hold phase measures a settled fleet and the ramp phase owns the initial load.
		for f.inflight.Load() > 0 && time.Since(rampStart) < cfg.RampTimeout && ctx.Err() == nil {
			time.Sleep(100 * time.Millisecond)
		}
		rep.SyncedS = time.Since(rampStart).Seconds()
	} else {
		rep.Failures = append(rep.Failures, fmt.Sprintf("only %d of %d agents connected after %s", f.connected.Load(), cfg.Agents, cfg.RampTimeout))
	}
	if cfg.IdentityCache != "" {
		if err := f.saveCache(cfg.IdentityCache); err != nil {
			cfg.Log.Warn("could not save the identity cache", "err", err)
		}
	}
	cfg.Log.Info("ramp finished", "connected", f.connected.Load(), "seconds", rep.RampS)

	// Scenario.
	jobCtx, stopJobs := context.WithCancel(ctx)
	var jobsWG sync.WaitGroup
	if cfg.JobFraction > 0 && ctx.Err() == nil {
		jobsWG.Add(1)
		go func() { defer jobsWG.Done(); f.jobLoop(jobCtx) }()
	}
	switch cfg.Scenario {
	case ScenarioSteady:
		f.startPhase("hold")
		sleep(ctx, cfg.Duration)
	case ScenarioChurn:
		f.startPhase("churn")
		f.churn(ctx, cfg.Duration)
		// Agents that were dropped last are still on their way back: let them settle before judging.
		settle := time.Now().Add(cfg.ChurnAway + 30*time.Second)
		for int(f.connected.Load()) < int(math.Ceil(0.99*float64(cfg.Agents))) && time.Now().Before(settle) && ctx.Err() == nil {
			time.Sleep(100 * time.Millisecond)
		}
	case ScenarioStorm:
		f.startPhase("hold")
		sleep(ctx, cfg.StormHold)
		rep.Storm = f.storm(ctx)
		if rep.Storm.Recovered99 {
			f.startPhase("after-storm")
			sleep(ctx, cfg.Duration)
		}
	}
	rep.ConnectedEnd = int(f.connected.Load())
	if f.api != nil {
		octx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		if ov, err := f.api.Overview(octx); err == nil {
			rep.ServerView = &ServerView{ActiveDevices: ov.Active, OnlineAtEnd: ov.Online}
		}
		cancel()
	}

	// Let outstanding jobs finish, then stop everything.
	stopJobs()
	jobsWG.Wait()
	if f.jobs.Outstanding() > 0 {
		deadline := time.Now().Add(cfg.JobGrace)
		for f.jobs.Outstanding() > 0 && time.Now().Before(deadline) && ctx.Err() == nil {
			time.Sleep(200 * time.Millisecond)
		}
	}
	f.startPhase("shutdown") // connection errors caused by stopping the agents belong to no scenario phase
	stopSamplers()
	stopAgents()
	done := make(chan struct{})
	go func() { agentsWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		cfg.Log.Warn("some agents did not stop within 30 s")
	}

	rep.FinishedAt = time.Now()
	rep.DurationS = rep.FinishedAt.Sub(started).Seconds()
	rep.Enrollment = EnrollReport{Enrolled: f.enrolled.Load(), FromCache: f.fromCache.Load(), Latency: f.enrollH.Summary()}
	f.phMu.Lock()
	for i, p := range f.phases {
		end := rep.FinishedAt
		if i+1 < len(f.phases) {
			end = f.phases[i+1].start
		}
		rep.Phases = append(rep.Phases, PhaseReport{Name: p.name, DurationS: math.Round(end.Sub(p.start).Seconds()*10) / 10,
			Latency: p.h.Summaries(), Counters: p.c.Snapshot()})
	}
	f.phMu.Unlock()
	rep.Connected = series.Points()
	for _, p := range rep.Connected {
		rep.ConnectedMax = max(rep.ConnectedMax, int(p.V))
	}
	js := f.jobs.Stats()
	if js.Created > 0 {
		rep.Jobs = &js
	}
	rep.ClientSelf = self.result()
	if server != nil {
		rep.ServerProc = server.result()
	}
	if db != nil {
		actx2, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		db.auditCounts(actx2, started)
		cancel()
		rep.Database, rep.AuditCounts, rep.DBError = db.result()
	}
	evaluate(rep, &cfg)
	return rep, nil
}

func (f *fleet) acceptSigningCertsRaw(ders [][]byte) {
	if f.trust() != nil {
		f.acceptSigningCerts(ders)
	}
}

func randHex(n int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "%02x", rand.IntN(256)) // #nosec G404 -- run label, not security
	}
	return sb.String()
}

func params(c *Config) map[string]any {
	return map[string]any{
		"server": c.Server, "agents": c.Agents, "ramp_per_sec": c.RampPerSec, "duration": c.Duration.String(),
		"heartbeat": c.Heartbeat.String(), "heartbeat_jitter": c.HeartbeatJitter, "inventory_size": c.InventorySize,
		"inventory_change_every": c.InventoryChangeEvery.String(), "storm_mode": c.StormMode, "storm_hold": c.StormHold.String(),
		"churn_per_sec": c.ChurnPerSec, "jobs_fraction": c.JobFraction, "job_kind": c.JobKind, "job_interval": c.JobInterval.String(),
		"backoff_base": c.BackoffBase.String(), "backoff_max": c.BackoffMax.String(), "identity_cache": c.IdentityCache != "",
	}
}

// onlineAgents lists the agents that currently hold a stream.
func (f *fleet) onlineAgents() []*simAgent {
	out := make([]*simAgent, 0, len(f.agents))
	for _, a := range f.agents {
		if a.online.Load() {
			out = append(out, a)
		}
	}
	return out
}

// churn drops random agents at the configured rate for d. Each one stays away for up to ChurnAway.
func (f *fleet) churn(ctx context.Context, d time.Duration) {
	end := time.Now().Add(d)
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	carry := 0.0
	for time.Now().Before(end) {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		carry += f.cfg.ChurnPerSec / 10
		n := int(carry)
		carry -= float64(n)
		if n == 0 {
			continue
		}
		on := f.onlineAgents()
		rand.Shuffle(len(on), func(i, j int) { on[i], on[j] = on[j], on[i] }) // #nosec G404 -- sampling, not security
		for i := 0; i < n && i < len(on); i++ {
			on[i].drop(time.Duration(rand.Int64N(int64(f.cfg.ChurnAway)))) // #nosec G404 -- jitter
			f.count("churn.drops")
		}
	}
}

// storm drops every connection at once (or waits for an operator to do it) and measures the recovery.
// "Connected" during recovery counts only agents whose current stream was opened after the disruption
// began, so connections that have not noticed the drop yet are not mistaken for recovered ones.
func (f *fleet) storm(ctx context.Context) *StormReport {
	cfg := f.cfg
	n := cfg.Agents
	sr := &StormReport{Mode: cfg.StormMode, ConnectedAtDrop: int(f.connected.Load()), TimeoutS: cfg.StormTimeout.Seconds()}
	var epoch int64
	if cfg.StormMode == "external" {
		f.log.Info("STORM: waiting for the connected count to fall (restart the server now)", "connected", sr.ConnectedAtDrop)
		deadline := time.Now().Add(cfg.StormTimeout)
		for int(f.connected.Load()) >= int(math.Ceil(0.99*float64(n))) && time.Now().Before(deadline) && ctx.Err() == nil {
			time.Sleep(25 * time.Millisecond)
		}
		f.startPhase("storm")
		epoch = f.stormEpoch.Add(1)
	} else {
		f.startPhase("storm")
		epoch = f.stormEpoch.Add(1)
		for _, a := range f.agents {
			a.drop(0)
		}
	}
	start := time.Now()
	rec := NewRecovery(n, start, 0.5, 0.9, 0.99, 1)
	trough := n
	for time.Since(start) < cfg.StormTimeout && ctx.Err() == nil {
		now := time.Now()
		trough = min(trough, int(f.connected.Load()))
		rec.Observe(now, f.reconnectedSince(epoch))
		if _, ok := rec.Reached(1); ok {
			break
		}
		// After 99% the stragglers are on long backoffs; give them a little longer, not the whole timeout.
		if at, ok := rec.Reached(0.99); ok && time.Since(start) > at+60*time.Second {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	rec.Observe(time.Now(), f.reconnectedSince(epoch))
	sr.TimeToPct = rec.Times()
	sr.TroughConnected = trough
	_, sr.Recovered99 = rec.Reached(0.99)
	p := f.cur.Load()
	sr.ReconnectAttempts = p.c.Get("attempts")
	sr.Failures, sr.GoAways = map[string]int64{}, map[string]int64{}
	for k, v := range p.c.Snapshot() {
		switch {
		case strings.HasPrefix(k, "fail.") && !strings.HasSuffix(k, ".dropped"):
			sr.Failures[strings.TrimPrefix(k, "fail.")] = v
		case strings.HasPrefix(k, "goaway."):
			sr.GoAways[strings.TrimPrefix(k, "goaway.")] = v
		}
	}
	return sr
}

// reconnectedSince counts agents that hold a stream opened in or after the given storm epoch.
func (f *fleet) reconnectedSince(epoch int64) int {
	n := 0
	for _, a := range f.agents {
		if a.online.Load() && a.onlineEpoch.Load() >= epoch {
			n++
		}
	}
	return n
}

// jobLoop creates no-op jobs for a fraction of the connected agents every JobInterval.
func (f *fleet) jobLoop(ctx context.Context) {
	cfg := f.cfg
	lim := rate.NewLimiter(rate.Limit(cfg.JobRate), max(1, int(cfg.JobRate)))
	tick := time.NewTicker(cfg.JobInterval)
	defer tick.Stop()
	n := 0
	wave := func() {
		on := f.onlineAgents()
		want := int(math.Round(cfg.JobFraction * float64(cfg.Agents)))
		if want < 1 {
			want = 1
		}
		rand.Shuffle(len(on), func(i, j int) { on[i], on[j] = on[j], on[i] }) // #nosec G404 -- sampling, not security
		if len(on) > want {
			on = on[:want]
		}
		var wg sync.WaitGroup
		sem := make(chan struct{}, 32)
		for _, a := range on {
			if lim.Wait(ctx) != nil {
				break
			}
			kind := cfg.JobKind
			if kind == JobMixed {
				kind = []string{JobInventory, JobWUScan}[n%2]
				n++
			}
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer func() { <-sem; wg.Done() }()
				start := time.Now()
				id, err := f.api.CreateJob(ctx, kind, a.ident.DeviceID)
				if err != nil {
					if ctx.Err() != nil {
						return // the run is ending; not a failure
					}
					var ae *APIError
					key := "job.create_error.net"
					if errors.As(err, &ae) {
						key = "job.create_error." + strconv.Itoa(ae.Status)
					}
					f.count(key)
					return
				}
				f.jobs.Created(id, start)
				f.count("job.created")
			}()
		}
		wg.Wait()
	}
	wave()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			wave()
		}
	}
}

// evaluate applies the success criteria.
func evaluate(r *Report, cfg *Config) {
	fail := func(f string, a ...any) { r.Failures = append(r.Failures, fmt.Sprintf(f, a...)) }
	minEnd := int(math.Ceil(0.99 * float64(cfg.Agents)))
	if cfg.Scenario == ScenarioChurn {
		minEnd = int(math.Ceil(0.95 * float64(cfg.Agents)))
	}
	if r.ConnectedEnd < minEnd {
		fail("%d of %d agents connected at the end (needed %d)", r.ConnectedEnd, cfg.Agents, minEnd)
	}
	// Errors that are not part of the scenario's own disruption.
	for _, p := range r.Phases {
		if p.Name != "hold" && p.Name != "after-storm" {
			continue
		}
		bad := int64(0)
		for k, v := range p.Counters {
			if strings.HasPrefix(k, "fail.") || k == "job.rejected" {
				bad += v
			}
		}
		if limit := int64(math.Max(1, float64(cfg.Agents)/100)); bad > limit {
			fail("phase %q had %d connection or protocol failures (limit %d)", p.Name, bad, limit)
		}
	}
	if r.Storm != nil && !r.Storm.Recovered99 {
		fail("the fleet did not return to 99%% connected within %s", cfg.StormTimeout)
	}
	if r.Jobs != nil && r.Jobs.Lost > 0 {
		fail("%d of %d jobs never completed", r.Jobs.Lost, r.Jobs.Created)
	}
	if cfg.JobFraction > 0 && (r.Jobs == nil || r.Jobs.Created == 0) {
		fail("no job could be created through the REST API")
	}
	r.Pass = len(r.Failures) == 0
}
