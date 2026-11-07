package e2e

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/auzring1/librepatch/internal/loadsim"
	sconfig "github.com/auzring1/librepatch/internal/server/config"
)

// loadsimHarness is a server whose enrollment limits allow a fleet of simulated agents from one address.
func loadsimHarness(t *testing.T) (*harness, string) {
	h := newHarnessCfg(t, 90*24*time.Hour, func(c *sconfig.Config) {
		c.EnrollRatePerIP, c.EnrollRatePerToken = 1000, 1000
	})
	h.setupAndLogin()
	st, b := h.do("POST", "/api/v1/me/api-tokens", map[string]any{"name": "loadsim", "expires_in_days": 1,
		"scopes": []string{"enrollment:write", "devices:read", "devices:write", "updates:write", "reports:read"}}, nil)
	if st != 201 {
		t.Fatalf("api token: %d %v", st, b)
	}
	return h, b["token"].(string)
}

func simConfig(h *harness, apiToken string) loadsim.Config {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	return loadsim.Config{
		Server: h.app.GatewayAddr(), API: h.base, APIToken: apiToken,
		Agents: 50, RampPerSec: 200, Duration: 3 * time.Second,
		Heartbeat: time.Second, HeartbeatJitter: 0.3, InventorySize: 40, InventoryChangeEvery: 1500 * time.Millisecond,
		BackoffBase: 50 * time.Millisecond, BackoffMax: 500 * time.Millisecond, Log: log,
	}
}

// TestLoadsimSteady runs the load generator's steady scenario (real enrollment, mTLS, inventory,
// heartbeats and jobs) against the in-process server.
func TestLoadsimSteady(t *testing.T) {
	h, tok := loadsimHarness(t)
	cfg := simConfig(h, tok) // no enrollment string: the tool mints a token through the API
	cfg.Scenario = loadsim.ScenarioSteady
	cfg.JobFraction, cfg.JobInterval, cfg.JobKind, cfg.JobGrace = 0.3, time.Second, loadsim.JobMixed, 20*time.Second
	cfg.IdentityCache = filepath.Join(t.TempDir(), "ids.json")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rep, err := loadsim.Run(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Pass {
		t.Fatalf("steady run failed: %v\n%s", rep.Failures, rep.Markdown())
	}
	if rep.Enrollment.Enrolled != 50 || rep.ConnectedEnd < 50 {
		t.Fatalf("enrolled %d, connected %d", rep.Enrollment.Enrolled, rep.ConnectedEnd)
	}
	var hold *loadsim.PhaseReport
	for i := range rep.Phases {
		if rep.Phases[i].Name == "hold" {
			hold = &rep.Phases[i]
		}
	}
	if hold == nil || hold.Counters["heartbeats"] < 50 || hold.Latency["ack_inventory_delta"].Count == 0 {
		t.Fatalf("hold phase saw no heartbeats or inventory deltas: %+v", hold)
	}
	if rep.Phases[0].Latency["handshake"].Count != 50 || rep.Phases[0].Latency["connect"].Count < 50 {
		t.Fatalf("ramp latencies: %+v", rep.Phases[0].Latency)
	}
	if rep.Jobs == nil || rep.Jobs.Created == 0 || rep.Jobs.Lost != 0 || rep.Jobs.EndToEnd.Count != uint64(rep.Jobs.Created) { // #nosec G115 -- small
		t.Fatalf("jobs: %+v", rep.Jobs)
	}
	if rep.ServerView == nil || rep.ServerView.OnlineAtEnd < 50 {
		t.Fatalf("the server's own count disagrees: %+v", rep.ServerView)
	}
	if devs := h.devices(); len(devs) != 50 {
		t.Fatalf("server has %d devices", len(devs))
	}
	if err := rep.WriteJSON(filepath.Join(t.TempDir(), "r.json")); err != nil {
		t.Fatal(err)
	}

	// A second run reuses the cached identities: no new devices, no enrollment.
	cfg.JobFraction, cfg.Duration = 0, time.Second
	rep2, err := loadsim.Run(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !rep2.Pass || rep2.Enrollment.Enrolled != 0 || rep2.Enrollment.FromCache != 50 {
		t.Fatalf("cached run: pass=%v %v enrollment=%+v", rep2.Pass, rep2.Failures, rep2.Enrollment)
	}
	if devs := h.devices(); len(devs) != 50 {
		t.Fatalf("a cached run created devices: %d", len(devs))
	}
}

// TestLoadsimStormAndChurn drops every connection at once and expects the fleet to come back with
// the agent's own backoff, then churns random agents.
func TestLoadsimStormAndChurn(t *testing.T) {
	h, tok := loadsimHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cfg := simConfig(h, tok)
	cfg.Scenario = loadsim.ScenarioStorm
	cfg.StormHold, cfg.StormTimeout, cfg.Duration = time.Second, 60*time.Second, time.Second
	rep, err := loadsim.Run(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Pass || rep.Storm == nil || !rep.Storm.Recovered99 {
		t.Fatalf("storm failed: %v\n%s", rep.Failures, rep.Markdown())
	}
	if rep.Storm.ConnectedAtDrop < 49 || rep.Storm.TroughConnected > 5 {
		t.Fatalf("the drop was not a mass disconnect: %+v", rep.Storm)
	}
	if rep.Storm.ReconnectAttempts < 50 || rep.Storm.TimeToPct["t99pct"] <= 0 {
		t.Fatalf("recovery numbers: %+v", rep.Storm)
	}

	cfg = simConfig(h, tok)
	cfg.Scenario = loadsim.ScenarioChurn
	cfg.ChurnPerSec, cfg.ChurnAway, cfg.Duration = 10, 500*time.Millisecond, 3*time.Second
	rep, err = loadsim.Run(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Pass {
		t.Fatalf("churn failed: %v\n%s", rep.Failures, rep.Markdown())
	}
	var churn int64
	for _, p := range rep.Phases {
		churn += p.Counters["churn.drops"]
	}
	if churn < 10 {
		t.Fatalf("only %d churn drops", churn)
	}
}
