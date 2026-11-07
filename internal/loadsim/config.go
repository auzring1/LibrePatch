// Package loadsim simulates a large fleet of LibrePatch agents against a real server.
//
// Each simulated agent speaks the real protocol: it enrolls with a token and a CSR over the pinned
// TLS channel, reconnects over TLS 1.3 mutual TLS, sends Hello, hardware, software and user
// inventory (full snapshot, then deltas) using the agent's own inventory manager, sends heartbeats,
// verifies signed job envelopes with the agent's own verifier and reports job updates. What it
// does not do is touch Windows: keys are software keys, inventory comes from a shared fixture and
// jobs are no-ops. It reuses internal/agent/core (TLS helpers, dial options, backoff),
// internal/agent/inventory, internal/shared/envelope and internal/shared/pkix, and relaxes no
// server check. See docs/LOADTEST.md.
package loadsim

import (
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Scenario names.
const (
	ScenarioSteady = "steady"
	ScenarioStorm  = "storm"
	ScenarioChurn  = "churn"
)

// Job kinds the tool can ask the server to create (through the REST API).
const (
	JobInventory = "inventory" // POST /devices/{id}/refresh      -> INVENTORY_FULL
	JobWUScan    = "wu_scan"   // POST /devices/{id}/windows-updates/scan -> WU_SCAN
	JobMixed     = "mixed"     // alternate between the two
)

// Config is everything a run needs. Zero values get defaults from Validate.
type Config struct {
	// Server is the agent gateway, host:port. It must be one of the names in the gateway certificate.
	// When Enrollment is set and Server is empty, the address inside the enrollment string is used.
	Server string
	// Enrollment is an "LP1." enrollment string (token, root pin and gateway). If empty, the tool
	// mints one through the REST API (API and APIToken).
	Enrollment string
	// API is the server's REST base URL (for example http://127.0.0.1:18080) and APIToken an API
	// token with the scopes enrollment:write, devices:read, devices:write, updates:write and
	// reports:read. Optional when Enrollment is given and no jobs are requested.
	API      string
	APIToken string

	Agents      int
	RampPerSec  float64       // new agents started per second
	RampTimeout time.Duration // give up waiting for 99% connected after this long
	Duration    time.Duration // hold time (steady, churn) or the post-recovery hold (storm)
	Scenario    string

	// Heartbeat is the interval between heartbeats of each agent (jittered by +-HeartbeatJitter).
	// A real agent sends one only when something changed or every 30 minutes; this is a deliberate
	// stress multiplier.
	Heartbeat       time.Duration
	HeartbeatJitter float64 // fraction, 0..1
	// InventorySize is the number of software items per agent. InventoryChangeEvery makes each
	// agent change a few items (a delta) about that often; 0 disables deltas after the snapshot.
	InventorySize        int
	InventoryChangeEvery time.Duration
	InventoryChangeItems int

	// Storm.
	StormHold    time.Duration // hold connected this long before the drop
	StormMode    string        // "client" (the tool drops every connection) or "external" (an operator restarts the server)
	StormTimeout time.Duration // how long to wait for recovery
	// Churn: this many random agents per second drop and reconnect, each staying away for up to ChurnAway.
	ChurnPerSec float64
	ChurnAway   time.Duration

	// Jobs: every JobInterval, JobFraction of the connected agents get a job through the REST API.
	JobFraction float64
	JobInterval time.Duration
	JobKind     string
	JobRate     float64       // maximum REST calls per second
	JobExecTime time.Duration // simulated execution time per job
	JobGrace    time.Duration // wait this long at the end for outstanding results

	// Reconnect behaviour (the real agent's values by default).
	BackoffBase time.Duration
	BackoffMax  time.Duration

	// IdentityCache keeps enrolled identities (device certificates and private keys!) between runs so
	// that repeated runs against one server do not enroll again. Created with mode 0600.
	IdentityCache string

	// Observation of the server under test (optional, same-host only).
	ServerPID int    // sample CPU, memory and descriptors of this process
	PGURL     string // sample database counters (a role that may read pg_stat_database and audit_log)

	// Client tuning.
	ReadBuffer, WriteBuffer int // gRPC per-connection buffers in bytes (0 = gRPC's 32 KiB)

	Log     *slog.Logger
	Version string
}

// Validate fills defaults and rejects nonsense.
func (c *Config) Validate() error {
	if c.Scenario == "" {
		c.Scenario = ScenarioSteady
	}
	switch c.Scenario {
	case ScenarioSteady, ScenarioStorm, ScenarioChurn:
	default:
		return fmt.Errorf("unknown scenario %q (steady, storm or churn)", c.Scenario)
	}
	if c.Agents < 1 || c.Agents > 100000 {
		return errors.New("--agents must be between 1 and 100000")
	}
	if c.RampPerSec <= 0 {
		c.RampPerSec = 100
	}
	if c.RampTimeout <= 0 {
		c.RampTimeout = max(2*time.Minute, time.Duration(float64(c.Agents)/c.RampPerSec*3*float64(time.Second))+time.Minute)
	}
	if c.Duration <= 0 {
		c.Duration = time.Minute
	}
	if c.Heartbeat <= 0 {
		c.Heartbeat = time.Minute
	}
	if c.HeartbeatJitter < 0 || c.HeartbeatJitter > 1 {
		return errors.New("--heartbeat-jitter must be between 0 and 1")
	}
	if c.InventorySize <= 0 {
		c.InventorySize = 120
	}
	if c.InventorySize > 20000 {
		return errors.New("--inventory-size must be at most 20000")
	}
	if c.InventoryChangeItems <= 0 {
		c.InventoryChangeItems = 3
	}
	if c.StormHold <= 0 {
		c.StormHold = 30 * time.Second
	}
	switch c.StormMode {
	case "":
		c.StormMode = "client"
	case "client", "external":
	default:
		return errors.New("--storm-mode must be client or external")
	}
	if c.StormTimeout <= 0 {
		c.StormTimeout = 10 * time.Minute
	}
	if c.ChurnPerSec <= 0 {
		c.ChurnPerSec = max(1, float64(c.Agents)/100)
	}
	if c.ChurnAway <= 0 {
		c.ChurnAway = 10 * time.Second
	}
	if c.JobFraction < 0 || c.JobFraction > 1 {
		return errors.New("--jobs-fraction must be between 0 and 1")
	}
	if c.JobInterval <= 0 {
		c.JobInterval = 30 * time.Second
	}
	switch c.JobKind {
	case "":
		c.JobKind = JobInventory
	case JobInventory, JobWUScan, JobMixed:
	default:
		return errors.New("--job-kind must be inventory, wu_scan or mixed")
	}
	if c.JobRate <= 0 {
		c.JobRate = 15 // the API's per-IP limit is 20/s with a burst of 60
	}
	if c.JobExecTime <= 0 {
		c.JobExecTime = 50 * time.Millisecond
	}
	if c.JobGrace <= 0 {
		c.JobGrace = 30 * time.Second
	}
	if c.BackoffBase <= 0 {
		c.BackoffBase = time.Second
	}
	if c.BackoffMax <= 0 {
		c.BackoffMax = 5 * time.Minute
	}
	if c.JobFraction > 0 && (c.API == "" || c.APIToken == "") {
		return errors.New("jobs need --api and --api-token")
	}
	if c.Enrollment == "" && (c.API == "" || c.APIToken == "") {
		return errors.New("give --enrollment (an LP1 string) or --api and --api-token to mint one")
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
	if c.Version == "" {
		c.Version = "loadsim"
	}
	return nil
}
