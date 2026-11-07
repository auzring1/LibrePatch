// Command librepatch-loadsim simulates thousands of agents against a LibrePatch server and measures how
// the server copes: a steady fleet, a reconnect storm after a mass disconnect, or random churn.
// The simulated agents enroll and speak the real gateway protocol; see docs/LOADTEST.md.
//
//	librepatch-loadsim --enrollment LP1.… --agents 1000 --scenario steady --report out.json
//	librepatch-loadsim --api http://127.0.0.1:8080 --api-token … --server localhost:8443 --scenario storm
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/auzring1/librepatch/internal/loadsim"
	"github.com/auzring1/librepatch/internal/shared/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "librepatch-loadsim:", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("librepatch-loadsim", flag.ContinueOnError)
	var (
		cfg      loadsim.Config
		report   = fs.String("report", "", "write the JSON report to this file")
		mdReport = fs.String("report-md", "", "write a Markdown report to this file")
		tokenEnv = fs.String("token-env", "LIBREPATCH_LOADSIM_API_TOKEN", "environment variable that holds the API token (keeps it off the command line)")
		enrEnv   = fs.String("enrollment-env", "LIBREPATCH_LOADSIM_ENROLLMENT", "environment variable that holds the enrollment string")
		verbose  = fs.Bool("v", false, "debug logging")
		noFail   = fs.Bool("no-fail", false, "exit 0 even when the success criteria are not met")
		scenario = fs.String("scenario", "steady", "steady, storm or churn")
	)
	fs.StringVar(&cfg.Server, "server", "", "gateway host:port (default: the address in the enrollment string); must match the gateway certificate")
	fs.StringVar(&cfg.Enrollment, "enrollment", "", "LP1 enrollment string (or set the variable named by --enrollment-env); otherwise a token is minted through --api")
	fs.StringVar(&cfg.API, "api", "", "REST base URL, for example http://127.0.0.1:8080 (mints tokens, creates jobs, reads the server's own device count)")
	fs.IntVar(&cfg.Agents, "agents", 100, "number of simulated agents")
	fs.Float64Var(&cfg.RampPerSec, "ramp-per-sec", 100, "agents started per second")
	fs.DurationVar(&cfg.RampTimeout, "ramp-timeout", 0, "give up waiting for 99% connected after this long (default depends on --agents and --ramp-per-sec)")
	fs.DurationVar(&cfg.Duration, "duration", time.Minute, "hold time (steady, churn) or the hold after recovery (storm)")
	fs.DurationVar(&cfg.Heartbeat, "heartbeat", time.Minute, "heartbeat interval per agent (a real agent sends one on change or every 30 minutes)")
	fs.Float64Var(&cfg.HeartbeatJitter, "heartbeat-jitter", 0.2, "random +- fraction applied to each heartbeat interval")
	fs.IntVar(&cfg.InventorySize, "inventory-size", 120, "software items per agent")
	fs.DurationVar(&cfg.InventoryChangeEvery, "inventory-change-every", 0, "each agent changes a few items (a delta) about this often; 0 disables")
	fs.IntVar(&cfg.InventoryChangeItems, "inventory-change-items", 3, "items changed per delta")
	fs.DurationVar(&cfg.StormHold, "storm-hold", 30*time.Second, "storm: stay connected this long before the drop")
	fs.StringVar(&cfg.StormMode, "storm-mode", "client", "storm: client (this tool drops every connection) or external (you restart the server while this tool waits)")
	fs.DurationVar(&cfg.StormTimeout, "storm-timeout", 10*time.Minute, "storm: how long to wait for recovery")
	fs.Float64Var(&cfg.ChurnPerSec, "churn-per-sec", 0, "churn: agents dropped per second (default 1% of the fleet)")
	fs.DurationVar(&cfg.ChurnAway, "churn-away", 10*time.Second, "churn: a dropped agent stays away for a random time up to this")
	fs.Float64Var(&cfg.JobFraction, "jobs-fraction", 0, "create a job through the REST API for this fraction of the fleet every --job-interval (needs --api)")
	fs.DurationVar(&cfg.JobInterval, "job-interval", 30*time.Second, "time between job waves")
	fs.StringVar(&cfg.JobKind, "job-kind", "inventory", "inventory, wu_scan or mixed")
	fs.Float64Var(&cfg.JobRate, "job-rate", 15, "maximum REST job requests per second (the API allows 20/s per address)")
	fs.DurationVar(&cfg.JobExecTime, "job-exec", 50*time.Millisecond, "simulated execution time of a job")
	fs.DurationVar(&cfg.BackoffBase, "backoff-base", time.Second, "reconnect backoff base (the agent's value)")
	fs.DurationVar(&cfg.BackoffMax, "backoff-max", 5*time.Minute, "reconnect backoff cap (the agent's value)")
	fs.StringVar(&cfg.IdentityCache, "identity-cache", "", "file that keeps enrolled identities (certificates and PRIVATE KEYS, mode 0600) so later runs against the same server do not enroll again")
	fs.IntVar(&cfg.ServerPID, "server-pid", 0, "sample CPU, memory and descriptors of this server process (same host)")
	fs.StringVar(&cfg.PGURL, "pg-url", "", "sample PostgreSQL counters and the audit log through this URL (optional)")
	fs.IntVar(&cfg.ReadBuffer, "read-buffer", 0, "gRPC read buffer per connection in bytes (0 = 32 KiB); lowering it saves memory with 10,000 agents")
	fs.IntVar(&cfg.WriteBuffer, "write-buffer", 0, "gRPC write buffer per connection in bytes (0 = 32 KiB)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg.Scenario = *scenario
	if cfg.Enrollment == "" {
		cfg.Enrollment = os.Getenv(*enrEnv)
	}
	cfg.APIToken = os.Getenv(*tokenEnv)
	lvl := slog.LevelInfo
	if *verbose {
		lvl = slog.LevelDebug
	}
	cfg.Log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	cfg.Version = "loadsim-" + version.Version

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rep, err := loadsim.Run(ctx, cfg)
	if err != nil {
		return err
	}
	if *report != "" {
		if err := rep.WriteJSON(*report); err != nil {
			return err
		}
	}
	md := rep.Markdown()
	if *mdReport != "" {
		if err := os.WriteFile(*mdReport, []byte(md), 0o600); err != nil {
			return err
		}
	}
	fmt.Print(md)
	if !rep.Pass && !*noFail {
		return errors.New("success criteria not met")
	}
	return nil
}
