package loadsim

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Report is the result of one run (the --report JSON file).
type Report struct {
	Tool       string    `json:"tool"`
	Scenario   string    `json:"scenario"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	DurationS  float64   `json:"duration_s"`

	Params map[string]any `json:"params"`

	Agents       int `json:"agents"`
	ConnectedMax int `json:"connected_max"`
	ConnectedEnd int `json:"connected_end"`

	Enrollment EnrollReport `json:"enrollment"`
	RampS      float64      `json:"ramp_to_99pct_s"`  // -1 when never reached
	SyncedS    float64      `json:"ramp_to_synced_s"` // until the first inventory reports were acknowledged too

	Phases []PhaseReport `json:"phases"`

	Storm *StormReport `json:"storm,omitempty"`
	Jobs  *JobStats    `json:"jobs,omitempty"`

	ServerView  *ServerView              `json:"server_view,omitempty"`
	ClientSelf  map[string]ResourceStats `json:"client_resources,omitempty"`
	ServerProc  map[string]ResourceStats `json:"server_process,omitempty"`
	Database    map[string]DBStats       `json:"database,omitempty"`
	AuditCounts map[string]int64         `json:"audit_since_start,omitempty"`
	DBError     string                   `json:"database_error,omitempty"`

	Connected []Point `json:"connected_series"`

	Pass     bool     `json:"pass"`
	Failures []string `json:"failures,omitempty"`
}

// EnrollReport covers identity acquisition.
type EnrollReport struct {
	Enrolled  int64   `json:"enrolled"`
	FromCache int64   `json:"from_cache"`
	Latency   Summary `json:"latency_ms"`
}

// PhaseReport is one phase's latency summaries and counters.
type PhaseReport struct {
	Name      string             `json:"name"`
	DurationS float64            `json:"duration_s"`
	Latency   map[string]Summary `json:"latency"`
	Counters  map[string]int64   `json:"counters"`
}

// StormReport is the reconnect storm result.
type StormReport struct {
	Mode            string             `json:"mode"`
	ConnectedAtDrop int                `json:"connected_at_drop"`
	TroughConnected int                `json:"trough_connected"`
	TimeToPct       map[string]float64 `json:"time_to_connected_s"` // t50pct, t90pct, t99pct, t100pct
	Recovered99     bool               `json:"recovered_99pct"`
	TimeoutS        float64            `json:"timeout_s"`
	// Attempts and failures during recovery, by class: the client-side view of what the server refused.
	ReconnectAttempts int64            `json:"reconnect_attempts"`
	Failures          map[string]int64 `json:"failures_by_class"`
	GoAways           map[string]int64 `json:"goaways"`
}

// ServerView is what the server itself reports through its API.
type ServerView struct {
	ActiveDevices int64 `json:"active_devices"`
	OnlineAtEnd   int64 `json:"online_at_end"`
}

// WriteJSON writes the report with mode 0600 to path.
func (r *Report) WriteJSON(path string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func fmtMs(v float64) string {
	switch {
	case v == 0:
		return "0"
	case v < 10:
		return fmt.Sprintf("%.2f", v)
	case v < 1000:
		return fmt.Sprintf("%.0f", v)
	default:
		return fmt.Sprintf("%.2fs", v/1000)
	}
}

// Markdown renders the report for a human.
func (r *Report) Markdown() string {
	var b strings.Builder
	verdict := "PASS"
	if !r.Pass {
		verdict = "FAIL"
	}
	fmt.Fprintf(&b, "## %s, %d agents: %s\n\n", r.Scenario, r.Agents, verdict)
	for _, f := range r.Failures {
		fmt.Fprintf(&b, "- FAILED: %s\n", f)
	}
	fmt.Fprintf(&b, "\nStarted %s, took %.0f s. Connected: peak %d, at end %d. Ramp to 99%%: ", r.StartedAt.Format(time.RFC3339), r.DurationS, r.ConnectedMax, r.ConnectedEnd)
	if r.RampS >= 0 {
		fmt.Fprintf(&b, "%.1f s (all initial inventory acknowledged after %.1f s).\n", r.RampS, r.SyncedS)
	} else {
		b.WriteString("not reached.\n")
	}
	fmt.Fprintf(&b, "Enrollment: %d enrolled, %d from the identity cache", r.Enrollment.Enrolled, r.Enrollment.FromCache)
	if r.Enrollment.Latency.Count > 0 {
		fmt.Fprintf(&b, "; enroll latency p50 %s, p99 %s", fmtMs(r.Enrollment.Latency.P50Ms), fmtMs(r.Enrollment.Latency.P99Ms))
	}
	b.WriteString(".\n")
	if r.ServerView != nil {
		fmt.Fprintf(&b, "Server's own count at the end: %d online of %d active.\n", r.ServerView.OnlineAtEnd, r.ServerView.ActiveDevices)
	}
	for _, p := range r.Phases {
		fmt.Fprintf(&b, "\n### Phase %q (%.0f s)\n\n", p.Name, p.DurationS)
		if len(p.Latency) > 0 {
			b.WriteString("| metric | count | p50 ms | p90 ms | p95 ms | p99 ms | max ms |\n|---|---:|---:|---:|---:|---:|---:|\n")
			for _, k := range sortedKeys(p.Latency) {
				s := p.Latency[k]
				fmt.Fprintf(&b, "| %s | %d | %s | %s | %s | %s | %s |\n", k, s.Count, fmtMs(s.P50Ms), fmtMs(s.P90Ms), fmtMs(s.P95Ms), fmtMs(s.P99Ms), fmtMs(s.MaxMs))
			}
		}
		if len(p.Counters) > 0 {
			b.WriteString("\nCounters: ")
			var parts []string
			for _, k := range sortedKeys(p.Counters) {
				parts = append(parts, fmt.Sprintf("%s=%d", k, p.Counters[k]))
			}
			b.WriteString(strings.Join(parts, ", ") + "\n")
		}
		if v, ok := r.ServerProc[p.Name]; ok {
			fmt.Fprintf(&b, "\nServer process: CPU avg %.0f%% / peak %.0f%% of one core, RSS peak %.0f MB, threads peak %d, fds peak %d.\n", v.CPUAvgPct, v.CPUPeakPct, v.RSSPeakMB, v.ThreadsPeak, v.FDsPeak)
		}
		if v, ok := r.ClientSelf[p.Name]; ok {
			fmt.Fprintf(&b, "Load generator: CPU avg %.0f%% / peak %.0f%%, RSS peak %.0f MB, goroutines peak %d, fds peak %d.\n", v.CPUAvgPct, v.CPUPeakPct, v.RSSPeakMB, v.GoroutinePk, v.FDsPeak)
		}
		if v, ok := r.Database[p.Name]; ok {
			fmt.Fprintf(&b, "PostgreSQL: %.0f commits/s avg (peak %.0f), %.0f rows inserted/s, %.0f updated/s, backends peak %d, active queries peak %d, lock waiters peak %d.\n", v.TPSAvg, v.TPSPeak, v.RowsInsAvg, v.RowsUpdAvg, v.BackendsPeak, v.ActivePeak, v.LockWaitPeak)
		}
	}
	if s := r.Storm; s != nil {
		fmt.Fprintf(&b, "\n### Reconnect storm (%s)\n\n", s.Mode)
		fmt.Fprintf(&b, "Connected at the drop: %d; trough: %d. Time until connected reached: ", s.ConnectedAtDrop, s.TroughConnected)
		var parts []string
		for _, k := range []string{"t50pct", "t90pct", "t99pct", "t100pct"} {
			if v, ok := s.TimeToPct[k]; ok {
				parts = append(parts, fmt.Sprintf("%s %.1f s", strings.TrimSuffix(strings.TrimPrefix(k, "t"), "pct")+"%", v))
			} else {
				parts = append(parts, strings.TrimSuffix(strings.TrimPrefix(k, "t"), "pct")+"% never")
			}
		}
		b.WriteString(strings.Join(parts, ", ") + ".\n")
		fmt.Fprintf(&b, "Reconnect attempts: %d. Failures by class: %v. Server goaways: %v.\n", s.ReconnectAttempts, s.Failures, s.GoAways)
	}
	if j := r.Jobs; j != nil && j.Created > 0 {
		fmt.Fprintf(&b, "\n### Jobs\n\nCreated %d, offered %d, completed %d, lost %d.\n\n", j.Created, j.Offered, j.Completed, j.Lost)
		b.WriteString("| latency | count | p50 ms | p95 ms | p99 ms | max ms |\n|---|---:|---:|---:|---:|---:|\n")
		for _, row := range []struct {
			n string
			s Summary
		}{{"REST request to agent verified the offer", j.Dispatch}, {"result sent to acknowledged", j.ResultRTT}, {"REST request to result acknowledged (end to end)", j.EndToEnd}} {
			fmt.Fprintf(&b, "| %s | %d | %s | %s | %s | %s |\n", row.n, row.s.Count, fmtMs(row.s.P50Ms), fmtMs(row.s.P95Ms), fmtMs(row.s.P99Ms), fmtMs(row.s.MaxMs))
		}
	}
	if len(r.AuditCounts) > 0 {
		b.WriteString("\nServer audit entries written during the run: ")
		var parts []string
		for _, k := range sortedKeys(r.AuditCounts) {
			parts = append(parts, fmt.Sprintf("%s=%d", k, r.AuditCounts[k]))
		}
		b.WriteString(strings.Join(parts, ", ") + "\n")
	}
	return b.String()
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
