package loadsim

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// ResourceStats summarizes CPU, memory and descriptors of a process over a phase.
type ResourceStats struct {
	Samples     int     `json:"samples"`
	CPUAvgPct   float64 `json:"cpu_avg_pct"` // of one core; 400 means four cores busy
	CPUPeakPct  float64 `json:"cpu_peak_pct"`
	RSSPeakMB   float64 `json:"rss_peak_mb"`
	RSSEndMB    float64 `json:"rss_end_mb"`
	ThreadsPeak int     `json:"threads_peak"`
	FDsPeak     int     `json:"fds_peak"`
	GoroutinePk int     `json:"goroutines_peak,omitempty"`
	HeapEndMB   float64 `json:"go_heap_end_mb,omitempty"`
	cpuSum      float64
}

func (r *ResourceStats) add(cpu, rss float64, threads, fds int) {
	r.Samples++
	r.cpuSum += cpu
	r.CPUAvgPct = r.cpuSum / float64(r.Samples)
	r.CPUPeakPct = max(r.CPUPeakPct, cpu)
	r.RSSPeakMB = max(r.RSSPeakMB, rss)
	r.RSSEndMB = rss
	r.ThreadsPeak = max(r.ThreadsPeak, threads)
	r.FDsPeak = max(r.FDsPeak, fds)
}

// procInfo reads /proc/<pid> (Linux). ok is false when it cannot.
func procInfo(pid string) (cpuTicks uint64, rssMB float64, threads, fds int, ok bool) {
	st, err := os.ReadFile("/proc/" + pid + "/stat") // #nosec G304 -- pid is a decimal process ID
	if err != nil {
		return
	}
	s := string(st)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return
	}
	f := strings.Fields(s[i+2:]) // fields from #3 (state) on
	if len(f) < 22 {
		return
	}
	ut, _ := strconv.ParseUint(f[11], 10, 64) // field 14 utime
	stt, _ := strconv.ParseUint(f[12], 10, 64)
	cpuTicks = ut + stt
	threads, _ = strconv.Atoi(f[17]) // field 20 num_threads
	rss, _ := strconv.ParseUint(f[21], 10, 64)
	rssMB = float64(rss) * float64(os.Getpagesize()) / (1 << 20)
	if d, err := os.ReadDir("/proc/" + pid + "/fd"); err == nil {
		fds = len(d)
	}
	return cpuTicks, rssMB, threads, fds, true
}

const clockTicks = 100 // USER_HZ on Linux

// sampleProc samples a process every interval and files the numbers under the current phase.
type procSampler struct {
	mu   sync.Mutex
	by   map[string]*ResourceStats
	pid  string
	self bool
}

func newProcSampler(pid string, self bool) *procSampler {
	return &procSampler{by: map[string]*ResourceStats{}, pid: pid, self: self}
}

func (p *procSampler) run(ctx context.Context, f *fleet, every time.Duration) {
	lastTicks, _, _, _, ok := procInfo(p.pid)
	if !ok {
		return
	}
	last := time.Now()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Time the reading itself: a tick can be delivered late when the host is saturated.
			now := time.Now() // the reading starts with /proc/<pid>/stat; the slow descriptor count comes after it
			ticks, rss, th, fds, ok := procInfo(p.pid)
			if !ok {
				continue
			}
			dt := now.Sub(last).Seconds()
			if dt < 0.5 {
				continue // a late tick delivered right behind the previous one; CPU ticks are 10 ms quanta
			}
			cpu := float64(ticks-lastTicks) / clockTicks / dt * 100
			lastTicks, last = ticks, now
			name := f.cur.Load().name
			p.mu.Lock()
			r := p.by[name]
			if r == nil {
				r = &ResourceStats{}
				p.by[name] = r
			}
			r.add(cpu, rss, th, fds)
			if p.self {
				r.GoroutinePk = max(r.GoroutinePk, runtime.NumGoroutine())
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				r.HeapEndMB = float64(ms.HeapAlloc) / (1 << 20)
			}
			p.mu.Unlock()
		}
	}
}

func (p *procSampler) result() map[string]ResourceStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]ResourceStats{}
	for k, v := range p.by {
		out[k] = *v
	}
	return out
}

// DBStats summarizes PostgreSQL activity over a phase.
type DBStats struct {
	Samples                int     `json:"samples"`
	TPSAvg                 float64 `json:"commits_per_s_avg"`
	TPSPeak                float64 `json:"commits_per_s_peak"`
	RowsInsAvg             float64 `json:"rows_inserted_per_s_avg"`
	RowsUpdAvg             float64 `json:"rows_updated_per_s_avg"`
	BackendsPeak           int     `json:"backends_peak"`
	ActivePeak             int     `json:"active_queries_peak"`
	LockWaitPeak           int     `json:"lock_waiters_peak"`
	IdleInTxPeak           int     `json:"idle_in_transaction_peak"`
	tpsSum, insSum, updSum float64
}

type dbSampler struct {
	mu    sync.Mutex
	by    map[string]*DBStats
	url   string
	err   string
	audit map[string]int64
}

func newDBSampler(url string) *dbSampler { return &dbSampler{by: map[string]*DBStats{}, url: url} }

func (d *dbSampler) run(ctx context.Context, f *fleet, every time.Duration) {
	conn, err := pgx.Connect(ctx, d.url)
	if err != nil {
		d.mu.Lock()
		d.err = err.Error()
		d.mu.Unlock()
		return
	}
	defer func() { _ = conn.Close(context.Background()) }()
	type snap struct{ commits, ins, upd int64 }
	read := func() (s snap, backends, active, lockw, idletx int, err error) {
		err = conn.QueryRow(ctx, `SELECT xact_commit + xact_rollback, tup_inserted, tup_updated, numbackends
			FROM pg_stat_database WHERE datname = current_database()`).Scan(&s.commits, &s.ins, &s.upd, &backends)
		if err != nil {
			return
		}
		err = conn.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state = 'active'),
				count(*) FILTER (WHERE wait_event_type = 'Lock'), count(*) FILTER (WHERE state = 'idle in transaction')
			FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()`).Scan(&active, &lockw, &idletx)
		return
	}
	prev, _, _, _, _, err := read()
	if err != nil {
		d.mu.Lock()
		d.err = err.Error()
		d.mu.Unlock()
		return
	}
	last := time.Now()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			cur, be, act, lw, itx, err := read()
			if err != nil {
				continue
			}
			dt := now.Sub(last).Seconds()
			if dt < 0.5 {
				continue // a late tick delivered right behind the previous one: too short to divide by
			}
			last = now
			tps, ins, upd := float64(cur.commits-prev.commits)/dt, float64(cur.ins-prev.ins)/dt, float64(cur.upd-prev.upd)/dt
			prev = cur
			name := f.cur.Load().name
			d.mu.Lock()
			s := d.by[name]
			if s == nil {
				s = &DBStats{}
				d.by[name] = s
			}
			s.Samples++
			s.tpsSum, s.insSum, s.updSum = s.tpsSum+tps, s.insSum+ins, s.updSum+upd
			s.TPSAvg, s.RowsInsAvg, s.RowsUpdAvg = s.tpsSum/float64(s.Samples), s.insSum/float64(s.Samples), s.updSum/float64(s.Samples)
			s.TPSPeak = max(s.TPSPeak, tps)
			s.BackendsPeak, s.ActivePeak = max(s.BackendsPeak, be), max(s.ActivePeak, act)
			s.LockWaitPeak, s.IdleInTxPeak = max(s.LockWaitPeak, lw), max(s.IdleInTxPeak, itx)
			d.mu.Unlock()
		}
	}
}

// auditCounts counts audit entries by action written since t (the server's own record of what the
// run caused, such as enrollments, certificate issues and protocol violations).
func (d *dbSampler) auditCounts(ctx context.Context, since time.Time) {
	conn, err := pgx.Connect(ctx, d.url)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close(context.Background()) }()
	rows, err := conn.Query(ctx, `SELECT action, outcome, count(*) FROM audit_log WHERE ts >= $1 GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 40`, since)
	if err != nil {
		return
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var a, o string
		var n int64
		if rows.Scan(&a, &o, &n) == nil {
			out[a+" ("+o+")"] = n
		}
	}
	d.mu.Lock()
	d.audit = out
	d.mu.Unlock()
}

func (d *dbSampler) result() (map[string]DBStats, map[string]int64, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string]DBStats{}
	for k, v := range d.by {
		out[k] = *v
	}
	return out, d.audit, d.err
}
