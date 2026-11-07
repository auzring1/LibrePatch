package loadsim

import (
	"math"
	"math/bits"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Hist is a concurrency-safe latency histogram with log-linear buckets: every power of two of
// nanoseconds is split into 32 equal parts, so any reported percentile is within about 3% of the
// true value. Recording is one atomic add, which keeps it cheap with 10,000 goroutines.
type Hist struct {
	counts [histExps * histSub]atomic.Uint64
	n      atomic.Uint64
	sum    atomic.Uint64 // nanoseconds
	min    atomic.Int64
	max    atomic.Int64
}

const (
	histSubBits = 5
	histSub     = 1 << histSubBits
	histExps    = 64
)

// NewHist returns an empty histogram.
func NewHist() *Hist {
	h := &Hist{}
	h.min.Store(math.MaxInt64)
	return h
}

func bucketOf(ns int64) int {
	if ns < histSub {
		return int(max(ns, 0)) // exact for tiny values
	}
	exp := bits.Len64(uint64(ns)) - 1                               // >= histSubBits
	sub := int(uint64(ns)>>(uint(exp)-histSubBits)) & (histSub - 1) // #nosec G115 -- masked to 5 bits
	return (exp-histSubBits+1)*histSub + sub
}

// bucketBounds returns the [lo, hi) nanosecond range of bucket b.
func bucketBounds(b int) (lo, hi int64) {
	if b < histSub {
		return int64(b), int64(b) + 1
	}
	exp := b/histSub + histSubBits - 1
	sub := int64(b % histSub)
	width := int64(1) << (uint(exp) - histSubBits)
	lo = (int64(1) << uint(exp)) + sub*width
	return lo, lo + width
}

// Record adds one observation.
func (h *Hist) Record(d time.Duration) {
	ns := int64(d)
	if ns < 0 {
		ns = 0
	}
	b := bucketOf(ns)
	if b >= len(h.counts) {
		b = len(h.counts) - 1
	}
	h.counts[b].Add(1)
	h.n.Add(1)
	h.sum.Add(uint64(ns))
	for {
		cur := h.min.Load()
		if ns >= cur || h.min.CompareAndSwap(cur, ns) {
			break
		}
	}
	for {
		cur := h.max.Load()
		if ns <= cur || h.max.CompareAndSwap(cur, ns) {
			break
		}
	}
}

// Count is the number of observations.
func (h *Hist) Count() uint64 { return h.n.Load() }

// Quantile returns the q-quantile (0..1) as the midpoint of the bucket that holds it, clamped to the
// observed minimum and maximum. It returns 0 for an empty histogram.
func (h *Hist) Quantile(q float64) time.Duration {
	n := h.n.Load()
	if n == 0 {
		return 0
	}
	q = math.Min(math.Max(q, 0), 1)
	rank := uint64(math.Ceil(q * float64(n)))
	if rank == 0 {
		rank = 1
	}
	var seen uint64
	for b := range h.counts {
		c := h.counts[b].Load()
		if c == 0 {
			continue
		}
		seen += c
		if seen >= rank {
			lo, hi := bucketBounds(b)
			mid := lo + (hi-lo)/2
			mid = max(mid, h.min.Load())
			mid = min(mid, h.max.Load())
			return time.Duration(mid)
		}
	}
	return time.Duration(h.max.Load())
}

// Summary is the JSON form of a histogram. All durations are milliseconds.
type Summary struct {
	Count  uint64  `json:"count"`
	MinMs  float64 `json:"min_ms"`
	MeanMs float64 `json:"mean_ms"`
	P50Ms  float64 `json:"p50_ms"`
	P90Ms  float64 `json:"p90_ms"`
	P95Ms  float64 `json:"p95_ms"`
	P99Ms  float64 `json:"p99_ms"`
	P999Ms float64 `json:"p999_ms"`
	MaxMs  float64 `json:"max_ms"`
}

func ms(d time.Duration) float64 { return math.Round(float64(d)/float64(time.Millisecond)*1000) / 1000 }

// Summary snapshots the histogram.
func (h *Hist) Summary() Summary {
	n := h.n.Load()
	if n == 0 {
		return Summary{}
	}
	return Summary{
		Count:  n,
		MinMs:  ms(time.Duration(h.min.Load())),
		MeanMs: ms(time.Duration(h.sum.Load() / n)), // #nosec G115 -- a sum of nanoseconds stays far below 2^63
		P50Ms:  ms(h.Quantile(0.50)),
		P90Ms:  ms(h.Quantile(0.90)),
		P95Ms:  ms(h.Quantile(0.95)),
		P99Ms:  ms(h.Quantile(0.99)),
		P999Ms: ms(h.Quantile(0.999)),
		MaxMs:  ms(time.Duration(h.max.Load())),
	}
}

// Counters is a set of named, concurrency-safe counters.
type Counters struct {
	mu sync.RWMutex
	m  map[string]*atomic.Int64
}

// NewCounters returns an empty set.
func NewCounters() *Counters { return &Counters{m: map[string]*atomic.Int64{}} }

// Add increases the named counter.
func (c *Counters) Add(name string, n int64) {
	c.mu.RLock()
	v := c.m[name]
	c.mu.RUnlock()
	if v == nil {
		c.mu.Lock()
		if v = c.m[name]; v == nil {
			v = new(atomic.Int64)
			c.m[name] = v
		}
		c.mu.Unlock()
	}
	v.Add(n)
}

// Inc adds one.
func (c *Counters) Inc(name string) { c.Add(name, 1) }

// Get returns the current value (0 if unknown).
func (c *Counters) Get(name string) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if v := c.m[name]; v != nil {
		return v.Load()
	}
	return 0
}

// Snapshot copies all counters.
func (c *Counters) Snapshot() map[string]int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]int64, len(c.m))
	for k, v := range c.m {
		out[k] = v.Load()
	}
	return out
}

// Hists is a named set of histograms.
type Hists struct {
	mu sync.RWMutex
	m  map[string]*Hist
}

// NewHists returns an empty set.
func NewHists() *Hists { return &Hists{m: map[string]*Hist{}} }

// Get returns (creating) the named histogram.
func (hs *Hists) Get(name string) *Hist {
	hs.mu.RLock()
	h := hs.m[name]
	hs.mu.RUnlock()
	if h != nil {
		return h
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if h = hs.m[name]; h == nil {
		h = NewHist()
		hs.m[name] = h
	}
	return h
}

// Summaries snapshots every histogram that has data.
func (hs *Hists) Summaries() map[string]Summary {
	hs.mu.RLock()
	defer hs.mu.RUnlock()
	out := map[string]Summary{}
	for k, h := range hs.m {
		if h.Count() > 0 {
			out[k] = h.Summary()
		}
	}
	return out
}

// Recovery watches a "connected" gauge after a disruption and notes when it first reaches given
// fractions of the target. Call Observe regularly (the scenario samples every 100 ms).
type Recovery struct {
	target int
	start  time.Time
	fracs  []float64
	at     []time.Duration // -1 until reached
	// Peak is the highest connected count seen since the start.
	Peak int
	// Trough is the lowest count seen (the depth of the drop).
	Trough int
}

// NewRecovery starts a recovery clock. fracs must be ascending, for example 0.5, 0.9, 0.99, 1.
func NewRecovery(target int, start time.Time, fracs ...float64) *Recovery {
	r := &Recovery{target: target, start: start, fracs: fracs, at: make([]time.Duration, len(fracs)), Trough: target}
	for i := range r.at {
		r.at[i] = -1
	}
	return r
}

// Observe records the connected count seen at time now.
func (r *Recovery) Observe(now time.Time, connected int) {
	r.Peak = max(r.Peak, connected)
	r.Trough = min(r.Trough, connected)
	for i, f := range r.fracs {
		if r.at[i] < 0 && float64(connected) >= math.Ceil(f*float64(r.target)) {
			r.at[i] = now.Sub(r.start)
		}
	}
}

// Reached reports the time at which fraction f was first reached (false if not yet).
func (r *Recovery) Reached(f float64) (time.Duration, bool) {
	for i, ff := range r.fracs {
		if ff == f && r.at[i] >= 0 {
			return r.at[i], true
		}
	}
	return 0, false
}

// Times returns "pNN" -> seconds for every fraction reached, e.g. {"p99": 12.4}.
func (r *Recovery) Times() map[string]float64 {
	out := map[string]float64{}
	for i, f := range r.fracs {
		if r.at[i] >= 0 {
			out[fracName(f)] = math.Round(r.at[i].Seconds()*1000) / 1000
		}
	}
	return out
}

func fracName(f float64) string {
	return "t" + strconv.FormatFloat(math.Round(f*1000)/10, 'f', -1, 64) + "pct"
}

// Series is a small ring of (time, value) samples for the report's time series.
type Series struct {
	mu   sync.Mutex
	pts  []Point
	step time.Duration
	last time.Time
}

// Point is one sample.
type Point struct {
	T float64 `json:"t_s"`
	V float64 `json:"v"`
}

// NewSeries keeps at most one point per step.
func NewSeries(step time.Duration) *Series { return &Series{step: step} }

// Add records v at t (seconds since the scenario start) if a step has elapsed since the last point.
func (s *Series) Add(now time.Time, t float64, v float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.last.IsZero() && now.Sub(s.last) < s.step {
		return
	}
	s.last = now
	s.pts = append(s.pts, Point{T: math.Round(t*1000) / 1000, V: v})
}

// Points returns a copy.
func (s *Series) Points() []Point {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Point, len(s.pts))
	copy(out, s.pts)
	return out
}

// Percentile of a plain slice (exact), used for small sets such as per-job latencies.
func Percentile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(q*float64(len(sorted)))) - 1
	idx = min(max(idx, 0), len(sorted)-1)
	return sorted[idx]
}

// SortDurations sorts ascending in place.
func SortDurations(d []time.Duration) { sort.Slice(d, func(i, j int) bool { return d[i] < d[j] }) }
