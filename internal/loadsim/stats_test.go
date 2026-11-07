package loadsim

import (
	"math"
	"math/rand/v2"
	"sync"
	"testing"
	"time"
)

func within(t *testing.T, name string, got, want time.Duration, tol float64) {
	t.Helper()
	if want == 0 {
		if got != 0 {
			t.Errorf("%s = %v, want 0", name, got)
		}
		return
	}
	if err := math.Abs(float64(got-want)) / float64(want); err > tol {
		t.Errorf("%s = %v, want %v (error %.1f%% > %.1f%%)", name, got, want, err*100, tol*100)
	}
}

func TestBucketsAreMonotonicAndContainTheirValues(t *testing.T) {
	prevHi := int64(0)
	for b := 0; b < histSub*40; b++ {
		lo, hi := bucketBounds(b)
		if lo != prevHi {
			t.Fatalf("bucket %d starts at %d, previous ended at %d (gap or overlap)", b, lo, prevHi)
		}
		if hi <= lo {
			t.Fatalf("bucket %d is empty: [%d,%d)", b, lo, hi)
		}
		for _, v := range []int64{lo, (lo + hi) / 2, hi - 1} {
			if got := bucketOf(v); got != b {
				t.Fatalf("value %d maps to bucket %d, want %d [%d,%d)", v, got, b, lo, hi)
			}
		}
		prevHi = hi
	}
}

func TestHistEmpty(t *testing.T) {
	h := NewHist()
	if h.Count() != 0 || h.Quantile(0.5) != 0 || h.Summary() != (Summary{}) {
		t.Fatalf("empty histogram not zero: %+v", h.Summary())
	}
}

func TestHistSingleValueIsExactAtEveryQuantile(t *testing.T) {
	h := NewHist()
	h.Record(1234 * time.Microsecond)
	s := h.Summary()
	if s.Count != 1 || s.MinMs != 1.234 || s.MaxMs != 1.234 || s.P50Ms != 1.234 || s.P999Ms != 1.234 || s.MeanMs != 1.234 {
		t.Fatalf("%+v", s)
	}
}

func TestHistPercentilesOnUniformData(t *testing.T) {
	h := NewHist()
	// 1ms .. 10s, 100,000 samples evenly spread: percentile q is q * 10s.
	const n = 100000
	for i := 1; i <= n; i++ {
		h.Record(time.Duration(i) * 100 * time.Microsecond)
	}
	for _, q := range []float64{0.5, 0.9, 0.95, 0.99, 0.999} {
		within(t, "q", h.Quantile(q), time.Duration(q*float64(10*time.Second)), 0.04)
	}
	s := h.Summary()
	if s.Count != n || s.MinMs != 0.1 || s.MaxMs != 10000 {
		t.Fatalf("summary: %+v", s)
	}
	within(t, "mean", time.Duration(s.MeanMs*float64(time.Millisecond)), 5*time.Second, 0.001)
}

func TestHistPercentilesOnSkewedData(t *testing.T) {
	// 99% fast (about 5 ms), 1% slow (about 2 s): p50 is fast, p99.9 is slow.
	h := NewHist()
	r := rand.New(rand.NewPCG(1, 2))
	var exact []time.Duration
	for i := 0; i < 50000; i++ {
		d := 5*time.Millisecond + time.Duration(r.IntN(2000))*time.Microsecond
		if i%100 == 0 {
			d = 2*time.Second + time.Duration(r.IntN(100))*time.Millisecond
		}
		h.Record(d)
		exact = append(exact, d)
	}
	SortDurations(exact)
	for _, q := range []float64{0.5, 0.9, 0.99, 0.995, 0.999} {
		within(t, "skewed", h.Quantile(q), Percentile(exact, q), 0.04)
	}
}

func TestHistClampsNegativeAndHugeValues(t *testing.T) {
	h := NewHist()
	h.Record(-5 * time.Second)
	h.Record(time.Duration(math.MaxInt64))
	if h.Count() != 2 {
		t.Fatal(h.Count())
	}
	if h.Quantile(0) != 0 || h.Quantile(1) <= 0 {
		t.Fatalf("q0=%v q1=%v", h.Quantile(0), h.Quantile(1))
	}
}

func TestHistConcurrentRecording(t *testing.T) {
	h := NewHist()
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5000; i++ {
				h.Record(time.Duration(i+1) * time.Microsecond)
			}
		}()
	}
	wg.Wait()
	if h.Count() != 16*5000 {
		t.Fatalf("lost observations: %d", h.Count())
	}
	within(t, "p50", h.Quantile(0.5), 2500*time.Microsecond, 0.04)
}

func TestCounters(t *testing.T) {
	c := NewCounters()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				c.Inc("a")
				c.Add("b", 2)
			}
		}()
	}
	wg.Wait()
	if c.Get("a") != 8000 || c.Get("b") != 16000 || c.Get("missing") != 0 {
		t.Fatalf("%v", c.Snapshot())
	}
	snap := c.Snapshot()
	snap["a"] = 0
	if c.Get("a") != 8000 {
		t.Fatal("snapshot aliases the live counters")
	}
}

func TestHistsOnlySummarizeNonEmpty(t *testing.T) {
	hs := NewHists()
	hs.Get("empty")
	hs.Get("used").Record(time.Millisecond)
	s := hs.Summaries()
	if len(s) != 1 || s["used"].Count != 1 {
		t.Fatalf("%v", s)
	}
}

func TestRecoveryTracksThresholds(t *testing.T) {
	t0 := time.Unix(1000, 0)
	r := NewRecovery(1000, t0, 0.5, 0.9, 0.99, 1)
	obs := []struct {
		at        time.Duration
		connected int
	}{{0, 0}, {time.Second, 400}, {2 * time.Second, 500}, {3 * time.Second, 899}, {4 * time.Second, 900},
		{5 * time.Second, 989}, {6 * time.Second, 990}, {7 * time.Second, 960}, {8 * time.Second, 1000}}
	for _, o := range obs {
		r.Observe(t0.Add(o.at), o.connected)
	}
	want := map[float64]time.Duration{0.5: 2 * time.Second, 0.9: 4 * time.Second, 0.99: 6 * time.Second, 1: 8 * time.Second}
	for f, w := range want {
		got, ok := r.Reached(f)
		if !ok || got != w {
			t.Errorf("fraction %v reached at %v (ok=%v), want %v", f, got, ok, w)
		}
	}
	if r.Peak != 1000 || r.Trough != 0 {
		t.Errorf("peak/trough %d/%d", r.Peak, r.Trough)
	}
	times := r.Times()
	if times["t99pct"] != 6 || times["t50pct"] != 2 || times["t100pct"] != 8 {
		t.Errorf("%v", times)
	}
}

func TestRecoveryNeverReached(t *testing.T) {
	t0 := time.Now()
	r := NewRecovery(100, t0, 0.99)
	r.Observe(t0.Add(time.Second), 98)
	if _, ok := r.Reached(0.99); ok {
		t.Fatal("98 of 100 is not 99%")
	}
	if len(r.Times()) != 0 {
		t.Fatal("unexpected times")
	}
	// 99.9% names keep their decimals.
	if got := fracName(0.999); got != "t99.9pct" {
		t.Fatal(got)
	}
}

func TestSeriesThrottles(t *testing.T) {
	s := NewSeries(time.Second)
	t0 := time.Unix(0, 0)
	for i := 0; i < 50; i++ {
		s.Add(t0.Add(time.Duration(i)*100*time.Millisecond), float64(i)/10, float64(i))
	}
	if n := len(s.Points()); n != 5 {
		t.Fatalf("expected one point per second over 5 s, got %d", n)
	}
}

func TestPercentileHelper(t *testing.T) {
	d := []time.Duration{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if Percentile(d, 0.5) != 5 || Percentile(d, 1) != 10 || Percentile(d, 0) != 1 || Percentile(nil, 0.5) != 0 {
		t.Fatal("percentile helper wrong")
	}
}
