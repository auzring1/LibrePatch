package auth

import (
	"slices"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter is a keyed token-bucket limiter with idle-entry eviction.
type Limiter struct {
	mu      sync.Mutex
	r       rate.Limit
	burst   int
	entries map[string]*limEntry
	maxKeys int
}

type limEntry struct {
	lim  *rate.Limiter
	seen time.Time
}

// NewLimiter allows `burst` events immediately and then `per` events per interval.
func NewLimiter(per int, interval time.Duration, burst int) *Limiter {
	return &Limiter{r: rate.Limit(float64(per) / interval.Seconds()), burst: burst,
		entries: make(map[string]*limEntry), maxKeys: 100000}
}

// Allow reports whether an event for key may proceed now.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= l.maxKeys {
			l.evict(now)
		}
		e = &limEntry{lim: rate.NewLimiter(l.r, l.burst)}
		l.entries[key] = e
	}
	e.seen = now
	return e.lim.AllowN(now, 1)
}

// evict drops entries idle for ten minutes. If the table is still full (someone is filling it with made-up keys), it
// also drops the least recently seen tenth, so the buckets of keys that are in use, such as an account under attack,
// survive instead of being reset together with everything else.
func (l *Limiter) evict(now time.Time) {
	for k, e := range l.entries {
		if now.Sub(e.seen) > 10*time.Minute {
			delete(l.entries, k)
		}
	}
	if len(l.entries) < l.maxKeys {
		return
	}
	type aged struct {
		key  string
		seen time.Time
	}
	all := make([]aged, 0, len(l.entries))
	for k, e := range l.entries {
		all = append(all, aged{k, e.seen})
	}
	slices.SortFunc(all, func(a, b aged) int { return a.seen.Compare(b.seen) })
	for _, a := range all[:max(1, len(all)/10)] {
		delete(l.entries, a.key)
	}
}

// Sweep removes idle entries; call periodically.
func (l *Limiter) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evict(time.Now())
}
