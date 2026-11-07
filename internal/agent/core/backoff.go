package core

import (
	"math/rand/v2"
	"time"
)

// Backoff implements exponential backoff with full jitter (PROTOCOL §7):
// sleep = rand(0, min(Max, Base * 2^n)).
type Backoff struct {
	Base, Max time.Duration
	// Start, FastFor and FastMax: for the first FastFor after Start the cap is FastMax instead of Max. A computer that
	// has just started often has no network or name resolution for a while; with the full cap a few early failures
	// could leave it waiting minutes after the network came up. Zero values turn this off.
	Start            time.Time
	FastFor, FastMax time.Duration
	// Now is the clock (tests); nil means time.Now.
	Now func() time.Time
	n   int
}

// Next returns the next delay and advances the attempt counter.
func (b *Backoff) Next() time.Duration {
	limit := b.Max
	if b.FastFor > 0 && b.FastMax > 0 && b.FastMax < limit && !b.Start.IsZero() {
		now := time.Now
		if b.Now != nil {
			now = b.Now
		}
		if now().Sub(b.Start) < b.FastFor {
			limit = b.FastMax
		}
	}
	ceil := b.Base << min(b.n, 30)
	if ceil > limit || ceil <= 0 {
		ceil = limit
	}
	b.n++
	return time.Duration(rand.Int64N(int64(ceil) + 1)) // #nosec G404 -- jitter, not security
}

// Reset clears the attempt counter.
func (b *Backoff) Reset() { b.n = 0 }

// jitter returns d plus a random amount in [0, extra].
func jitter(d, extra time.Duration) time.Duration {
	if extra <= 0 {
		return d
	}
	return d + time.Duration(rand.Int64N(int64(extra)+1)) // #nosec G404 -- jitter
}
