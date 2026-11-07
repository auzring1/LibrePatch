package gateway

import "context"

// gate bounds how many callers are inside a section at once; the rest wait their turn (or give up
// when their context ends).
//
// Enrollment uses one. Enrollments serialize on the enrollment-token row and on the audit chain
// anyway, so extra concurrency buys nothing, but every one of them holds a database connection while
// it waits for those locks. Unbounded, a burst of enrolling devices occupied the entire connection
// pool and the mTLS handshakes of already enrolled devices (which look the device up in the database)
// timed out, which looked like a connection failure to every agent and made them retry (found by
// cmd/librepatch-loadsim with 10,000 agents).
type gate chan struct{}

func newGate(n int) gate { return make(gate, n) }

// acquire waits for a free slot. The returned function frees it; it is nil when ctx ended first.
func (g gate) acquire(ctx context.Context) (release func(), err error) {
	select {
	case g <- struct{}{}:
		return func() { <-g }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
