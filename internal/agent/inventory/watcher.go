package inventory

import (
	"context"
	"time"
)

// Debouncer coalesces bursts of change notifications (an installer writes
// dozens of registry values) into one scan after a quiet period.
type Debouncer struct {
	Quiet time.Duration
}

// Wait consumes events and returns once the first event has been followed by
// Quiet of silence, or when ctx ends (returning false).
func (d Debouncer) Wait(ctx context.Context, events <-chan struct{}) bool {
	select {
	case <-ctx.Done():
		return false
	case _, ok := <-events:
		if !ok {
			return false
		}
	}
	t := time.NewTimer(d.Quiet)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-events:
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
			t.Reset(d.Quiet)
		case <-t.C:
			return true
		}
	}
}
