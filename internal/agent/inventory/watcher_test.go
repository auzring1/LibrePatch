package inventory

import (
	"context"
	"testing"
	"time"
)

func TestDebouncerCoalescesBursts(t *testing.T) {
	ev := make(chan struct{}, 8)
	d := Debouncer{Quiet: 80 * time.Millisecond}
	go func() {
		for i := 0; i < 5; i++ { // a burst: each event restarts the quiet period
			ev <- struct{}{}
			time.Sleep(30 * time.Millisecond)
		}
	}()
	start := time.Now()
	if !d.Wait(context.Background(), ev) {
		t.Fatal("Wait returned false")
	}
	if el := time.Since(start); el < 150*time.Millisecond { // a non-coalescing debouncer would fire at ~80ms
		t.Fatalf("fired too early (%v): burst not coalesced", el)
	}
}

func TestDebouncerStopsOnContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if (Debouncer{Quiet: time.Second}).Wait(ctx, make(chan struct{})) {
		t.Fatal("should return false on cancelled context")
	}
	ev := make(chan struct{})
	close(ev)
	if (Debouncer{Quiet: time.Second}).Wait(context.Background(), ev) {
		t.Fatal("closed channel should end Wait")
	}
}
