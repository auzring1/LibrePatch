package gateway

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGateBoundsConcurrency(t *testing.T) {
	g := newGate(3)
	var inside, peak atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := g.acquire(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			n := inside.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			inside.Add(-1)
			rel()
		}()
	}
	wg.Wait()
	if peak.Load() > 3 || peak.Load() < 2 {
		t.Fatalf("peak concurrency %d, want 2 or 3 (limit 3)", peak.Load())
	}
}

func TestGateGivesUpWhenTheContextEnds(t *testing.T) {
	g := newGate(1)
	rel, err := g.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if r, err := g.acquire(ctx); err == nil || r != nil {
		t.Fatal("a full gate admitted a caller whose context ended")
	}
	rel()
	if r, err := g.acquire(context.Background()); err != nil {
		t.Fatal(err)
	} else {
		r()
	}
}
