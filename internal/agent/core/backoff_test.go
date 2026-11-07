package core

import (
	"testing"
	"time"
)

func TestBackoffStartupWindowCapsTheDelay(t *testing.T) {
	now := time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC)
	b := &Backoff{Base: time.Second, Max: 5 * time.Minute, Start: now, FastFor: 10 * time.Minute, FastMax: 15 * time.Second, Now: func() time.Time { return now }}
	for i := 0; i < 40; i++ { // many failures in a row: the ceiling would be 5 minutes without the window
		if d := b.Next(); d > 15*time.Second {
			t.Fatalf("attempt %d waited %v inside the startup window, want at most 15s", i, d)
		}
	}
	// After the window the normal cap applies again (the ceiling is already at its maximum after 40 attempts).
	now = now.Add(11 * time.Minute)
	max := time.Duration(0)
	for i := 0; i < 400; i++ {
		if d := b.Next(); d > max {
			max = d
		}
		if max > 15*time.Second {
			break
		}
	}
	if max <= 15*time.Second || max > 5*time.Minute {
		t.Fatalf("after the window the delay should reach beyond 15s and stay within 5 minutes, got max %v", max)
	}
}

func TestBackoffWithoutWindowIsUnchanged(t *testing.T) {
	b := &Backoff{Base: time.Second, Max: 8 * time.Second}
	for i := 0; i < 50; i++ {
		if d := b.Next(); d > 8*time.Second {
			t.Fatalf("delay %v above the cap", d)
		}
	}
}
