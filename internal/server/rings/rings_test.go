package rings

import (
	"strings"
	"testing"
	"time"
)

func TestGate(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	ring := Ring{Name: "Pilot", SoakHours: 24, SuccessThreshold: 90}
	started := func(ago time.Duration, total, ok, failed int) Stats {
		return Stats{Total: total, Installed: ok, Failed: failed, First: now.Add(-ago)}
	}
	cases := []struct {
		name   string
		st     Stats
		hold   HoldState
		needs  bool
		passed bool
		hold_  bool // a hold is raised
	}{
		{"nothing tried and devices still need it: the ring has not started", Stats{}, HoldState{}, true, false, false},
		{"nothing tried and nobody needs it: nothing to learn, move on", Stats{}, HoldState{}, false, true, false},
		{"tried but nothing finished yet", started(time.Hour, 3, 0, 0), HoldState{}, true, false, false},
		{"all good but still soaking", started(2*time.Hour, 2, 2, 0), HoldState{}, false, false, false},
		{"all good and soaked", started(30*time.Hour, 2, 2, 0), HoldState{}, false, true, false},
		{"too many failures hold at once, before the soak", started(time.Hour, 2, 1, 1), HoldState{}, true, false, true},
		{"within the allowed failure rate", started(30*time.Hour, 10, 9, 1), HoldState{}, false, true, false},
		{"fewer than half reported, inside the week", started(30*time.Hour, 10, 2, 0), HoldState{}, true, false, false},
		{"fewer than half reported, after the week", started(9*24*time.Hour, 10, 2, 0), HoldState{}, true, true, false},
		{"an open hold blocks", started(30*time.Hour, 2, 2, 0), HoldState{Open: true}, false, false, false},
		{"a released hold passes", started(time.Hour, 2, 0, 2), HoldState{Released: true}, true, true, false},
	}
	for _, c := range cases {
		passed, reason := Gate(c.st, ring, c.hold, now, c.needs)
		if passed != c.passed || (reason != "") != c.hold_ {
			t.Errorf("%s: passed=%v reason=%q, want passed=%v hold=%v", c.name, passed, reason, c.passed, c.hold_)
		}
		if reason != "" && !strings.Contains(reason, "Pilot") {
			t.Errorf("%s: the reason must name the ring: %q", c.name, reason)
		}
	}
}
