package reportsched

import (
	"testing"
	"time"
)

func TestLastSlot(t *testing.T) {
	utc := time.UTC
	at := func(s string) time.Time { v, _ := time.Parse("2006-01-02 15:04", s); return v }
	cases := []struct {
		name, now, freq, weekday string
		dom                      int
		clock, want              string
	}{
		{"daily, already past today", "2026-03-04 09:00", "daily", "", 0, "07:00", "2026-03-04 07:00"},
		{"daily, not yet today", "2026-03-04 06:00", "daily", "", 0, "07:00", "2026-03-03 07:00"},
		{"weekly, same day later", "2026-03-04 09:00", "weekly", "wednesday", 0, "07:00", "2026-03-04 07:00"},
		{"weekly, same day earlier", "2026-03-04 06:00", "weekly", "wednesday", 0, "07:00", "2026-02-25 07:00"},
		{"weekly, other day", "2026-03-04 09:00", "weekly", "monday", 0, "07:00", "2026-03-02 07:00"},
		{"monthly, past", "2026-03-04 09:00", "monthly", "", 2, "07:00", "2026-03-02 07:00"},
		{"monthly, not yet", "2026-03-04 09:00", "monthly", "", 15, "07:00", "2026-02-15 07:00"},
		{"monthly across the year", "2026-01-04 09:00", "monthly", "", 15, "07:00", "2025-12-15 07:00"},
	}
	for _, c := range cases {
		got := LastSlot(at(c.now), utc, c.freq, c.weekday, c.dom, c.clock)
		if !got.Equal(at(c.want)) {
			t.Errorf("%s: got %v, want %s", c.name, got, c.want)
		}
	}
	berlin, _ := time.LoadLocation("Europe/Berlin")
	if got := LastSlot(at("2026-03-04 09:00"), berlin, "daily", "", 0, "07:00"); !got.Equal(at("2026-03-04 06:00")) {
		t.Errorf("time zone: %v", got)
	}
}

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{"=SUM(A1)": "'=SUM(A1)", "+1": "'+1", "-1": "'-1", "@x": "'@x", "plain": "plain", "": ""} {
		if CSVSafe(in) != want {
			t.Errorf("%q", in)
		}
	}
}
