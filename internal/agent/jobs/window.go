package jobs

import (
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// WindowOpen reports whether t falls inside the maintenance window, and if not,
// when it next opens. A nil or empty window is always open. Local time is the
// device's unless the window names a time zone.
func WindowOpen(w *agentv1.MaintenanceWindow, t time.Time, local *time.Location) (open bool, next time.Time) {
	if w == nil || w.DurationMinutes == 0 {
		return true, t
	}
	loc := local
	if w.Tz != "" {
		if l, err := time.LoadLocation(w.Tz); err == nil {
			loc = l
		}
	}
	if loc == nil {
		loc = time.Local
	}
	lt := t.In(loc)
	allowed := func(d time.Weekday) bool {
		if len(w.Days) == 0 {
			return true
		}
		for _, x := range w.Days {
			if int(x) == int(d) {
				return true
			}
		}
		return false
	}
	dur := time.Duration(w.DurationMinutes) * time.Minute
	// A window that started yesterday may still be open after midnight.
	for back := 1; back >= 0; back-- {
		day := time.Date(lt.Year(), lt.Month(), lt.Day()-back, 0, 0, 0, 0, loc)
		if !allowed(day.Weekday()) {
			continue
		}
		start := day.Add(time.Duration(w.StartMinute) * time.Minute)
		if !lt.Before(start) && lt.Before(start.Add(dur)) {
			return true, t
		}
	}
	for ahead := 0; ahead < 8; ahead++ {
		day := time.Date(lt.Year(), lt.Month(), lt.Day()+ahead, 0, 0, 0, 0, loc)
		if !allowed(day.Weekday()) {
			continue
		}
		start := day.Add(time.Duration(w.StartMinute) * time.Minute)
		if start.After(lt) {
			return false, start
		}
	}
	return false, t.Add(time.Hour)
}
