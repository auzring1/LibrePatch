package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/auzring1/librepatch/internal/server/lifecycle"
)

type lifecycleItem struct {
	DeviceID     string  `json:"device_id"`
	Hostname     string  `json:"hostname"`
	OS           string  `json:"os"`
	Version      string  `json:"version"`
	Build        int     `json:"build"`
	Edition      string  `json:"edition"`
	Product      string  `json:"product"`
	Release      string  `json:"release"`
	EndOfSupport *string `json:"end_of_support"`
	DaysLeft     *int    `json:"days_left"`
	Status       string  `json:"status"`
	Note         string  `json:"note"`
	LastSeenAt   *string `json:"last_seen_at"`
}

// lifecycleRows reads the report: ?warn_days= is how many days before the end of support a device counts as "ending
// soon" (default 180).
func (s *server) lifecycleRows(w http.ResponseWriter, r *http.Request) ([]lifecycleItem, int, bool) {
	warn := lifecycle.DefaultWarnDays
	if v := r.URL.Query().Get("warn_days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 3650 {
			badRequest(w, "warn_days must be a number of days between 0 and 3650")
			return nil, 0, false
		}
		if n > 0 {
			warn = n
		}
	}
	rows, err := lifecycle.List(r.Context(), s.Pool, principalFrom(r).OrgID, s.now(), warn)
	if err != nil {
		s.Log.Error("lifecycle report", "err", err)
		internalError(w)
		return nil, 0, false
	}
	date := func(t *time.Time) *string {
		if t == nil {
			return nil
		}
		v := t.UTC().Format("2006-01-02")
		return &v
	}
	items := make([]lifecycleItem, 0, len(rows))
	for _, x := range rows {
		items = append(items, lifecycleItem{DeviceID: x.DeviceID.String(), Hostname: x.Hostname, OS: x.OS, Version: x.Version, Build: x.Build,
			Edition: x.Edition, Product: x.Product, Release: x.Release, EndOfSupport: date(x.End), DaysLeft: x.DaysLeft, Status: x.Status,
			Note: x.Note, LastSeenAt: rfc3339(x.LastSeen)})
	}
	return items, warn, true
}

func rfc3339(t *time.Time) *string {
	if t == nil {
		return nil
	}
	v := t.UTC().Format(time.RFC3339)
	return &v
}

// reportLifecycle: GET /reports/lifecycle — which devices run an operating system that is out of support or soon will be.
func (s *server) reportLifecycle(w http.ResponseWriter, r *http.Request) {
	items, warn, ok := s.lifecycleRows(w, r)
	if !ok {
		return
	}
	var sum lifecycle.Summary
	for _, x := range items {
		switch x.Status {
		case lifecycle.Supported:
			sum.Supported++
		case lifecycle.EndingSoon:
			sum.EndingSoon++
		case lifecycle.Unsupported:
			sum.Unsupported++
		default:
			sum.Unknown++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data_as_of": lifecycle.DataAsOf, "warn_days": warn, "items": items,
		"summary": map[string]int{"supported": sum.Supported, "ending_soon": sum.EndingSoon, "unsupported": sum.Unsupported, "unknown": sum.Unknown}})
}

// lifecycleCSV: GET /reports/lifecycle.csv
func (s *server) lifecycleCSV(w http.ResponseWriter, r *http.Request) {
	items, warn, ok := s.lifecycleRows(w, r)
	if !ok {
		return
	}
	cw, ok := s.startCSV(w, r, "lifecycle", map[string]any{"warn_days": warn})
	if !ok {
		return
	}
	_ = csvRow(cw, "hostname", "status", "operating_system", "release", "build", "edition", "end_of_support", "days_left", "note", "last_seen")
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	for _, x := range items {
		days := ""
		if x.DaysLeft != nil {
			days = strconv.Itoa(*x.DaysLeft)
		}
		if csvRow(cw, x.Hostname, x.Status, x.Product, x.Release, strconv.Itoa(x.Build), x.Edition, str(x.EndOfSupport), days, x.Note, str(x.LastSeenAt)) != nil {
			return
		}
	}
	cw.Flush()
}
