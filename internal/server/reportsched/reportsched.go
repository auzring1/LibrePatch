// Package reportsched sends the scheduled reports configured under Settings > Scheduled reports (D95): compliance,
// missing updates and inventory, as PDF or CSV, by e-mail, with the organization's name in the header. A schedule
// fires once per due time (a row in report_runs guards that), never for a time before the schedule was first seen,
// and never for a time more than a few hours in the past (a server that was down does not send a burst of old reports).
package reportsched

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/dashboard"
	"github.com/auzring1/librepatch/internal/server/notify"
	"github.com/auzring1/librepatch/internal/server/pdf"
	"github.com/auzring1/librepatch/internal/server/settings"
	"github.com/auzring1/librepatch/internal/shared/text"
)

// Grace is how late a due report may still be sent.
const Grace = 6 * time.Hour

// Sender sends an e-mail (the notify service).
type Sender interface {
	SendMail(ctx context.Context, org uuid.UUID, m notify.Message) error
}

// Names gives the header of a report: organization name, product name and accent color.
type Names func(ctx context.Context) (org, product, accent string)

// Logo gives the report logo as PNG bytes, or nil.
type Logo func(ctx context.Context, org uuid.UUID) []byte

// Service runs the schedules.
type Service struct {
	Pool     *pgxpool.Pool
	Settings *settings.Service
	Mail     Sender
	Names    Names
	Logo     Logo
	Log      *slog.Logger
	Now      func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

var weekdays = map[string]time.Weekday{"sunday": time.Sunday, "monday": time.Monday, "tuesday": time.Tuesday, "wednesday": time.Wednesday, "thursday": time.Thursday, "friday": time.Friday, "saturday": time.Saturday}

// LastSlot returns the most recent due time of a schedule at or before now, in loc.
func LastSlot(now time.Time, loc *time.Location, freq, weekday string, dayOfMonth int, hhmm string) time.Time {
	var h, m int
	_, _ = fmt.Sscanf(hhmm, "%d:%d", &h, &m)
	l := now.In(loc)
	at := func(y int, mo time.Month, d int) time.Time { return time.Date(y, mo, d, h, m, 0, 0, loc) }
	c := at(l.Year(), l.Month(), l.Day())
	switch freq {
	case "weekly":
		wd := weekdays[weekday]
		c = c.AddDate(0, 0, -((int(c.Weekday()) - int(wd) + 7) % 7))
		if c.After(now) {
			c = c.AddDate(0, 0, -7)
		}
	case "monthly":
		c = at(l.Year(), l.Month(), dayOfMonth)
		if c.After(now) {
			c = at(l.Year(), l.Month()-1, dayOfMonth)
		}
	default:
		if c.After(now) {
			c = c.AddDate(0, 0, -1)
		}
	}
	return c.UTC()
}

// Tick looks for schedules that are due and sends them.
func (s *Service) Tick(ctx context.Context) {
	org, err := s.Settings.Org(ctx)
	if err != nil {
		return
	}
	v := s.Settings.Values(ctx, org, "reports")
	loc, err := time.LoadLocation(v.Str("time_zone"))
	if err != nil {
		loc = time.UTC
	}
	q := dbq.New(s.Pool)
	now := s.now()
	windows := s.Settings.Peek(ctx, org, "updates").Bool("windows_updates_enabled")
	for _, sc := range v.Items("schedules") {
		if !sc.Bool("enabled") || ctx.Err() != nil {
			continue
		}
		if k := sc.Str("report"); !windows && (k == "compliance" || k == "missing_updates") {
			continue // these two report on Windows updates, which are switched off
		}
		id := sc.Str("id")
		slot := LastSlot(now, loc, sc.Str("frequency"), sc.Str("weekday"), sc.Int("day_of_month"), sc.Str("time"))
		seen, err := q.CountReportRuns(ctx, dbq.CountReportRunsParams{OrgID: org, ScheduleID: id})
		if err != nil {
			continue
		}
		status := "running"
		if seen == 0 || now.Sub(slot) > Grace {
			status = "skipped" // first time we see it, or too late to be useful
		}
		n, err := q.InsertReportRun(ctx, dbq.InsertReportRunParams{OrgID: org, ScheduleID: id, DueAt: slot, StartedAt: now, Name: sc.Str("name"), Report: sc.Str("report"), Format: sc.Str("format"), Status: status})
		if err != nil || n == 0 || status == "skipped" {
			continue
		}
		s.run(ctx, org, sc, slot)
	}
}

func (s *Service) run(ctx context.Context, org uuid.UUID, sc settings.V, due time.Time) {
	q := dbq.New(s.Pool)
	size, err := s.send(ctx, org, sc)
	st, msg := "sent", ""
	if err != nil {
		st, msg = "failed", trim(err.Error())
		s.log().Warn("scheduled report failed", "schedule", sc.Str("name"), "err", err)
	}
	if err := q.FinishReportRun(ctx, dbq.FinishReportRunParams{OrgID: org, ScheduleID: sc.Str("id"), DueAt: due, Status: st, Error: msg, Bytes: i32(size), Recipients: i32(len(sc.Strings("recipients")))}); err != nil {
		s.log().Error("record report run", "err", err)
	}
}

func trim(s string) string {
	return text.Truncate(strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " "), 400)
}

// SendNow sends one schedule's report immediately (the "Send now" button) and records the run.
func (s *Service) SendNow(ctx context.Context, org uuid.UUID, scheduleID string) error {
	v := s.Settings.Values(ctx, org, "reports")
	for _, sc := range v.Items("schedules") {
		if sc.Str("id") != scheduleID {
			continue
		}
		now := s.now()
		q := dbq.New(s.Pool)
		if _, err := q.InsertReportRun(ctx, dbq.InsertReportRunParams{OrgID: org, ScheduleID: scheduleID, DueAt: now, StartedAt: now, Name: sc.Str("name"), Report: sc.Str("report"), Format: sc.Str("format"), Status: "running"}); err != nil {
			return err
		}
		size, err := s.send(ctx, org, sc)
		st, msg := "sent", ""
		if err != nil {
			st, msg = "failed", trim(err.Error())
		}
		_ = q.FinishReportRun(ctx, dbq.FinishReportRunParams{OrgID: org, ScheduleID: scheduleID, DueAt: now, Status: st, Error: msg, Bytes: i32(size), Recipients: i32(len(sc.Strings("recipients")))})
		return err
	}
	return errors.New("save the schedule first: there is no saved schedule with that id")
}

func (s *Service) send(ctx context.Context, org uuid.UUID, sc settings.V) (int, error) {
	rcpt := sc.Strings("recipients")
	if len(rcpt) == 0 {
		return 0, errors.New("the schedule has no recipients")
	}
	body, name, ctype, err := s.Build(ctx, org, sc.Str("report"), sc.Str("format"))
	if err != nil {
		return 0, err
	}
	orgName, product, _ := s.names(ctx)
	text := fmt.Sprintf("Attached: %s (%s).\r\n\r\nThis report is sent on the schedule %q set up under Settings > Scheduled reports.\r\n", reportTitle(sc.Str("report")), strings.ToUpper(sc.Str("format")), sc.Str("name"))
	subject := fmt.Sprintf("%s: %s", sc.Str("name"), reportTitle(sc.Str("report")))
	if orgName != "" {
		subject = orgName + " - " + subject
	}
	_ = product
	return len(body), s.Mail.SendMail(ctx, org, notify.Message{To: rcpt, Subject: subject, Text: text, Attachments: []notify.Attachment{{Name: name, Type: ctype, Data: body}}})
}

func (s *Service) names(ctx context.Context) (string, string, string) {
	if s.Names != nil {
		return s.Names(ctx)
	}
	return "", brand.Name, "#1971c2"
}

func reportTitle(kind string) string {
	switch kind {
	case "compliance":
		return "Patch compliance"
	case "missing_updates":
		return "Missing Windows updates"
	}
	return "Device inventory"
}

// CSVSafe neutralizes spreadsheet formula injection in a cell (the same rule as the console's CSV exports).
func CSVSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

type table struct {
	cols []pdf.Column
	rows [][]string
}

func (s *Service) data(ctx context.Context, org uuid.UUID, kind string) (table, error) {
	q := dbq.New(s.Pool)
	now := s.now()
	switch kind {
	case "compliance":
		rows, err := q.ComplianceReport(ctx, org)
		if err != nil {
			return table{}, err
		}
		t := table{cols: []pdf.Column{{Header: "Device", Width: 24}, {Header: "State", Width: 14}, {Header: "Approved missing", Width: 16}, {Header: "Critical missing", Width: 16}, {Header: "Failed", Width: 6}, {Header: "Online", Width: 6}, {Header: "Last scan", Width: 16}, {Header: "Operating system", Width: 30}}}
		for _, r := range rows {
			scan := ""
			if r.WuScannedAt != nil {
				scan = r.WuScannedAt.UTC().Format("2006-01-02 15:04")
			}
			t.rows = append(t.rows, []string{r.Hostname, strings.ReplaceAll(dashboard.State(r, now), "_", " "), fmt.Sprint(r.ApprovedMissing), fmt.Sprint(r.CriticalMissing), fmt.Sprint(r.FailedUpdates), yesNo(r.Online), scan, r.OsCaption})
		}
		return t, nil
	case "missing_updates":
		rows, err := q.TopMissingUpdates(ctx, dbq.TopMissingUpdatesParams{OrgID: org, RowLimit: 2000})
		if err != nil {
			return table{}, err
		}
		t := table{cols: []pdf.Column{{Header: "Update", Width: 70}, {Header: "KB", Width: 12}, {Header: "Severity", Width: 10}, {Header: "Classification", Width: 20}, {Header: "Devices", Width: 8}}}
		for _, r := range rows {
			kb := ""
			if len(r.Kb) > 0 {
				kb = "KB" + strings.TrimPrefix(r.Kb[0], "KB")
			}
			t.rows = append(t.rows, []string{r.Title, kb, r.Severity, r.Classification, fmt.Sprint(r.Devices)})
		}
		return t, nil
	default:
		rows, err := q.ListActiveDevicesForReport(ctx, org)
		if err != nil {
			return table{}, err
		}
		t := table{cols: []pdf.Column{{Header: "Device", Width: 22}, {Header: "Operating system", Width: 26}, {Header: "Model", Width: 26}, {Header: "Serial", Width: 16}, {Header: "User", Width: 16}, {Header: "Online", Width: 6}, {Header: "Last seen", Width: 16}, {Header: "Agent", Width: 10}}}
		for _, r := range rows {
			seen := ""
			if r.LastSeenAt != nil {
				seen = r.LastSeenAt.UTC().Format("2006-01-02 15:04")
			}
			t.rows = append(t.rows, []string{r.Hostname, r.OsCaption, strings.TrimSpace(r.Manufacturer + " " + r.Model), r.Serial, r.LoggedOnUser, yesNo(r.Online), seen, r.AgentVersion})
		}
		return t, nil
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// Build renders one report. It returns the bytes, a file name and the content type.
func (s *Service) Build(ctx context.Context, org uuid.UUID, kind, format string) ([]byte, string, string, error) {
	t, err := s.data(ctx, org, kind)
	if err != nil {
		return nil, "", "", err
	}
	orgName, product, accent := s.names(ctx)
	note := ""
	if v := s.Settings.Values(ctx, org, "reports"); v.Str("header_note") != "" {
		note = v.Str("header_note")
	}
	stem := strings.ReplaceAll(kind, "_", "-") + "-" + s.now().UTC().Format("2006-01-02")
	if format == "csv" {
		var b bytes.Buffer
		b.WriteString("\xef\xbb\xbf") // the byte-order mark Excel needs to read UTF-8
		w := csv.NewWriter(&b)
		heads := make([]string, len(t.cols))
		for i, c := range t.cols {
			heads[i] = c.Header
		}
		_ = w.Write(heads)
		for _, r := range t.rows {
			out := make([]string, len(r))
			for i, c := range r {
				out[i] = CSVSafe(c)
			}
			_ = w.Write(out)
		}
		w.Flush()
		return b.Bytes(), stem + ".csv", "text/csv; charset=utf-8", w.Error()
	}
	doc := pdf.Doc{OrgName: orgName, ProductName: product, Title: reportTitle(kind), Note: note, Footer: strings.TrimSpace(orgName + " " + product), Accent: pdf.ParseHexColor(accent), Generated: s.now()}
	if s.Logo != nil {
		doc.LogoPNG = s.Logo(ctx, org)
	}
	return doc.Table(t.cols, t.rows), stem + ".pdf", "application/pdf", nil
}

// Tick prunes old run rows once a day along with the other retention work (see maintenance).
func (s *Service) Prune(ctx context.Context, before time.Time) {
	if _, err := dbq.New(s.Pool).PruneReportRuns(ctx, before); err != nil {
		s.log().Error("prune report runs", "err", err)
	}
}

// i32 narrows a count that is far below the limit (a few hundred recipients, a report of a few megabytes).
func i32(n int) int32 {
	if n > 1<<31-1 {
		return 1<<31 - 1
	}
	return int32(n) // #nosec G115 -- checked above
}
