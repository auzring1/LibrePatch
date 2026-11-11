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
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/dashboard"
	"github.com/auzring1/librepatch/internal/server/groups"
	"github.com/auzring1/librepatch/internal/server/notify"
	"github.com/auzring1/librepatch/internal/server/pdf"
	"github.com/auzring1/librepatch/internal/server/reportbuilder"
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
		if k := sc.Str("report"); !windows && (k == "compliance" || k == "missing_updates" || usesWindowsUpdates(k)) {
			continue // these report on Windows updates, which are switched off
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

// usesWindowsUpdates reports whether a ready-made report reads the Windows update data.
func usesWindowsUpdates(kind string) bool {
	b, ok := reportbuilder.BuiltinByID(kind)
	return ok && b.Spec.Dataset == "patching"
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
	built, err := s.Build(ctx, org, sc.Str("report"), sc.Str("saved_report"), sc.Str("format"))
	if err != nil {
		return 0, err
	}
	orgName, _, _ := s.names(ctx)
	text := fmt.Sprintf("Attached: %s (%s).\r\n\r\nThis report is sent on the schedule %q set up under Settings > Scheduled reports.\r\n", built.Title, strings.ToUpper(sc.Str("format")), sc.Str("name"))
	subject := fmt.Sprintf("%s: %s", sc.Str("name"), built.Title)
	if orgName != "" {
		subject = orgName + " - " + subject
	}
	return len(built.Body), s.Mail.SendMail(ctx, org, notify.Message{To: rcpt, Subject: subject, Text: text, Attachments: []notify.Attachment{{Name: built.Name, Type: built.Type, Data: built.Body}}})
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

// Built is one rendered report ready to attach.
type Built struct {
	Body       []byte
	Name, Type string
	Title      string
}

// maxAttachment is the largest report sent by e-mail; mail servers commonly refuse more than 20 MB once encoded.
const maxAttachment = 15 << 20

// maxRows bounds the rows of a report built from the report builder.
const maxRows = 200_000

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func stem(title string) string {
	t := strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(title), "-"), "-")
	if t == "" {
		t = "report"
	}
	if len(t) > 60 {
		t = strings.Trim(t[:60], "-")
	}
	return t
}

// pdfDoc is the header and footer every PDF carries.
func (s *Service) pdfDoc(ctx context.Context, org uuid.UUID, title string) pdf.Doc {
	orgName, product, accent := s.names(ctx)
	note := ""
	if v := s.Settings.Values(ctx, org, "reports"); v.Str("header_note") != "" {
		note = v.Str("header_note")
	}
	doc := pdf.Doc{OrgName: orgName, ProductName: product, Title: title, Note: note, Footer: strings.TrimSpace(orgName + " " + product), Accent: pdf.ParseHexColor(accent), Generated: s.now()}
	if s.Logo != nil {
		doc.LogoPNG = s.Logo(ctx, org)
	}
	return doc
}

// Build renders one report. kind is one of the three original reports, the id of a ready-made report, or "saved" with
// the id of a saved custom report in savedID.
func (s *Service) Build(ctx context.Context, org uuid.UUID, kind, savedID, format string) (Built, error) {
	if kind == "saved" || reportbuilder.IsBuiltin(kind) {
		return s.buildSpec(ctx, org, kind, savedID, format)
	}
	t, err := s.data(ctx, org, kind)
	if err != nil {
		return Built{}, err
	}
	title := reportTitle(kind)
	name := strings.ReplaceAll(kind, "_", "-") + "-" + s.now().UTC().Format("2006-01-02")
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
				out[i] = text.CSVSafe(c)
			}
			_ = w.Write(out)
		}
		w.Flush()
		return Built{Body: b.Bytes(), Name: name + ".csv", Type: "text/csv; charset=utf-8", Title: title}, w.Error()
	}
	doc := s.pdfDoc(ctx, org, title)
	return Built{Body: doc.Table(t.cols, t.rows), Name: name + ".pdf", Type: "application/pdf", Title: title}, nil
}

// buildSpec renders a ready-made or saved report from the report builder.
func (s *Service) buildSpec(ctx context.Context, org uuid.UUID, kind, savedID, format string) (Built, error) {
	var sp reportbuilder.Spec
	var title string
	if kind == "saved" {
		id, err := uuid.Parse(savedID)
		if err != nil {
			return Built{}, errors.New("the schedule has no saved report chosen")
		}
		sv, err := (&reportbuilder.Store{Pool: s.Pool}).Get(ctx, org, id)
		if errors.Is(err, reportbuilder.ErrNotFound) {
			return Built{}, errors.New("the saved report no longer exists; choose another one in the schedule")
		}
		if err != nil {
			return Built{}, err
		}
		sp, title = sv.Spec, sv.Name
	} else {
		b, _ := reportbuilder.BuiltinByID(kind)
		sp, title = b.Spec, b.Name
	}
	windows := s.Settings.Peek(ctx, org, "updates").Bool("windows_updates_enabled")
	sp, _, err := sp.Validate(windows)
	if err != nil {
		return Built{}, err
	}
	var grp *groups.Node
	if sp.GroupID != nil {
		g, err := dbq.New(s.Pool).GetGroup(ctx, dbq.GetGroupParams{ID: *sp.GroupID, OrgID: org})
		if err != nil {
			return Built{}, errors.New("the group this report is limited to no longer exists")
		}
		if grp, err = groups.Parse(g.Filter); err != nil {
			return Built{}, err
		}
	}
	res, err := reportbuilder.Run(ctx, s.Pool, org, sp, grp, windows, maxRows)
	if err != nil {
		return Built{}, err
	}
	if res.Truncated {
		return Built{}, fmt.Errorf("the report has %d rows, more than can be sent by e-mail; narrow it with filters, a site or a group", res.Total)
	}
	name := stem(title) + "-" + s.now().UTC().Format("2006-01-02")
	out := Built{Title: title}
	if format == "csv" {
		out.Body, err = reportbuilder.CSV(res)
		out.Name, out.Type = name+".csv", "text/csv; charset=utf-8"
	} else {
		out.Body = reportbuilder.PDF(s.pdfDoc(ctx, org, title), res)
		out.Name, out.Type = name+".pdf", "application/pdf"
	}
	if err != nil {
		return Built{}, err
	}
	if len(out.Body) > maxAttachment {
		return Built{}, fmt.Errorf("the report is %d MB, over the %d MB e-mail limit; narrow it with filters, a site or a group", len(out.Body)>>20, maxAttachment>>20)
	}
	return out, nil
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
