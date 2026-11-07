// Package notify turns events into e-mails and webhook calls according to the organization's settings (D95): rules
// say who hears about what, quiet hours hold messages back, and an outbox with retries and de-duplication makes
// delivery survive a restart and a flaky mail server. Nothing here talks to the network except to the mail relay and
// the webhook URLs an administrator configured.
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/branding"
	"github.com/auzring1/librepatch/internal/server/lifecycle"
	"github.com/auzring1/librepatch/internal/server/settings"
	"github.com/auzring1/librepatch/internal/server/vulns"
	"github.com/auzring1/librepatch/internal/shared/ptr"
	"github.com/auzring1/librepatch/internal/shared/text"
	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

// Service sends notifications.
type Service struct {
	Pool     *pgxpool.Pool
	Settings *settings.Service
	Branding *branding.Service
	Log      *slog.Logger
	Now      func() time.Time
	// Mailer and Poster are replaced in tests.
	Mailer Mailer
	Poster Poster

	ticks int
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

// Event is something that happened.
type Event struct {
	Name string
	// Key de-duplicates: the same event with the same key is queued once per target (empty = never de-duplicated).
	Key     string
	Subject string
	Text    string
	Data    map[string]any
}

// Emit queues the event for every rule that wants it. It never fails the caller's work: errors are logged.
func (s *Service) Emit(ctx context.Context, org uuid.UUID, ev Event) {
	if err := s.emit(ctx, org, ev); err != nil {
		s.log().Error("queue notification", "event", ev.Name, "err", err)
	}
}

func (s *Service) emit(ctx context.Context, org uuid.UUID, ev Event) error {
	ns := s.Settings.Values(ctx, org, "notifications")
	var rule settings.V
	for _, r := range ns.Items("rules") {
		if r.Str("event") == ev.Name {
			rule = r
		}
	}
	if rule == nil || !rule.Bool("enabled") {
		return nil
	}
	q := dbq.New(s.Pool)
	now := s.now()
	notBefore := now
	if rule.Bool("quiet_hours") {
		notBefore = quietUntil(ns, now)
	}
	payload := s.payload(ctx, org, ev, now)
	if rule.Bool("email") && ns.Bool("email_enabled") {
		body, _ := json.Marshal(map[string]any{"subject": ev.Subject, "text": ev.Text})
		for _, to := range rule.Strings("recipients") {
			if err := q.EnqueueNotification(ctx, dbq.EnqueueNotificationParams{OrgID: org, Channel: "email", Event: ev.Name, Target: to, DedupeKey: ev.Key, Payload: body, NotBefore: notBefore}); err != nil {
				return err
			}
		}
	}
	if rule.Bool("webhook") {
		wb, _ := json.Marshal(payload)
		is := s.Settings.Values(ctx, org, "integrations")
		for _, w := range is.Items("webhooks") {
			if !w.Bool("enabled") || !contains(w.Strings("events"), ev.Name) {
				continue
			}
			if err := q.EnqueueNotification(ctx, dbq.EnqueueNotificationParams{OrgID: org, Channel: "webhook", Event: ev.Name, Target: w.Str("id"), DedupeKey: ev.Key, Payload: wb, NotBefore: notBefore}); err != nil {
				return err
			}
		}
	}
	return nil
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func (s *Service) names(ctx context.Context) (org, product string) {
	if s.Branding != nil {
		if p, err := s.Branding.Public(ctx); err == nil {
			return p.OrgName, p.ProductName
		}
	}
	return "", brand.Name
}

func (s *Service) payload(ctx context.Context, org uuid.UUID, ev Event, now time.Time) map[string]any {
	orgName, _ := s.names(ctx)
	p := map[string]any{"id": uuid.NewString(), "event": ev.Name, "time": now.UTC().Format(time.RFC3339), "organization": orgName, "summary": ev.Subject}
	for k, v := range ev.Data {
		p[k] = v
	}
	return p
}

// quietUntil returns when a message may be sent: now, or the end of the quiet hours if now falls inside them.
func quietUntil(ns settings.V, now time.Time) time.Time {
	if !ns.Bool("quiet_hours_enabled") {
		return now
	}
	loc, err := time.LoadLocation(ns.Str("quiet_time_zone"))
	if err != nil {
		loc = time.UTC
	}
	return QuietEnd(now, loc, ns.Str("quiet_start"), ns.Str("quiet_end"))
}

func minutes(hhmm string) int {
	var h, m int
	_, _ = fmt.Sscanf(hhmm, "%d:%d", &h, &m)
	return h*60 + m
}

// QuietEnd returns now when it is outside the quiet window [start, end) in loc, otherwise the next end of the window.
// The window may cross midnight.
func QuietEnd(now time.Time, loc *time.Location, start, end string) time.Time {
	l := now.In(loc)
	cur := l.Hour()*60 + l.Minute()
	st, en := minutes(start), minutes(end)
	inside := false
	if st < en {
		inside = cur >= st && cur < en
	} else if st > en {
		inside = cur >= st || cur < en
	}
	if !inside {
		return now
	}
	day := l
	if st > en && cur >= st {
		day = l.AddDate(0, 0, 1)
	}
	return time.Date(day.Year(), day.Month(), day.Day(), en/60, en%60, 0, 0, loc)
}

// Tick delivers what is due and, every few minutes, looks for conditions that have no event of their own.
func (s *Service) Tick(ctx context.Context) {
	s.deliver(ctx)
	s.ticks++
	if s.ticks%5 == 1 {
		s.scan(ctx)
	}
}

const maxAttempts = 5

var backoff = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour}

func (s *Service) deliver(ctx context.Context) {
	q := dbq.New(s.Pool)
	now := s.now()
	// Claim in a transaction so two servers (or two ticks) never send the same row.
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := q.WithTx(tx).ClaimDueNotifications(ctx, dbq.ClaimDueNotificationsParams{NotBefore: now, Limit: 50})
	if err != nil {
		s.log().Error("claim notifications", "err", err)
		return
	}
	for _, r := range rows {
		var sendErr error
		switch r.Channel {
		case "email":
			sendErr = s.sendEmailRow(ctx, r)
		case "webhook":
			sendErr = s.sendWebhookRow(ctx, r)
		}
		status, next, text := "sent", r.NotBefore, ""
		var sent *time.Time
		if sendErr == nil {
			sent = &now
		} else {
			text = trim(sendErr.Error(), 500)
			if int(r.Attempts)+1 >= maxAttempts {
				status = "failed"
			} else {
				status = "pending"
				next = now.Add(backoff[min(int(r.Attempts), len(backoff)-1)])
			}
			s.log().Warn("notification not delivered", "channel", r.Channel, "event", r.Event, "attempt", r.Attempts+1, "err", sendErr)
		}
		if err := q.WithTx(tx).FinishNotification(ctx, dbq.FinishNotificationParams{ID: r.ID, Status: status, LastError: text, NotBefore: next, SentAt: sent}); err != nil {
			s.log().Error("finish notification", "err", err)
		}
	}
	_ = tx.Commit(ctx)
}

func trim(s string, n int) string {
	return text.Truncate(strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " "), n)
}

// scan looks for the conditions that nothing announces: devices gone quiet, the license filling up, late agents.
func (s *Service) scan(ctx context.Context) {
	org, err := s.Settings.Org(ctx)
	if err != nil {
		return
	}
	ns := s.Settings.Values(ctx, org, "notifications")
	rules := map[string]settings.V{}
	for _, r := range ns.Items("rules") {
		if r.Bool("enabled") {
			rules[r.Str("event")] = r
		}
	}
	q := dbq.New(s.Pool)
	now := s.now()
	if r, ok := rules["device_offline"]; ok {
		hours := r.Int("threshold")
		if hours > 0 {
			rows, err := q.OfflineDevicesSince(ctx, dbq.OfflineDevicesSinceParams{OrgID: org, LastSeenAt: ptr.Of(now.Add(-time.Duration(hours) * time.Hour))})
			if err == nil {
				for _, d := range rows {
					seen := ""
					if d.LastSeenAt != nil {
						seen = d.LastSeenAt.UTC().Format(time.RFC3339)
					}
					s.Emit(ctx, org, Event{Name: "device_offline", Key: "offline:" + d.ID.String() + ":" + seen,
						Subject: fmt.Sprintf("%s has not reported for %d hours or more", d.Hostname, hours),
						Text:    fmt.Sprintf("The device %s last reported at %s.", d.Hostname, seen),
						Data:    map[string]any{"device": map[string]any{"id": d.ID.String(), "hostname": d.Hostname}, "hours_offline": hours, "last_seen": seen}})
				}
			}
		}
	}
	if r, ok := rules["agent_out_of_date"]; ok {
		if t, err := q.RolloutTargetVersion(ctx, org); err == nil && now.Sub(t.CreatedAt) >= time.Duration(r.Int("threshold"))*24*time.Hour {
			if devs, err := q.ActiveDeviceAgents(ctx, org); err == nil {
				for _, d := range devs {
					if vercmp.Key(d.AgentVersion) == nil || vercmp.Compare(d.AgentVersion, t.Version) >= 0 {
						continue
					}
					s.Emit(ctx, org, Event{Name: "agent_out_of_date", Key: "agent:" + d.ID.String() + ":" + t.Version,
						Subject: fmt.Sprintf("%s runs agent %s; the target is %s", d.Hostname, d.AgentVersion, t.Version),
						Text:    fmt.Sprintf("The device %s runs agent version %s, older than the rollout's target %s.", d.Hostname, d.AgentVersion, t.Version),
						Data:    map[string]any{"device": map[string]any{"id": d.ID.String(), "hostname": d.Hostname}, "agent_version": d.AgentVersion, "target_version": t.Version}})
				}
			}
		}
	}
	s.scanDeviceHealth(ctx, org, rules, now)
}

// isoWeek names the calendar week of t ("2026-W43"): a reminder that should come at most once a week uses it in its key.
func isoWeek(t time.Time) string {
	y, w := t.UTC().ISOWeek()
	return fmt.Sprintf("%d-W%02d", y, w)
}

func deviceData(id uuid.UUID, host string, extra map[string]any) map[string]any {
	d := map[string]any{"device": map[string]any{"id": id.String(), "hostname": host}}
	for k, v := range extra {
		d[k] = v
	}
	return d
}

// scanDeviceHealth raises the events about a device's condition: a restart that has waited too long, a full system
// drive, a disk without BitLocker, and an operating system that is, or soon will be, out of support. Each has a
// de-duplication key that repeats as rarely as the event deserves (weekly, monthly, or once).
func (s *Service) scanDeviceHealth(ctx context.Context, org uuid.UUID, rules map[string]settings.V, now time.Time) {
	q := dbq.New(s.Pool)
	if r, ok := rules["restart_pending_long"]; ok && r.Int("threshold") > 0 {
		days := r.Int("threshold")
		if rows, err := q.RestartPendingDevices(ctx, dbq.RestartPendingDevicesParams{OrgID: org, UptimeS: int64(days) * 86400}); err == nil {
			for _, d := range rows {
				up := int(d.UptimeS / 86400)
				s.Emit(ctx, org, Event{Name: "restart_pending_long", Key: "restart:" + d.ID.String() + ":" + isoWeek(now),
					Subject: fmt.Sprintf("%s has needed a restart for a while (%d days since the last one)", d.Hostname, up),
					Text:    fmt.Sprintf("The device %s needs a restart and has been running for %d days without one.", d.Hostname, up),
					Data:    deviceData(d.ID, d.Hostname, map[string]any{"days_without_restart": up})})
			}
		}
	}
	if r, ok := rules["low_disk"]; ok && r.Int("threshold") > 0 {
		gb := r.Int("threshold")
		limit := int64(gb) << 30
		if rows, err := q.LowDiskDevices(ctx, dbq.LowDiskDevicesParams{OrgID: org, SystemDriveFreeBytes: &limit}); err == nil {
			for _, d := range rows {
				free := float64(d.FreeBytes) / float64(1<<30)
				s.Emit(ctx, org, Event{Name: "low_disk", Key: "disk:" + d.ID.String() + ":" + isoWeek(now),
					Subject: fmt.Sprintf("%s has %.1f GB free on its system drive", d.Hostname, free),
					Text:    fmt.Sprintf("The system drive of %s has %.1f GB free, less than the %d GB you set. Installs may fail when the drive is full.", d.Hostname, free, gb),
					Data:    deviceData(d.ID, d.Hostname, map[string]any{"free_gb": float64(int(free*10)) / 10, "threshold_gb": gb})})
			}
		}
	}
	if _, ok := rules["bitlocker_off"]; ok {
		if rows, err := q.UnprotectedDiskDevices(ctx, org); err == nil {
			for _, d := range rows {
				s.Emit(ctx, org, Event{Name: "bitlocker_off", Key: "bitlocker:" + d.ID.String() + ":" + now.UTC().Format("2006-01"),
					Subject: fmt.Sprintf("BitLocker is off on %s (%s)", d.Hostname, d.Mounts),
					Text:    fmt.Sprintf("The device %s reports that BitLocker does not protect these disks: %s.", d.Hostname, d.Mounts),
					Data:    deviceData(d.ID, d.Hostname, map[string]any{"disks": d.Mounts})})
			}
		}
	}
	if r, ok := rules["os_end_of_support"]; ok {
		s.scanEndOfSupport(ctx, org, r.Int("threshold"), now)
	}
	if _, ok := rules["exploited_vulnerability"]; ok {
		s.scanExploited(ctx, org)
	}
}

// scanExploited announces, once per CVE, a vulnerability on the CISA list of known exploited vulnerabilities that affects
// devices of the organization.
func (s *Service) scanExploited(ctx context.Context, org uuid.UUID) {
	items, _, err := (&vulns.Store{Pool: s.Pool}).Overview(ctx, org, vulns.Filter{Exploited: true, Limit: 500})
	if err != nil {
		return
	}
	queued := s.queuedKeys(ctx, org, "exploited_vulnerability")
	for _, it := range items {
		key := "kev:" + it.ID
		if queued[key] {
			continue
		}
		due := ""
		if it.KEVDue != nil {
			due = it.KEVDue.UTC().Format("2006-01-02")
		}
		name := it.ExploitedName
		if name == "" {
			name = it.ID
		}
		text := fmt.Sprintf("%s (%s) is known to be exploited and affects %d device(s).", it.ID, name, it.Devices)
		if due != "" {
			text += " CISA asks for it to be fixed by " + due + "."
		}
		if len(it.FixedIn) > 0 {
			text += " Fix: update to " + strings.Join(it.FixedIn, "; ") + "."
		}
		s.Emit(ctx, org, Event{Name: "exploited_vulnerability", Key: key,
			Subject: fmt.Sprintf("%s is known to be exploited and affects %d device(s)", it.ID, it.Devices), Text: text,
			Data: map[string]any{"cve": it.ID, "name": name, "devices": it.Devices, "fix_due": due, "ransomware": it.Ransomware, "severity": it.Severity}})
	}
}

// maxEndOfSupportPerScan bounds how many new end-of-support events one scan raises, so a fleet that is all on one old
// release is announced over a few scans instead of in one burst.
const maxEndOfSupportPerScan = 200

// queuedKeys returns the de-duplication keys already queued for an event, so a scan does not walk a whole fleet of
// devices that were announced before.
func (s *Service) queuedKeys(ctx context.Context, org uuid.UUID, event string) map[string]bool {
	out := map[string]bool{}
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT dedupe_key FROM notification_outbox WHERE org_id = $1 AND event = $2 AND dedupe_key <> ''`, org, event)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		if rows.Scan(&k) == nil {
			out[k] = true
		}
	}
	return out
}

func (s *Service) scanEndOfSupport(ctx context.Context, org uuid.UUID, warnDays int, now time.Time) {
	rows, err := lifecycle.List(ctx, s.Pool, org, now, warnDays)
	if err != nil {
		return
	}
	queued := s.queuedKeys(ctx, org, "os_end_of_support")
	raised := 0
	for _, d := range rows {
		if d.Status != lifecycle.Unsupported && (d.Status != lifecycle.EndingSoon || d.DaysLeft == nil || *d.DaysLeft > warnDays) {
			continue
		}
		name := strings.TrimSpace(d.Product + " " + d.Release)
		key := "eos:" + d.DeviceID.String() + ":" + name
		if queued[key] {
			continue
		}
		if raised++; raised > maxEndOfSupportPerScan {
			return
		}
		var verb, when string
		data := map[string]any{"os": name}
		switch {
		case d.End == nil: // older than any release in the table
			verb = "has ended"
		case d.Status == lifecycle.Unsupported:
			when = d.End.UTC().Format("2006-01-02")
			verb = "ended on " + when
		default:
			when = d.End.UTC().Format("2006-01-02")
			verb = "ends on " + when
		}
		if when != "" {
			data["end_of_support"] = when
		}
		if d.DaysLeft != nil {
			data["days_left"] = *d.DaysLeft
		}
		s.Emit(ctx, org, Event{Name: "os_end_of_support", Key: key,
			Subject: fmt.Sprintf("%s runs %s, whose support %s", d.Hostname, name, verb),
			Text:    fmt.Sprintf("The device %s runs %s. Microsoft's support for it %s.", d.Hostname, name, verb),
			Data:    deviceData(d.DeviceID, d.Hostname, data)})
	}
}
