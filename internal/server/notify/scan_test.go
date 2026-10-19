package notify

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/server/settings"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

func ruleSet(enabled map[string]int) []any {
	var out []any
	for _, e := range settings.Events {
		th, on := enabled[e.Value]
		out = append(out, map[string]any{"event": e.Value, "enabled": on, "email": true, "webhook": false,
			"recipients": []any{"ops@example.org"}, "threshold": th, "quiet_hours": false})
	}
	return out
}

func TestScanRaisesDeviceHealthEventsOncePerReminderPeriod(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	org, user, site := uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec("INSERT INTO organizations (id, name) VALUES ($1, 'Contoso Health')", org)
	exec("INSERT INTO users (id, org_id, email, display_name, password_hash) VALUES ($1, $2, 'a@example.org', 'A', 'x')", user, org)
	exec("INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 's')", site, org)

	device := func(host string, online bool, pending bool, uptimeDays int, freeGB *int64, caption string, build int, edition, bitlocker string) {
		hw := `{"os_build":` + itoa(build) + `,"os_edition":"` + edition + `","disks":[{"mount":"C:","bitlocker":"` + bitlocker + `"}]}`
		var free *int64
		if freeGB != nil {
			v := *freeGB << 30
			free = &v
		}
		exec(`INSERT INTO devices (id, org_id, site_id, status, hostname, arch, online, pending_reboot, uptime_s, system_drive_free_bytes, os_caption, hardware)
		      VALUES ($1,$2,$3,'active',$4,'amd64',$5,$6,$7,$8,$9,$10::jsonb)`,
			uuid.New(), org, site, host, online, pending, int64(uptimeDays)*86400, free, caption, hw)
	}
	gb := func(n int64) *int64 { return &n }
	device("LONG-UP", true, true, 12, gb(200), "Windows 11 Pro", 26200, "Professional", "protected") // restart waiting 12 days
	device("SHORT-UP", true, true, 2, gb(200), "Windows 11 Pro", 26200, "Professional", "protected") // only 2 days
	device("FULL", true, false, 1, gb(3), "Windows 11 Pro", 26200, "Professional", "protected")      // 3 GB free
	device("OFF-DISK", false, false, 1, gb(1), "Windows 11 Pro", 26200, "Professional", "protected") // offline: not reported
	device("PLAIN", true, false, 1, nil, "Windows 11 Pro", 26200, "Professional", "unprotected")     // BitLocker off
	device("OLD-OS", true, false, 1, gb(200), "Windows 10 Pro", 19045, "Professional", "protected")  // out of support
	device("NEW-OS", true, false, 1, gb(200), "Windows 11 Pro", 26200, "Professional", "protected")  // supported

	svc := &settings.Service{Pool: db.Pool}
	if _, err := svc.Put(ctx, settings.Actor{Org: org, User: user}, "notifications", 0, map[string]any{
		"email_enabled": true, "smtp_host": "mail.example.org", "from_address": "librepatch@example.org",
		"rules": ruleSet(map[string]int{"restart_pending_long": 7, "low_disk": 10, "bitlocker_off": 0, "os_end_of_support": 0}),
	}); err != nil {
		t.Fatal(err)
	}
	n := &Service{Pool: db.Pool, Settings: svc, Now: func() time.Time { return time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC) }}

	type queued struct{ event, subject string }
	subjects := func() []queued {
		rows, err := db.Pool.Query(ctx, `SELECT event, payload->>'subject' FROM notification_outbox WHERE org_id = $1`, org)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []queued
		for rows.Next() {
			var q queued
			if err := rows.Scan(&q.event, &q.subject); err != nil {
				t.Fatal(err)
			}
			out = append(out, q)
		}
		return out
	}
	count := func(m []queued, ev string) (c int) {
		for _, q := range m {
			if q.event == ev {
				c++
			}
		}
		return
	}

	n.scan(ctx)
	got := subjects()
	for ev, want := range map[string]int{"restart_pending_long": 1, "low_disk": 1, "bitlocker_off": 1, "os_end_of_support": 1} {
		if c := count(got, ev); c != want {
			t.Errorf("%s: %d notifications, want %d (%v)", ev, c, want, got)
		}
	}
	for _, q := range got {
		for _, bad := range []string{"SHORT-UP", "OFF-DISK", "NEW-OS"} {
			if containsHost(q.subject, bad) {
				t.Errorf("%s must not be reported: %s", bad, q.subject)
			}
		}
	}

	// A second scan in the same week and month announces nothing new.
	n.scan(ctx)
	if again := subjects(); len(again) != len(got) {
		t.Fatalf("a second scan queued more: %d then %d", len(got), len(again))
	}

	// The next week the restart and the disk are reminded about again; BitLocker (monthly) and the end of support
	// (once) are not.
	n.Now = func() time.Time { return time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC) }
	n.scan(ctx)
	later := subjects()
	for ev, want := range map[string]int{"restart_pending_long": 2, "low_disk": 2, "bitlocker_off": 1, "os_end_of_support": 1} {
		if c := count(later, ev); c != want {
			t.Errorf("a week later, %s: %d notifications, want %d", ev, c, want)
		}
	}
}

func containsHost(s, host string) bool {
	for i := 0; i+len(host) <= len(s); i++ {
		if s[i:i+len(host)] == host {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if s == "" {
		return "0"
	}
	return s
}
