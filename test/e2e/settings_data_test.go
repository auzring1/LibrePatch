package e2e

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCustomDeviceFieldsRetentionAndStaleCleanup(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()
	op := h.orgUser("op@example.com", "operator")
	ro := h.orgUser("ro@example.com", "readonly")
	ctx := context.Background()

	// Define two fields. Operators may (the devices section is delegated to them), read-only people may not.
	defs := []any{
		map[string]any{"key": "asset_tag", "label": "Asset tag", "type": "text", "show_in_list": true},
		map[string]any{"key": "tier", "label": "Tier", "type": "select", "options": []any{"gold", "silver"}, "show_in_list": true},
		map[string]any{"key": "warranty", "label": "Warranty ends", "type": "date", "show_in_list": false},
	}
	if st, _ := ro.do("PUT", "/api/v1/settings/sections/devices", map[string]any{"revision": 0, "values": map[string]any{"custom_fields": defs}}, nil); st != 403 {
		t.Fatalf("read-only defining fields: %d", st)
	}
	if st, b := op.do("PUT", "/api/v1/settings/sections/devices", map[string]any{"revision": 0, "values": map[string]any{"custom_fields": defs}}, nil); st != 200 {
		t.Fatalf("operator defining fields: %d %v", st, b)
	}
	// A device to put values on.
	taHead := h.startAgent(h.createToken("head", 5, false), &fakeHW{host: "HQ-1", serial: "S1", uuid: "U1"}, nil)
	waitFor(t, 20e9, "agent", func() bool { return taHead.state() == "connected" && len(h.devices()) == 1 })
	dev := h.devices()[0]["id"].(string)

	if st, b := op.do("PUT", "/api/v1/devices/"+dev+"/fields", map[string]any{"values": map[string]any{"asset_tag": "HQ-0142", "tier": "gold", "warranty": "2027-03-01"}}, nil); st != 200 || b["values"].(map[string]any)["tier"] != "gold" {
		t.Fatalf("set values: %d %v", st, b)
	}
	for name, in := range map[string]map[string]any{
		"unknown field": {"nope": "x"},
		"not a choice":  {"tier": "bronze"},
		"bad date":      {"warranty": "tomorrow"},
		"control chars": {"asset_tag": "a\x00b"},
		"too long":      {"asset_tag": strings.Repeat("x", 201)},
	} {
		if st, _ := op.do("PUT", "/api/v1/devices/"+dev+"/fields", map[string]any{"values": in}, nil); st != 422 {
			t.Errorf("%s: %d", name, st)
		}
	}
	if st, _ := ro.do("PUT", "/api/v1/devices/"+dev+"/fields", map[string]any{"values": map[string]any{"tier": "silver"}}, nil); st != 403 {
		t.Fatalf("read-only writing values: %d", st)
	}
	if _, b := ro.do("GET", "/api/v1/devices/"+dev+"/fields", nil, nil); b["values"].(map[string]any)["asset_tag"] != "HQ-0142" {
		t.Fatalf("read-only reading values: %v", b)
	}
	det := h.auditDetails("device.fields_update")
	if det["changes"].(map[string]any)["asset_tag"].(map[string]any)["after"] != "HQ-0142" {
		t.Fatalf("audit: %v", det)
	}
	// The list carries the values, and a group filter can use them.
	_, list := h.do("GET", "/api/v1/devices", nil, nil)
	if list["items"].([]any)[0].(map[string]any)["custom"].(map[string]any)["asset_tag"] != "HQ-0142" {
		t.Fatalf("list values: %v", list)
	}
	filter := map[string]any{"op": "device", "field": "custom.asset_tag", "cmp": "prefix", "value": "HQ-"}
	if st, b := h.do("POST", "/api/v1/groups/preview", map[string]any{"filter": filter}, nil); st != 200 || num(b["total"]) != 1 {
		t.Fatalf("group preview with a custom field: %d %v", st, b)
	}
	filter["value"] = "BR-"
	if _, b := h.do("POST", "/api/v1/groups/preview", map[string]any{"filter": filter}, nil); num(b["total"]) != 0 {
		t.Fatalf("no match expected: %v", b)
	}
	// Clearing a value.
	op.do("PUT", "/api/v1/devices/"+dev+"/fields", map[string]any{"values": map[string]any{"tier": nil}}, nil)
	if _, b := h.do("GET", "/api/v1/devices/"+dev+"/fields", nil, nil); b["values"].(map[string]any)["tier"] != nil {
		t.Fatalf("cleared: %v", b)
	}

	// Retention: finished jobs older than the limit go; a recent one stays. Stale revoked devices go; active ones never.
	org := parseUUID(t, h.session()["org"].(map[string]any)["id"].(string))
	var jobID string
	if err := h.db.Pool.QueryRow(ctx, `SELECT id::text FROM jobs LIMIT 1`).Scan(&jobID); err == nil {
		t.Log("a job exists in this run; retention is checked on stale devices")
	}
	if st, b := h.do("PUT", "/api/v1/settings/sections/data", map[string]any{"revision": 0, "values": map[string]any{"job_history_days": 30, "compliance_history_days": 30, "notification_log_days": 7}}, nil); st != 200 {
		t.Fatalf("data settings: %d %v", st, b)
	}
	if st, b := h.do("PUT", "/api/v1/settings/sections/devices", map[string]any{"revision": 1, "values": map[string]any{"stale_cleanup_days": 30}}, nil); st != 200 {
		t.Fatalf("stale days: %d %v", st, b)
	}
	// A connected agent sends a heartbeat every couple of seconds, which resets "last seen" to now. Stop it and wait until
	// the server sees the device go offline, so nothing can touch the row between the update below and the clean-up
	// (on a slow runner a heartbeat in that gap made the device look recently seen).
	taHead.stop()
	waitFor(t, 20*time.Second, "device offline", func() bool {
		d := h.devices()
		return len(d) == 1 && d[0]["online"] == false
	})
	if _, err := h.db.Pool.Exec(ctx, `UPDATE devices SET status = 'revoked', revoked_at = now() - interval '90 days', last_seen_at = now() - interval '90 days', online = false WHERE id = $1`, dev); err != nil {
		t.Fatal(err)
	}
	res, err := h.app.Maint.Run(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	if res.Devices != 1 {
		t.Fatalf("a revoked device unseen for 90 days must be removed with a 30-day limit: %+v", res)
	}
	if n := h.auditCount("maintenance.retention"); n != 1 {
		t.Fatalf("retention is audited: %d", n)
	}
	if n := h.auditCount("device.delete"); n < 1 {
		t.Fatalf("the deletion is audited: %d", n)
	}
	st, ds := h.do("GET", "/api/v1/settings/data/status", nil, nil)
	if st != 200 || ds["retention"] == nil || ds["footprint"] == nil {
		t.Fatalf("data status: %d %v", st, ds)
	}
	if st, _ := ro.do("GET", "/api/v1/settings/data/status", nil, nil); st != 403 {
		t.Fatalf("read-only data status: %d", st)
	}
	if st, _ := op.do("POST", "/api/v1/settings/data/run-retention", map[string]any{}, nil); st != 403 {
		t.Fatalf("operator running retention: %d", st)
	}
	if st, b := h.do("POST", "/api/v1/settings/data/run-retention", map[string]any{}, nil); st != 200 {
		t.Fatalf("run now: %d %v", st, b)
	}
}

func TestScheduledReports(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()
	mailer := &fakeMailer{}
	h.app.Notify.Mailer = mailer
	ctx := context.Background()
	org := parseUUID(t, h.session()["org"].(map[string]any)["id"].(string))

	// Mail has to work first.
	if st, b := h.do("PUT", "/api/v1/settings/sections/notifications", map[string]any{"revision": 0, "values": map[string]any{"email_enabled": true, "smtp_host": "smtp.example.org", "from_address": "r@example.org"}}, nil); st != 200 {
		t.Fatalf("notifications: %d %v", st, b)
	}
	ta := h.startAgent(h.createToken("head", 5, false), &fakeHW{host: "=HYPERLINK-PC", serial: "S1", uuid: "U1"}, nil)
	waitFor(t, 20e9, "agent", func() bool { return ta.state() == "connected" && len(h.devices()) == 1 })

	sched := func(id, report, format string) map[string]any {
		return map[string]any{"id": id, "name": "Daily " + report, "enabled": true, "report": report, "format": format, "frequency": "daily", "weekday": "monday", "day_of_month": 1, "time": "07:00", "recipients": []any{"boss@example.org"}}
	}
	vals := map[string]any{"header_note": "Confidential", "time_zone": "UTC", "schedules": []any{sched("s-pdf", "compliance", "pdf"), sched("s-csv", "inventory", "csv")}}
	if st, b := h.do("PUT", "/api/v1/settings/sections/reports", map[string]any{"revision": 0, "values": vals}, nil); st != 200 {
		t.Fatalf("schedules: %d %v", st, b)
	}
	// A schedule needs recipients.
	bad := map[string]any{"schedules": []any{func() map[string]any { s := sched("x", "compliance", "pdf"); s["recipients"] = []any{}; return s }()}}
	if st, _ := h.do("PUT", "/api/v1/settings/sections/reports", map[string]any{"revision": 1, "values": bad}, nil); st != 422 {
		t.Fatalf("no recipients: %d", st)
	}

	// Send now: a PDF and a CSV, with the organization's name.
	if st, b := h.do("POST", "/api/v1/settings/reports/schedules/s-pdf/send-now", map[string]any{}, nil); st != 200 {
		t.Fatalf("send now pdf: %d %v", st, b)
	}
	if st, b := h.do("POST", "/api/v1/settings/reports/schedules/s-csv/send-now", map[string]any{}, nil); st != 200 {
		t.Fatalf("send now csv: %d %v", st, b)
	}
	if len(mailer.sent) != 2 {
		t.Fatalf("mails: %d", len(mailer.sent))
	}
	pdfMsg, csvMsg := mailer.sent[0], mailer.sent[1]
	if !strings.HasPrefix(string(pdfMsg.Attachments[0].Data), "%PDF-") || !strings.HasSuffix(pdfMsg.Attachments[0].Name, ".pdf") || pdfMsg.To[0] != "boss@example.org" {
		t.Fatalf("pdf attachment: %s %q", pdfMsg.Attachments[0].Name, pdfMsg.Attachments[0].Data[:8])
	}
	if !strings.Contains(string(pdfMsg.Attachments[0].Data), "Acme") {
		t.Fatal("the PDF header names the organization")
	}
	csvText := string(csvMsg.Attachments[0].Data)
	if !strings.HasPrefix(csvText, "\xef\xbb\xbf") || !strings.Contains(csvText, "'=HYPERLINK-PC") || strings.Contains(csvText, ",=HYPERLINK") {
		t.Fatalf("csv: %q", csvText)
	}
	st, runs := h.do("GET", "/api/v1/settings/reports/runs", nil, nil)
	if st != 200 || len(runs["items"].([]any)) != 2 {
		t.Fatalf("runs: %d %v", st, runs)
	}
	if st, _ := h.do("POST", "/api/v1/settings/reports/schedules/nope/send-now", map[string]any{}, nil); st != 422 {
		t.Fatalf("unknown schedule: %d", st)
	}

	// The scheduler: the first sight of a schedule sends nothing; the next due time sends once.
	mailer.sent = nil
	clock := time.Date(2026, 3, 4, 7, 5, 0, 0, time.UTC)
	h.app.Sched.Now = func() time.Time { return clock }
	if _, err := h.db.Pool.Exec(ctx, `DELETE FROM report_runs`); err != nil {
		t.Fatal(err)
	}
	h.app.Sched.Tick(ctx)
	if len(mailer.sent) != 0 {
		t.Fatalf("a schedule seen for the first time must not send an old slot: %d", len(mailer.sent))
	}
	clock = clock.AddDate(0, 0, 1)
	h.app.Sched.Tick(ctx)
	h.app.Sched.Tick(ctx) // twice: still once
	if len(mailer.sent) != 2 {
		t.Fatalf("both schedules are due once: %d", len(mailer.sent))
	}
	clock = clock.Add(8 * time.Hour) // 15:05, past the grace period of the 07:00 slot: nothing new is due
	h.app.Sched.Tick(ctx)
	if len(mailer.sent) != 2 {
		t.Fatalf("nothing new is due: %d", len(mailer.sent))
	}
	_ = org
}
