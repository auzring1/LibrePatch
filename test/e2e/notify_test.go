package e2e

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/auzring1/librepatch/internal/server/notify"
)

type fakeMailer struct {
	mu   sync.Mutex
	sent []notify.Message
	fail error
}

func (f *fakeMailer) Send(_ context.Context, _ notify.SMTPConfig, m notify.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.sent = append(f.sent, m)
	return nil
}

type post struct {
	url     string
	headers map[string]string
	body    []byte
}
type fakePoster struct {
	mu    sync.Mutex
	posts []post
	code  int
}

func (f *fakePoster) Post(_ context.Context, url string, h map[string]string, body []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.posts = append(f.posts, post{url, h, body})
	if f.code == 0 {
		return 200, nil
	}
	return f.code, nil
}

func TestNotificationRulesDeliveryQuietHoursAndRetries(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()
	mailer, poster := &fakeMailer{}, &fakePoster{}
	h.app.Notify.Mailer, h.app.Notify.Poster = mailer, poster
	ctx := context.Background()
	org := h.session()["org"].(map[string]any)["id"].(string)
	_ = org

	// A webhook and a rule for failed installs (e-mail and webhook).
	hook := map[string]any{"name": "SIEM", "url": "https://hooks.example.org/in", "secret": "whsec-123", "events": []any{"failed_install"}}
	if st, b := h.do("PUT", "/api/v1/settings/sections/integrations", map[string]any{"revision": 0, "values": map[string]any{"webhooks": []any{hook}}}, nil); st != 200 {
		t.Fatalf("webhook: %d %v", st, b)
	}
	_, d := h.do("GET", "/api/v1/settings/sections/notifications", nil, nil)
	rules := d["values"].(map[string]any)["rules"].([]any)
	r0 := rules[0].(map[string]any)
	r0["enabled"], r0["recipients"] = true, []any{"oncall@example.org"}
	vals := map[string]any{"email_enabled": true, "smtp_host": "smtp.example.org", "from_address": "librepatch@example.org", "rules": rules}
	if st, b := h.do("PUT", "/api/v1/settings/sections/notifications", map[string]any{"revision": 0, "values": vals}, nil); st != 200 {
		t.Fatalf("rules: %d %v", st, b)
	}

	ev := notify.Event{Name: "failed_install", Key: "job:1", Subject: "Install 7-Zip failed on PC-1", Text: "exit code 1603", Data: map[string]any{"device": map[string]any{"hostname": "PC-1"}}}
	h.app.Notify.Emit(ctx, parseUUID(t, org), ev)
	h.app.Notify.Emit(ctx, parseUUID(t, org), ev) // the same key: queued once
	h.app.Notify.Tick(ctx)
	if len(mailer.sent) != 1 || mailer.sent[0].To[0] != "oncall@example.org" || !strings.Contains(mailer.sent[0].Subject, "Install 7-Zip failed") {
		t.Fatalf("mail: %+v", mailer.sent)
	}
	if len(poster.posts) != 1 {
		t.Fatalf("webhook posts: %d", len(poster.posts))
	}
	p := poster.posts[0]
	sig := p.headers["X-LibrePatch-Signature"]
	ts := p.headers["X-LibrePatch-Timestamp"]
	if sig == "" || p.headers["X-LibrePatch-Event"] != "failed_install" || !strings.HasPrefix(sig, "sha256=") {
		t.Fatalf("headers: %v", p.headers)
	}
	var tsn int64
	for _, c := range ts {
		tsn = tsn*10 + int64(c-'0')
	}
	if sig != notify.Sign("whsec-123", tsn, p.body) {
		t.Fatal("the signature does not verify with the secret")
	}
	var pay map[string]any
	if err := jsonUnmarshal(p.body, &pay); err != nil || pay["event"] != "failed_install" || !strings.Contains(string(p.body), "PC-1") || pay["id"] == "" {
		t.Fatalf("payload: %s", p.body)
	}

	// A different event with no rule is dropped.
	h.app.Notify.Emit(ctx, parseUUID(t, org), notify.Event{Name: "update_held", Subject: "x", Text: "y"})
	h.app.Notify.Tick(ctx)
	if len(mailer.sent) != 1 {
		t.Fatal("an event without an enabled rule must not send")
	}

	// A failing mail server: retried with a back-off, error recorded, nothing lost.
	mailer.fail = errors.New("450 try again later")
	h.app.Notify.Emit(ctx, parseUUID(t, org), notify.Event{Name: "failed_install", Key: "job:2", Subject: "second", Text: "again"})
	h.app.Notify.Tick(ctx)
	var attempts int
	var status, lastErr string
	if err := h.db.Pool.QueryRow(ctx, `SELECT attempts, status, last_error FROM notification_outbox WHERE channel = 'email' AND dedupe_key = 'job:2'`).Scan(&attempts, &status, &lastErr); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || status != "pending" || !strings.Contains(lastErr, "450") {
		t.Fatalf("retry state: %d %s %q", attempts, status, lastErr)
	}
	mailer.fail = nil
	if _, err := h.db.Pool.Exec(ctx, `UPDATE notification_outbox SET not_before = now() - interval '1 minute' WHERE dedupe_key = 'job:2'`); err != nil {
		t.Fatal(err)
	}
	h.app.Notify.Tick(ctx)
	if len(mailer.sent) != 2 {
		t.Fatalf("the retry should deliver: %d", len(mailer.sent))
	}

	// Quiet hours hold a message until they end.
	vals = map[string]any{"quiet_hours_enabled": true, "quiet_start": "00:00", "quiet_end": "23:59", "quiet_time_zone": "UTC"}
	_, d = h.do("GET", "/api/v1/settings/sections/notifications", nil, nil)
	if st, b := h.do("PUT", "/api/v1/settings/sections/notifications", map[string]any{"revision": d["revision"], "values": vals}, nil); st != 200 {
		t.Fatalf("quiet hours: %d %v", st, b)
	}
	h.app.Notify.Emit(ctx, parseUUID(t, org), notify.Event{Name: "failed_install", Key: "job:3", Subject: "third", Text: "held"})
	h.app.Notify.Tick(ctx)
	if len(mailer.sent) != 2 {
		t.Fatal("quiet hours must hold the message")
	}
	var held time.Time
	if err := h.db.Pool.QueryRow(ctx, `SELECT not_before FROM notification_outbox WHERE dedupe_key = 'job:3' AND channel = 'email'`).Scan(&held); err != nil || !held.After(time.Now()) {
		t.Fatalf("held until: %v %v", held, err)
	}

	// Test buttons use the saved settings and report the server's own error.
	mailer.fail = errors.New("535 authentication failed")
	if st, b := h.do("POST", "/api/v1/settings/notifications/test-email", map[string]any{"to": "me@example.org"}, nil); st != 422 || !strings.Contains(toString(b), "535") {
		t.Fatalf("failing test e-mail: %d %v", st, b)
	}
	mailer.fail = nil
	if st, _ := h.do("POST", "/api/v1/settings/notifications/test-email", map[string]any{"to": "not an address"}, nil); st != 422 {
		t.Fatal("bad address")
	}
	if st, b := h.do("POST", "/api/v1/settings/notifications/test-email", map[string]any{"to": "me@example.org"}, nil); st != 200 {
		t.Fatalf("test e-mail: %d %v", st, b)
	}
	_, d = h.do("GET", "/api/v1/settings/sections/integrations", nil, nil)
	hid := d["values"].(map[string]any)["webhooks"].([]any)[0].(map[string]any)["id"].(string)
	if st, b := h.do("POST", "/api/v1/settings/integrations/webhooks/"+hid+"/test", map[string]any{}, nil); st != 200 {
		t.Fatalf("test webhook: %d %v", st, b)
	}
	poster.code = 500
	if st, b := h.do("POST", "/api/v1/settings/integrations/webhooks/"+hid+"/test", map[string]any{}, nil); st != 422 || !strings.Contains(toString(b), "500") {
		t.Fatalf("failing webhook: %d %v", st, b)
	}
}
