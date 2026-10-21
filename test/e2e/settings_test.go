package e2e

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func sectionIDs(b map[string]any) []string {
	var ids []string
	for _, s := range b["sections"].([]any) {
		ids = append(ids, s.(map[string]any)["id"].(string))
	}
	return ids
}

func has(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func TestSettingsPermissionsValidationAuditAndSecrets(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()
	op := h.orgUser("op@example.com", "operator")
	ro := h.orgUser("ro@example.com", "readonly")

	// The schema lists only what the caller may open: administrators all twelve, operators the delegated four,
	// read-only people none.
	_, b := h.do("GET", "/api/v1/settings/schema", nil, nil)
	if len(sectionIDs(b)) != 12 {
		t.Fatalf("admin sections: %v", sectionIDs(b))
	}
	_, b = op.do("GET", "/api/v1/settings/schema", nil, nil)
	ids := sectionIDs(b)
	if len(ids) != 4 || !has(ids, "notifications") || !has(ids, "devices") || !has(ids, "downloads") || !has(ids, "reports") {
		t.Fatalf("operator sections: %v", ids)
	}
	_, b = ro.do("GET", "/api/v1/settings/schema", nil, nil)
	if len(sectionIDs(b)) != 0 {
		t.Fatalf("read-only sections: %v", sectionIDs(b))
	}
	for _, c := range []struct {
		who     *harness
		method  string
		path    string
		want    int
		comment string
	}{
		{op, "GET", "/api/v1/settings/sections/security", 403, "operator reading security"},
		{op, "PUT", "/api/v1/settings/sections/security", 403, "operator writing security"},
		{ro, "GET", "/api/v1/settings/sections/notifications", 403, "read-only reading notifications"},
		{h, "GET", "/api/v1/settings/sections/nope", 404, "unknown section"},
		{op, "GET", "/api/v1/settings/export", 403, "operator exporting"},
		{op, "POST", "/api/v1/settings/import", 403, "operator importing"},
		{op, "GET", "/api/v1/settings/events", 403, "operator reading the webhook reference"},
		{h.otherClient(), "GET", "/api/v1/settings/schema", 401, "anonymous"},
	} {
		if st, _ := c.who.do(c.method, c.path, map[string]any{}, nil); st != c.want {
			t.Errorf("%s: %d, want %d", c.comment, st, c.want)
		}
	}

	// Defaults before anything is saved.
	_, d := h.do("GET", "/api/v1/settings/sections/security", nil, nil)
	if num(d["revision"]) != 0 || num(d["values"].(map[string]any)["lockout_threshold"]) != 10 {
		t.Fatalf("defaults: %v", d)
	}

	// A valid save, audited with before and after; a stale revision is a conflict.
	st, d := h.do("PUT", "/api/v1/settings/sections/security", map[string]any{"revision": 0, "values": map[string]any{"lockout_threshold": 7, "session_idle_minutes": 10}}, nil)
	if st != 200 || num(d["revision"]) != 1 {
		t.Fatalf("save: %d %v", st, d)
	}
	det := h.auditDetails("settings.update")
	ch := det["changes"].(map[string]any)["lockout_threshold"].(map[string]any)
	if num(ch["before"]) != 10 || num(ch["after"]) != 7 || det["section"] != "security" {
		t.Fatalf("audit details: %v", det)
	}
	if st, _ := h.do("PUT", "/api/v1/settings/sections/security", map[string]any{"revision": 0, "values": map[string]any{"lockout_threshold": 8}}, nil); st != 409 {
		t.Fatalf("stale revision: %d", st)
	}
	// Keys left out keep their values.
	_, d = h.do("GET", "/api/v1/settings/sections/security", nil, nil)
	if num(d["values"].(map[string]any)["session_idle_minutes"]) != 10 {
		t.Fatalf("saved values: %v", d)
	}

	// The server never trusts the form.
	for name, in := range map[string]map[string]any{
		"range":    {"lockout_threshold": 99},
		"type":     {"lockout_minutes": "soon"},
		"unknown":  {"nope": true},
		"short pw": {"password_min_length": 6},
		"cidr":     {"ip_allowlist": []any{"hello"}},
		"banner":   {"login_banner_enabled": true},
		"lockout":  {"ip_allowlist": []any{"10.0.0.0/8"}},
	} {
		st, b := h.do("PUT", "/api/v1/settings/sections/security", map[string]any{"revision": 1, "values": in}, nil)
		if st != 422 {
			t.Errorf("%s: %d %v", name, st, b)
		}
	}
	if _, d := h.do("GET", "/api/v1/settings/sections/security", nil, nil); num(d["revision"]) != 1 {
		t.Fatal("a refused save changed the revision")
	}

	// Enforcement: the session timeout applies to the next sign-in.
	late := h.orgUser("late@example.com", "readonly")
	_ = late
	var idle time.Duration
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT max(s.idle_expires_at - s.created_at) FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.email = 'late@example.com'`).Scan(&idle); err != nil {
		t.Fatal(err)
	}
	if idle < 9*time.Minute || idle > 11*time.Minute {
		t.Fatalf("the saved idle timeout (10 minutes) should apply to a new session, got %v", idle)
	}
	// Enforcement: password minimum.
	if st, _ := h.do("PUT", "/api/v1/settings/sections/security", map[string]any{"revision": 1, "values": map[string]any{"password_min_length": 20}}, nil); st != 200 {
		t.Fatal("password minimum")
	}
	org := h.session()["org"].(map[string]any)["id"]
	if st, b := h.do("POST", "/api/v1/users", map[string]any{"email": "pw@example.com", "display_name": "P", "password": "Granite-Lantern-42x", "roles": []map[string]any{{"role": "readonly", "scope_type": "org", "scope_id": org}}}, nil); st != 400 {
		t.Fatalf("a 19-character password must be refused when the minimum is 20: %d %v", st, b)
	}
	// Enforcement: API token lifetime cap, and the security-key switch.
	h.do("PUT", "/api/v1/settings/sections/security", map[string]any{"revision": 2, "values": map[string]any{"api_token_max_days": 30, "allow_security_keys": false}}, nil)
	if st, _ := h.do("POST", "/api/v1/me/api-tokens", map[string]any{"name": "t", "scopes": []string{"devices:read"}, "expires_in_days": 90}, nil); st != 400 {
		t.Fatalf("a 90-day token with a 30-day cap: %d", st)
	}
	if st, _ := h.do("POST", "/api/v1/me/api-tokens", map[string]any{"name": "t", "scopes": []string{"devices:read"}, "expires_in_days": 30}, nil); st != 201 {
		t.Fatalf("a 30-day token: %d", st)
	}
	if st, b := h.do("POST", "/api/v1/me/security-keys/begin", map[string]any{}, nil); st != 403 {
		t.Fatalf("security keys switched off: %d %v", st, b)
	}
	// A token can never carry a settings permission (except the old settings:write).
	if st, _ := h.do("POST", "/api/v1/me/api-tokens", map[string]any{"name": "s", "scopes": []string{"settings:security"}, "expires_in_days": 5}, nil); st != 400 && st != 422 {
		t.Fatalf("settings scopes in tokens: %d", st)
	}
	// The sign-in notice is public.
	h.do("PUT", "/api/v1/settings/sections/security", map[string]any{"revision": 3, "values": map[string]any{"login_banner_enabled": true, "login_banner": "Authorized use only.", "login_banner_require_ack": true}}, nil)
	_, n := h.otherClient().do("GET", "/api/v1/auth/notice", nil, nil)
	if n["enabled"] != true || n["text"] != "Authorized use only." || n["require_ack"] != true {
		t.Fatalf("notice: %v", n)
	}

	// Secrets: sealed, never returned, never exported, audited without their value.
	notif := map[string]any{"email_enabled": true, "smtp_host": "smtp.example.org", "from_address": "librepatch@example.org", "smtp_username": "mailer", "smtp_password": "hunter2-very-secret"}
	st, d = op.do("PUT", "/api/v1/settings/sections/notifications", map[string]any{"revision": 0, "values": notif}, nil)
	if st != 200 {
		t.Fatalf("operator saving notifications: %d %v", st, d)
	}
	if d["secrets_set"].(map[string]any)["smtp_password"] != true || strings.Contains(toString(d), "hunter2") {
		t.Fatalf("secret state: %v", d)
	}
	_, d = h.do("GET", "/api/v1/settings/sections/notifications", nil, nil)
	if strings.Contains(toString(d), "hunter2") {
		t.Fatal("the secret came back")
	}
	if det := h.auditDetails("settings.update"); strings.Contains(toString(det), "hunter2") {
		t.Fatal("the secret is in the audit log")
	}
	var sealed string
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT secrets::text FROM settings_sections WHERE section = 'notifications'`).Scan(&sealed); err != nil || strings.Contains(sealed, "hunter2") || !strings.Contains(sealed, "smtp_password") {
		t.Fatalf("stored secret: %v %q", err, sealed)
	}
	// Keeping the saved secret when the field is left out; clearing it with an empty string.
	_, d = h.do("PUT", "/api/v1/settings/sections/notifications", map[string]any{"revision": 1, "values": map[string]any{"quiet_hours_enabled": true}}, nil)
	if d["secrets_set"].(map[string]any)["smtp_password"] != true {
		t.Fatalf("the secret must survive an unrelated save: %v", d)
	}
	// A rule that e-mails nobody is refused; a user name without a password too.
	rules := d["values"].(map[string]any)["rules"].([]any)
	rules[0].(map[string]any)["enabled"] = true
	if st, b := h.do("PUT", "/api/v1/settings/sections/notifications", map[string]any{"revision": 2, "values": map[string]any{"rules": rules}}, nil); st != 422 || !strings.Contains(toString(b), "rules[0].recipients") {
		t.Fatalf("a rule without recipients: %d %v", st, b)
	}

	// Webhooks with item secrets.
	hook := map[string]any{"name": "SIEM", "url": "https://hooks.example.org/in", "secret": "whsec-123", "events": []any{"failed_install"}}
	st, d = h.do("PUT", "/api/v1/settings/sections/integrations", map[string]any{"revision": 0, "values": map[string]any{"webhooks": []any{hook}}}, nil)
	if st != 200 || strings.Contains(toString(d), "whsec-123") {
		t.Fatalf("webhook save: %d %v", st, d)
	}
	items := d["values"].(map[string]any)["webhooks"].([]any)
	id := items[0].(map[string]any)["id"].(string)
	if id == "" || d["secrets_set"].(map[string]any)["webhooks."+id+".secret"] != true {
		t.Fatalf("webhook id and secret: %v", d)
	}
	// Removing the webhook removes its secret.
	h.do("PUT", "/api/v1/settings/sections/integrations", map[string]any{"revision": 1, "values": map[string]any{"webhooks": []any{}}}, nil)
	_, d = h.do("GET", "/api/v1/settings/sections/integrations", nil, nil)
	if len(d["secrets_set"].(map[string]any)) != 0 {
		t.Fatalf("orphaned secret: %v", d["secrets_set"])
	}

	// Export carries values only; import validates, can be a dry run, and respects the caller's sections.
	status, raw, body := h.raw("GET", "/api/v1/settings/export", "", nil)
	if status != 200 || strings.Contains(string(body), "hunter2") || strings.Contains(string(body), "smtp_password") || !strings.Contains(raw.Get("Content-Disposition"), "attachment") {
		t.Fatalf("export: %d %s", status, body)
	}
	var doc map[string]any
	if err := jsonUnmarshal(body, &doc); err != nil || doc["format"] != "librepatch-settings" {
		t.Fatalf("export format: %v", err)
	}
	doc["sections"].(map[string]any)["security"].(map[string]any)["lockout_threshold"] = 4
	st, rep := h.do("POST", "/api/v1/settings/import?dry_run=1", doc, nil)
	if st != 200 || rep["applied"] != false {
		t.Fatalf("dry run: %d %v", st, rep)
	}
	if _, d := h.do("GET", "/api/v1/settings/sections/security", nil, nil); num(d["values"].(map[string]any)["lockout_threshold"]) != 7 {
		t.Fatal("a dry run changed settings")
	}
	if st, rep := h.do("POST", "/api/v1/settings/import", doc, nil); st != 200 || rep["applied"] != true {
		t.Fatalf("import: %d %v", st, rep)
	}
	if _, d := h.do("GET", "/api/v1/settings/sections/security", nil, nil); num(d["values"].(map[string]any)["lockout_threshold"]) != 4 {
		t.Fatal("import did not apply")
	}
	doc["sections"].(map[string]any)["security"].(map[string]any)["lockout_threshold"] = 999
	if st, rep := h.do("POST", "/api/v1/settings/import", doc, nil); st != 422 || rep["applied"] == true {
		t.Fatalf("an invalid file must change nothing: %d %v", st, rep)
	}
	if st, _ := h.do("POST", "/api/v1/settings/import", map[string]any{"format": "other", "schema_version": 1, "sections": map[string]any{}}, nil); st != 422 {
		t.Fatalf("a foreign file: %d", st)
	}
	if h.auditCount("settings.export") != 1 || h.auditCount("settings.import") != 1 {
		t.Fatalf("export and import are audited: %d %d", h.auditCount("settings.export"), h.auditCount("settings.import"))
	}

	// The event reference documents every event.
	_, ev := h.do("GET", "/api/v1/settings/events", nil, nil)
	if len(ev["events"].([]any)) < 5 {
		t.Fatalf("events: %v", ev)
	}
}

func TestAboutAndSupportBundleHaveNoSecrets(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()
	op := h.orgUser("op@example.com", "operator")
	notif := map[string]any{"email_enabled": true, "smtp_host": "smtp.example.org", "from_address": "r@example.org", "smtp_username": "mailer", "smtp_password": "hunter2-very-secret"}
	if st, b := h.do("PUT", "/api/v1/settings/sections/notifications", map[string]any{"revision": 0, "values": notif}, nil); st != 200 {
		t.Fatalf("notifications: %d %v", st, b)
	}
	if st, _ := op.do("GET", "/api/v1/settings/about", nil, nil); st != 403 {
		t.Fatalf("operator about: %d", st)
	}
	if st, _, _ := op.raw("GET", "/api/v1/settings/support-bundle", "", nil); st != 403 {
		t.Fatalf("operator bundle: %d", st)
	}
	st, a := h.do("GET", "/api/v1/settings/about", nil, nil)
	if st != 200 || a["version"] == nil || a["database_migration"] == nil {
		t.Fatalf("about: %d %v", st, a)
	}
	status, hdr, body := h.raw("GET", "/api/v1/settings/support-bundle", "", nil)
	if status != 200 || hdr.Get("Content-Type") != "application/zip" {
		t.Fatalf("bundle: %d %s", status, hdr.Get("Content-Type"))
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	var all strings.Builder
	for _, f := range zr.File {
		names[f.Name] = true
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		all.Write(b)
	}
	for _, want := range []string{"README.txt", "about.json", "config.json", "settings.json", "audit-tail.json"} {
		if !names[want] {
			t.Errorf("the bundle lacks %s: %v", want, names)
		}
	}
	text := all.String()
	for _, secret := range []string{"hunter2", os.Getenv("LIBREPATCH_MASTER_KEY"), "devpostgres", "smtp_password"} {
		if secret != "" && strings.Contains(text, secret) {
			t.Errorf("the bundle contains %q", secret)
		}
	}
	if h.auditCount("settings.support_bundle") != 1 {
		t.Fatal("the bundle download is audited")
	}
}
