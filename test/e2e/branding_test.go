package e2e

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/auzring1/librepatch/internal/server/auth"
)

func brandPNG(t testing.TB, w, h int) []byte {
	t.Helper()
	im := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			im.Set(x, y, color.NRGBA{uint8(x), uint8(y), 90, 255})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, im); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// raw sends a non-JSON request with the harness session (cookies, CSRF, Origin) and returns status, headers and body.
func (h *harness) raw(method, path, contentType string, body []byte) (int, http.Header, []byte) {
	h.t.Helper()
	req, _ := http.NewRequest(method, h.base+path, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Origin", h.origin)
	if h.csrf != "" {
		req.Header.Set("X-CSRF-Token", h.csrf)
	}
	resp, err := h.http.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, out
}

func (h *harness) auditCount(action string) int {
	var n int
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action=$1 AND outcome='success'`, action).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func (h *harness) auditDetails(action string) map[string]any {
	var raw []byte
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT details FROM audit_log WHERE action=$1 ORDER BY id DESC LIMIT 1`, action).Scan(&raw); err != nil {
		h.t.Fatalf("audit %s: %v", action, err)
	}
	var d map[string]any
	_ = json.Unmarshal(raw, &d)
	return d
}

// orgUser creates a user with an organization-wide role and returns a signed-in client.
func (h *harness) orgUser(email, role string) *harness {
	org := h.session()["org"].(map[string]any)["id"]
	st, nu := h.do("POST", "/api/v1/users", map[string]any{"email": email, "display_name": role,
		"roles": []map[string]any{{"role": role, "scope_type": "org", "scope_id": org}}}, nil)
	if st != 201 {
		h.t.Fatalf("create %s: %d %v", role, st, nu)
	}
	c := h.otherClient()
	c.signInNewUser(email, nu["temporary_password"].(string), "Quartz-Harbor-Violin-77", false)
	return c
}

func TestBrandingDefaultsAndWizard(t *testing.T) {
	h := newHarness(t)
	// Before setup the public endpoint already answers with the stock product and no organization.
	st, b := h.do("GET", "/api/v1/branding", nil, nil)
	if st != 200 || b["product_name"] != "LibrePatch" || b["org_name"] != "" || b["title"] != "LibrePatch" || b["accent_color"] != "#1971c2" {
		t.Fatalf("stock branding: %d %v", st, b)
	}
	if st, _, _ := h.raw("GET", "/api/v1/branding/assets/logo_light", "", nil); st != 404 {
		t.Fatalf("no logo before setup: %d", st)
	}

	// The wizard takes an optional logo; a bad one stops setup before anything is created.
	st, begin := h.do("POST", "/api/v1/setup/begin", map[string]any{"setup_token": h.app.SetupToken(), "email": "admin@example.com"}, nil)
	if st != 200 {
		t.Fatalf("begin: %d %v", st, begin)
	}
	req := func(logo string, code string) map[string]any {
		return map[string]any{"setup_token": h.app.SetupToken(), "org_name": "Example Clinic", "display_name": "Ada Admin",
			"email": "admin@example.com", "password": adminPassword, "root_passphrase": "a-long-root-ca-passphrase", "totp_code": code, "logo_base64": logo}
	}
	h.setupSecret(begin)
	svg := base64.StdEncoding.EncodeToString([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`))
	if st, b := h.do("POST", "/api/v1/setup/complete", req(svg, h.code(0)), nil); st != 400 || !strings.Contains(toString(b), "SVG") {
		t.Fatalf("an SVG logo in the wizard: %d %v", st, b)
	}
	if st, _ := h.do("POST", "/api/v1/setup/complete", req("!!notbase64!!", h.code(0)), nil); st != 400 {
		t.Fatalf("garbage logo: %d", st)
	}
	if st, b := h.do("GET", "/api/v1/setup/status", nil, nil); st != 200 || b["setup_required"] != true {
		t.Fatal("a refused logo must not complete setup")
	}
	logo := base64.StdEncoding.EncodeToString(brandPNG(t, 240, 80))
	if st, b := h.do("POST", "/api/v1/setup/complete", req(logo, h.code(0)), nil); st != 200 {
		t.Fatalf("setup with logo: %d %v", st, b)
	}

	st, b = h.do("GET", "/api/v1/branding", nil, nil)
	if st != 200 || b["org_name"] != "Example Clinic" || b["product_name"] != "LibrePatch" || b["title"] != "Example Clinic · LibrePatch" {
		t.Fatalf("after setup: %d %v", st, b)
	}
	assets := b["assets"].(map[string]any)
	ll, ok := assets["logo_light"].(map[string]any)
	if !ok || ll["width"] != float64(240) || ll["height"] != float64(80) || !strings.HasPrefix(ll["url"].(string), "/api/v1/branding/assets/logo_light?v=") {
		t.Fatalf("logo: %v", assets)
	}
	// The shell page carries the title and the data for the first paint.
	_, hdr, body := h.raw("GET", "/", "", nil)
	if !strings.Contains(string(body), "<title>Example Clinic · LibrePatch</title>") || !strings.Contains(string(body), `id="branding-data"`) {
		t.Fatalf("index shell: %.300s", body)
	}
	if strings.Contains(hdr.Get("Content-Security-Policy"), "unsafe-inline") {
		t.Fatalf("CSP: %s", hdr.Get("Content-Security-Policy"))
	}
	if h.auditDetails("setup.complete")["org_name"] != "Example Clinic" {
		t.Fatal("the setup audit entry must name the organization")
	}
}

func TestBrandingAdministration(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin() // organization "Acme"
	operator := h.orgUser("op@example.com", "operator")
	readonly := h.orgUser("ro@example.com", "readonly")

	// Only administrators: operators and read-only users can read the public page but nothing under /settings/branding.
	for name, c := range map[string]*harness{"operator": operator, "readonly": readonly} {
		for _, rq := range []struct{ m, p string }{
			{"GET", "/settings/branding"}, {"PUT", "/settings/branding"}, {"POST", "/settings/branding/reset"},
			{"PUT", "/settings/branding/assets/logo_light"}, {"DELETE", "/settings/branding/assets/logo_light"},
		} {
			if st, _, _ := c.raw(rq.m, "/api/v1"+rq.p, "application/json", []byte(`{}`)); st != 403 {
				t.Errorf("%s %s %s: %d, want 403", name, rq.m, rq.p, st)
			}
		}
		if st, _ := c.do("GET", "/api/v1/branding", nil, nil); st != 200 {
			t.Errorf("%s may read the public branding: %d", name, st)
		}
	}
	// No session at all.
	anon := h.otherClient()
	if st, _ := anon.do("GET", "/api/v1/settings/branding", nil, nil); st != 401 {
		t.Fatalf("anonymous: %d", st)
	}
	if st, _ := anon.do("PUT", "/api/v1/settings/branding", map[string]any{"org_name": "Hacked"}, nil); st != 401 && st != 403 {
		t.Fatalf("anonymous write: %d", st)
	}
	// CSRF protection applies to the administrator's session too.
	if st, _ := h.do("PUT", "/api/v1/settings/branding", map[string]any{"org_name": "Hacked"}, map[string]string{"X-CSRF-Token": ""}); st != 403 {
		t.Fatalf("missing CSRF token: %d", st)
	}
	// An API token cannot carry the permission, even for an administrator.
	if st, _ := h.do("POST", "/api/v1/me/api-tokens", map[string]any{"name": "x", "scopes": []string{"branding:write"}, "expires_in_days": 30}, nil); st != 400 {
		t.Fatalf("branding:write in an API token: %d", st)
	}
	_, tok := h.do("POST", "/api/v1/me/api-tokens", map[string]any{"name": "ro", "scopes": []string{"devices:read"}, "expires_in_days": 30}, nil)
	if st, _ := h.bearer(tok["token"].(string), "GET", "/api/v1/settings/branding", nil); st != 403 {
		t.Fatalf("token without scope: %d", st)
	}

	// Initial view: the organization from setup, product defaults, and no images.
	st, v := h.do("GET", "/api/v1/settings/branding", nil, nil)
	if st != 200 {
		t.Fatalf("view: %d %v", st, v)
	}
	s0 := v["settings"].(map[string]any)
	if s0["org_name"] != "Acme" || s0["product_name"] != "" || s0["accent_color"] != "" || len(v["assets"].(map[string]any)) != 0 {
		t.Fatalf("initial settings: %v", s0)
	}
	if v["defaults"].(map[string]any)["product_name"] != "LibrePatch" {
		t.Fatalf("defaults: %v", v["defaults"])
	}
	for _, c := range v["contrast"].([]any) {
		if c.(map[string]any)["pass"] != true {
			t.Fatalf("the default accent must pass: %v", c)
		}
	}

	// Update: validation first.
	bad := map[string]any{"org_name": "Acme", "accent_color": "#ffd43b"}
	st, b := h.do("PUT", "/api/v1/settings/branding", bad, nil)
	eb, _ := b["error"].(map[string]any)
	if st != 422 || eb["code"] != "invalid_branding" || eb["fields"].(map[string]any)["accent_color"] == nil {
		t.Fatalf("low-contrast accent: %d %v", st, b)
	}
	for field, in := range map[string]map[string]any{
		"support_url":   {"support_url": "javascript:alert(1)"},
		"support_email": {"support_email": "nope"},
		"org_name":      {"org_name": strings.Repeat("x", 121)},
	} {
		st, b := h.do("PUT", "/api/v1/settings/branding", in, nil)
		eb, _ := b["error"].(map[string]any)
		if st != 422 || eb["fields"].(map[string]any)[field] == nil {
			t.Errorf("%s: %d %v", field, st, b)
		}
	}
	if h.auditCount("branding.update") != 0 {
		t.Fatal("a refused change must not be audited as a change")
	}

	// A valid update is stored, normalized, audited with before/after, and visible on the public page.
	good := map[string]any{"org_name": "Example Clinic", "product_name": "PatchBoard", "accent_color": "#C92A2A", "secondary_color": "#E8590C",
		"login_headline": "Welcome", "login_message": "Sign in with your work account.", "login_footer": "Authorized use only.",
		"support_email": "Help@Example.org", "support_phone": "+1 555 010 0100", "support_url": "https://example.org/help", "report_footer": "Confidential"}
	st, v = h.do("PUT", "/api/v1/settings/branding", good, nil)
	if st != 200 {
		t.Fatalf("update: %d %v", st, v)
	}
	if r := v["resolved"].(map[string]any); r["product_name"] != "PatchBoard" || r["org_name"] != "Example Clinic" || r["accent_color"] != "#c92a2a" {
		t.Fatalf("the response to a save must carry the new resolved values: %v", r)
	}
	if h.auditCount("branding.update") != 1 {
		t.Fatalf("audit entries: %d", h.auditCount("branding.update"))
	}
	d := h.auditDetails("branding.update")
	before, after := d["before"].(map[string]any), d["after"].(map[string]any)
	if before["org_name"] != "Acme" || after["org_name"] != "Example Clinic" || after["accent_color"] != "#c92a2a" || after["support_email"] != "help@example.org" {
		t.Fatalf("audit before/after: %v", d)
	}
	if _, ok := before["login_headline"]; ok && before["login_headline"] == after["login_headline"] {
		t.Fatal("only changed fields belong in the audit entry")
	}
	// Saving the same thing again changes nothing and writes nothing.
	if st, _ := h.do("PUT", "/api/v1/settings/branding", good, nil); st != 200 || h.auditCount("branding.update") != 1 {
		t.Fatalf("idempotent save: %d, entries %d", st, h.auditCount("branding.update"))
	}
	_, pub := anon.do("GET", "/api/v1/branding", nil, nil)
	if pub["product_name"] != "PatchBoard" || pub["org_name"] != "Example Clinic" || pub["title"] != "Example Clinic · PatchBoard" || pub["login_headline"] != "Welcome" {
		t.Fatalf("public: %v", pub)
	}
	support := pub["support"].(map[string]any)
	if support["email"] != "help@example.org" || support["url"] != "https://example.org/help" {
		t.Fatalf("support: %v", support)
	}
	if _, leaks := pub["report_footer"]; leaks {
		t.Fatal("the public endpoint must expose only login-page display fields")
	}
	// The TOTP issuer and the page shell follow the product-name override.
	_, hdr, body := h.raw("GET", "/login", "", nil)
	if !strings.Contains(string(body), "<title>Example Clinic · PatchBoard</title>") || strings.Contains(hdr.Get("Content-Security-Policy"), "unsafe") {
		t.Fatalf("shell: %.200s / %s", body, hdr.Get("Content-Security-Policy"))
	}
	// Etag revalidation.
	req, _ := http.NewRequest("GET", h.base+"/api/v1/branding", nil)
	resp, _ := http.DefaultClient.Do(req)
	etag := resp.Header.Get("ETag")
	_ = resp.Body.Close()
	req.Header.Set("If-None-Match", etag)
	resp, _ = http.DefaultClient.Do(req)
	_ = resp.Body.Close()
	if etag == "" || resp.StatusCode != 304 {
		t.Fatalf("etag %q -> %d", etag, resp.StatusCode)
	}

	// Images.
	st, hd, _ := h.raw("PUT", "/api/v1/settings/branding/assets/logo_light", "image/svg+xml", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`))
	_ = hd
	if st != 415 {
		t.Fatalf("svg: %d", st)
	}
	if st, _, body := h.raw("PUT", "/api/v1/settings/branding/assets/logo_light", "image/png", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)); st != 422 || !strings.Contains(string(body), "SVG") {
		t.Fatalf("svg declared as png: %d %s", st, body)
	}
	if st, _, _ := h.raw("PUT", "/api/v1/settings/branding/assets/logo_light", "text/html", []byte(`<script>`)); st != 415 {
		t.Fatalf("html: %d", st)
	}
	if st, _, _ := h.raw("PUT", "/api/v1/settings/branding/assets/logo_light", "image/png", bytes.Repeat([]byte{0x89}, 600<<10)); st != 413 {
		t.Fatalf("oversize: %d", st)
	}
	if st, _, _ := h.raw("PUT", "/api/v1/settings/branding/assets/icon", "image/png", brandPNG(t, 128, 64)); st != 422 {
		t.Fatalf("non-square icon: %d", st)
	}
	if st, _, _ := h.raw("PUT", "/api/v1/settings/branding/assets/wallpaper", "image/png", brandPNG(t, 128, 128)); st != 404 {
		t.Fatalf("unknown slot: %d", st)
	}
	if h.auditCount("branding.asset_set") != 0 {
		t.Fatal("refused uploads must not be audited as changes")
	}

	dirty := append(brandPNG(t, 300, 100), []byte("<script>alert(1)</script>TRAILING")...)
	st, _, body = h.raw("PUT", "/api/v1/settings/branding/assets/logo_light", "image/png", dirty)
	if st != 200 {
		t.Fatalf("logo: %d %s", st, body)
	}
	if st, _, _ := h.raw("PUT", "/api/v1/settings/branding/assets/favicon", "image/png", brandPNG(t, 32, 32)); st != 200 {
		t.Fatalf("favicon: %d", st)
	}
	if h.auditCount("branding.asset_set") != 2 {
		t.Fatalf("asset audit entries: %d", h.auditCount("branding.asset_set"))
	}
	var pv map[string]any
	_ = json.Unmarshal(body, &pv)
	url := pv["resolved"].(map[string]any)["assets"].(map[string]any)["logo_light"].(map[string]any)["url"].(string)

	// Serving: anonymous, always PNG, locked-down headers, no trailing payload.
	st, hd, img := anon.raw("GET", url, "", nil)
	if st != 200 || hd.Get("Content-Type") != "image/png" || hd.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.Contains(hd.Get("Content-Security-Policy"), "default-src 'none'") || !strings.Contains(hd.Get("Content-Security-Policy"), "sandbox") ||
		hd.Get("Cross-Origin-Resource-Policy") != "same-origin" || !strings.Contains(hd.Get("Cache-Control"), "immutable") {
		t.Fatalf("asset: %d %v", st, hd)
	}
	if bytes.Contains(img, []byte("<script")) || bytes.Contains(img, []byte("TRAILING")) {
		t.Fatal("the served image still has the uploaded trailing payload")
	}
	if cfg, err := png.DecodeConfig(bytes.NewReader(img)); err != nil || cfg.Width != 300 || cfg.Height != 100 {
		t.Fatalf("served image: %v %v", cfg, err)
	}
	if st, _, _ := anon.raw("GET", "/api/v1/branding/assets/logo_dark", "", nil); st != 404 {
		t.Fatalf("empty slot: %d", st)
	}
	if st, _, _ := anon.raw("GET", "/api/v1/branding/assets/..%2f..%2fetc%2fpasswd", "", nil); st != 404 {
		t.Fatalf("path-like kind: %d", st)
	}
	// The favicon appears in the page shell.
	_, _, body = h.raw("GET", "/", "", nil)
	if !strings.Contains(string(body), `rel="icon" href="/api/v1/branding/assets/favicon?v=`) {
		t.Fatalf("favicon link missing: %.600s", body)
	}

	// The printable report carries the logo, the organization and the footer, and escapes everything.
	if st, _ := h.do("PUT", "/api/v1/settings/branding", mergeMap(good, map[string]any{"report_footer": "Confidential <script>alert(1)</script>"}), nil); st != 200 {
		t.Fatal("footer update")
	}
	st, hd, body = h.raw("GET", "/api/v1/reports/compliance.html", "", nil)
	page := string(body)
	if st != 200 || !strings.HasPrefix(hd.Get("Content-Type"), "text/html") || !strings.Contains(page, "Example Clinic") || !strings.Contains(page, "data:image/png;base64,") ||
		!strings.Contains(page, "Confidential &lt;script&gt;") || strings.Contains(page, "<script") || !strings.Contains(hd.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("report: %d %s", st, page)
	}
	if st, _, _ := operator.raw("GET", "/api/v1/reports/compliance.html", "", nil); st != 200 {
		t.Fatalf("operators may export reports: %d", st)
	}
	if st, _, _ := readonly.raw("GET", "/api/v1/reports/compliance.html", "", nil); st != 403 {
		t.Fatalf("read-only users may not export: %d", st)
	}

	// Deleting an image and resetting.
	if st, _ := h.do("DELETE", "/api/v1/settings/branding/assets/favicon", nil, nil); st != 200 || h.auditCount("branding.asset_delete") != 1 {
		t.Fatal("delete favicon")
	}
	if st, _ := h.do("DELETE", "/api/v1/settings/branding/assets/favicon", nil, nil); st != 404 {
		t.Fatalf("delete twice: %d", st)
	}
	st, v = h.do("POST", "/api/v1/settings/branding/reset", map[string]any{}, nil)
	if st != 200 || h.auditCount("branding.reset") != 1 {
		t.Fatalf("reset: %d %v", st, v)
	}
	s1 := v["settings"].(map[string]any)
	if s1["org_name"] != "" || s1["product_name"] != "" || s1["accent_color"] != "" || s1["login_headline"] != "" || len(v["assets"].(map[string]any)) != 0 {
		t.Fatalf("after reset: %v", v)
	}
	rd := h.auditDetails("branding.reset")
	if rd["before"] == nil {
		t.Fatalf("reset audit must record what was removed: %v", rd)
	}
	_, pub = anon.do("GET", "/api/v1/branding", nil, nil)
	if pub["product_name"] != "LibrePatch" || pub["org_name"] != "" || pub["title"] != "LibrePatch" {
		t.Fatalf("defaults after reset: %v", pub)
	}
	if st, _, _ := anon.raw("GET", url, "", nil); st != 404 {
		t.Fatalf("the logo must be gone after a reset: %d", st)
	}
}

func mergeMap(a, b map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// setupSecret reads the authenticator secret from a /setup/begin response, as setupAndLogin does.
func (h *harness) setupSecret(begin map[string]any) {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(begin["totp_secret"].(string))
	if err != nil {
		h.t.Fatal(err)
	}
	h.totp, h.step = secret, auth.TOTPStep(time.Now())
}
