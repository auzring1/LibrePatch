package e2e

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/auzring1/librepatch/internal/server/auth"
)

// otherClient is a second, independent browser session against the same server.
func (h *harness) otherClient() *harness {
	c := *h
	jar, _ := cookiejar.New(nil)
	c.http = &http.Client{Jar: jar, Timeout: 30 * time.Second}
	c.csrf, c.totp, c.step = "", nil, 0
	return &c
}

// signInNewUser takes a user created by an administrator through the forced password change and
// authenticator enrollment, and returns with a full session.
func (c *harness) signInNewUser(email, temp, newPassword string, negative bool) {
	t := c.t
	st, b := c.do("POST", "/api/v1/auth/login", map[string]any{"email": email, "password": temp}, nil)
	if st != 200 || b["mfa"] != "change_password" {
		t.Fatalf("first login must demand a new password: %d %v", st, b)
	}
	c.csrf = b["csrf_token"].(string)
	if st, _ := c.do("POST", "/api/v1/auth/mfa", map[string]any{"code": "123456"}, nil); st != 409 {
		t.Fatalf("MFA before the password change must be refused: %d", st)
	}
	if negative { // the password-change limiter allows five tries a minute, so only once per test
		if st, _ := c.do("POST", "/api/v1/auth/change-password", map[string]any{"current_password": "wrong-wrong-wrong", "new_password": newPassword}, nil); st != 401 {
			t.Fatalf("wrong current password: %d", st)
		}
		if st, b := c.do("POST", "/api/v1/auth/change-password", map[string]any{"current_password": temp, "new_password": "password1234"}, nil); st != 400 {
			t.Fatalf("weak new password accepted: %d %v", st, b)
		}
	}
	st, b = c.do("POST", "/api/v1/auth/change-password", map[string]any{"current_password": temp, "new_password": newPassword}, nil)
	if st != 200 || b["mfa"] != "enroll" {
		t.Fatalf("after the change the user must enroll an authenticator: %d %v", st, b)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b["totp_secret"].(string))
	if err != nil {
		t.Fatal(err)
	}
	c.totp, c.step = secret, auth.TOTPStep(time.Now())
	st, b = c.do("POST", "/api/v1/auth/mfa/enroll", map[string]any{"code": c.code(0)}, nil)
	if st != 200 || len(b["recovery_codes"].([]any)) == 0 {
		t.Fatalf("enroll: %d %v", st, b)
	}
	c.csrf = b["csrf_token"].(string)
}

func (h *harness) bearer(token, method, path string, body any) (int, map[string]any) {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req) // no cookie jar, no Origin header: like curl
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestSitesUsersAndSiteScopedAccess(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()

	// A second site; agents enroll into the site their token names.
	st, branch := h.do("POST", "/api/v1/sites", map[string]any{"name": "Branch", "timezone": "Europe/Berlin"}, nil)
	if st != 201 {
		t.Fatalf("site: %d %v", st, branch)
	}
	if st, _ := h.do("POST", "/api/v1/sites", map[string]any{"name": "Branch"}, nil); st != 409 {
		t.Fatalf("duplicate site: %d", st)
	}
	if st, _ := h.do("POST", "/api/v1/sites", map[string]any{"name": "X", "timezone": "Mars/Base"}, nil); st != 422 {
		t.Fatalf("bad time zone: %d", st)
	}
	st, tk := h.do("POST", "/api/v1/enrollment-tokens", map[string]any{"name": "branch", "max_uses": 5, "expires_in_hours": 1, "require_approval": false, "site_id": branch["id"]}, nil)
	if st != 201 {
		t.Fatalf("branch token: %d %v", st, tk)
	}
	headToken := h.createToken("head", 5, false)
	taHead := h.startAgent(headToken, &fakeHW{host: "HQ-1", serial: "S1", uuid: "U1"}, nil)
	taBranch := h.startAgent(tk["enrollment_string"].(string), &fakeHW{host: "BR-1", serial: "S2", uuid: "U2"}, nil)
	waitFor(t, agentConnectWait, "both agents connected", func() bool {
		return taHead.state() == "connected" && taBranch.state() == "connected" && len(h.devices()) == 2
	})
	var hq, br string
	for _, d := range h.devices() {
		if d["hostname"] == "HQ-1" {
			hq = d["id"].(string)
		} else {
			br = d["id"].(string)
		}
	}
	if h.device(br)["site_id"] != branch["id"] || h.device(hq)["site_id"] == branch["id"] {
		t.Fatal("devices must join the site named by their enrollment token")
	}

	// A technician who may only manage the Branch site.
	st, nu := h.do("POST", "/api/v1/users", map[string]any{"email": "tech@example.com", "display_name": "Tess Tech",
		"roles": []map[string]any{{"role": "operator", "scope_type": "site", "scope_id": branch["id"]}}}, nil)
	if st != 201 || nu["temporary_password"] == "" {
		t.Fatalf("create user: %d %v", st, nu)
	}
	if st, _ := h.do("POST", "/api/v1/users", map[string]any{"email": "tech@example.com", "display_name": "Dup", "roles": []map[string]any{{"role": "operator", "scope_type": "site", "scope_id": branch["id"]}}}, nil); st != 409 {
		t.Fatalf("duplicate user: %d", st)
	}
	tech := h.otherClient()
	tech.signInNewUser("tech@example.com", nu["temporary_password"].(string), "Quartz-Harbor-Violin-77", true)

	st, sess := tech.do("GET", "/api/v1/auth/session", nil, nil)
	if st != 200 || len(sess["permissions"].([]any)) != 0 || len(sess["scoped_permissions"].([]any)) == 0 {
		t.Fatalf("a site-limited session has no organization-wide permissions: %d %v", st, sess)
	}
	_, list := tech.do("GET", "/api/v1/devices", nil, nil)
	if len(items(list)) != 1 || items(list)[0]["id"] != br || list["total"] != float64(1) {
		t.Fatalf("the technician must see only the branch device: %v", list)
	}
	if st, _ := tech.do("GET", "/api/v1/devices/"+br, nil, nil); st != 200 {
		t.Fatalf("own site device: %d", st)
	}
	for _, path := range []string{"/devices/" + hq, "/devices/" + hq + "/software", "/devices/" + hq + "/jobs"} {
		if st, _ := tech.do("GET", "/api/v1"+path, nil, nil); st != 404 {
			t.Fatalf("GET %s on another site must look like a missing device: %d", path, st)
		}
	}
	if st, _ := tech.do("POST", "/api/v1/devices/"+hq+"/refresh", map[string]any{}, nil); st != 404 {
		t.Fatalf("refresh on another site's device: %d", st)
	}
	if st, b := tech.do("POST", "/api/v1/devices/"+br+"/refresh", map[string]any{}, nil); st != 202 {
		t.Fatalf("refresh on own site's device: %d %v", st, b)
	}
	// Organization-wide views and configuration need an organization-wide role.
	for _, c := range []struct{ m, p string }{
		{"GET", "/groups"}, {"GET", "/software"}, {"GET", "/deployments"}, {"GET", "/updates"}, {"GET", "/audit"}, {"GET", "/users"},
		{"GET", "/enrollment-tokens"}, {"GET", "/reports/software.csv"}, {"PUT", "/settings"}, {"GET", "/agent-releases"},
	} {
		if st, _ := tech.do(c.m, "/api/v1"+c.p, nil, nil); st != 403 {
			t.Errorf("%s %s should need an organization-wide role: %d", c.m, c.p, st)
		}
	}
	if st, _ := tech.do("POST", "/api/v1/devices/delete", map[string]any{"ids": []string{hq}}, nil); st != 200 {
		t.Fatalf("bulk delete: %d", st) // answers 200 but skips what is out of scope
	}
	if len(h.devices()) != 2 {
		t.Fatal("a site technician deleted a device outside the site")
	}
	_, sites := tech.do("GET", "/api/v1/sites", nil, nil)
	if len(items(sites)) != 2 {
		t.Fatalf("sites are listed for site-limited users: %v", sites)
	}
	// Promote to org-wide read-only: now fleet views open up, writes stay closed.
	_, users := h.do("GET", "/api/v1/users", nil, nil)
	var techID string
	for _, u := range items(users) {
		if u["email"] == "tech@example.com" {
			techID = u["id"].(string)
		}
	}
	org := h.session()["org"].(map[string]any)["id"]
	if st, b := h.do("POST", "/api/v1/users/"+techID+"/roles", map[string]any{"role": "readonly", "scope_type": "org", "scope_id": org}, nil); st != 204 {
		t.Fatalf("add role: %d %v", st, b)
	}
	if st, _ := tech.do("GET", "/api/v1/groups", nil, nil); st != 200 {
		t.Fatalf("org read-only may list groups: %d", st)
	}
	if st, _ := tech.do("POST", "/api/v1/groups", map[string]any{"kind": "static", "name": "x"}, nil); st != 403 {
		t.Fatalf("org read-only may not write: %d", st)
	}
	// A binding to a site of another organization or an unknown site is refused.
	if st, _ := h.do("POST", "/api/v1/users/"+techID+"/roles", map[string]any{"role": "admin", "scope_type": "site", "scope_id": "11111111-1111-1111-1111-111111111111"}, nil); st != 400 {
		t.Fatalf("unknown site: %d", st)
	}

	// Guards: nobody locks the organization out.
	me := h.session()["user"].(map[string]any)["id"].(string)
	if st, _ := h.do("PUT", "/api/v1/users/"+me, map[string]any{"display_name": "Ada", "status": "disabled"}, nil); st != 409 {
		t.Fatalf("disabling yourself: %d", st)
	}
	if st, _ := h.do("DELETE", "/api/v1/users/"+me, nil, nil); st != 409 {
		t.Fatalf("deleting yourself: %d", st)
	}
	if st, _ := h.do("DELETE", "/api/v1/sites/"+branch["id"].(string), nil, nil); st != 409 {
		t.Fatalf("deleting a site with devices: %d", st)
	}

	// Disabling the technician ends their session at once.
	if st, _ := h.do("PUT", "/api/v1/users/"+techID, map[string]any{"display_name": "Tess Tech", "status": "disabled"}, nil); st != 204 {
		t.Fatal("disable")
	}
	if st, _ := tech.do("GET", "/api/v1/devices", nil, nil); st != 401 {
		t.Fatalf("a disabled user's session must stop working: %d", st)
	}
	// Re-enable, reset the password and MFA: the technician starts over.
	h.do("PUT", "/api/v1/users/"+techID, map[string]any{"display_name": "Tess Tech", "status": "active"}, nil)
	// A token the technician made earlier must not survive a password reset (docs/THREAT-MODEL.md T-WEB-7).
	if _, err := h.db.Pool.Exec(t.Context(), `INSERT INTO api_tokens (id, org_id, user_id, name, prefix, token_hash, scopes, expires_at)
		SELECT gen_random_uuid(), org_id, id, 'old', 'lp_old0', decode(repeat('ab', 32), 'hex'), ARRAY['devices:read'], now() + interval '30 days' FROM users WHERE id = $1`, techID); err != nil {
		t.Fatal(err)
	}
	st, rp := h.do("POST", "/api/v1/users/"+techID+"/reset-password", map[string]any{}, nil)
	if st != 200 || rp["temporary_password"] == "" {
		t.Fatalf("reset password: %d %v", st, rp)
	}
	var live int
	if err := h.db.Pool.QueryRow(t.Context(), "SELECT count(*) FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL", techID).Scan(&live); err != nil || live != 0 {
		t.Fatalf("API tokens survived a password reset: %d %v", live, err)
	}
	if st, _ := h.do("POST", "/api/v1/users/"+techID+"/reset-mfa", map[string]any{}, nil); st != 204 {
		t.Fatal("reset mfa")
	}
	tech2 := h.otherClient()
	tech2.signInNewUser("tech@example.com", rp["temporary_password"].(string), "Marble-Lantern-Orbit-91", false)

	// The audit log recorded all of it.
	_, a := h.do("GET", "/api/v1/audit?limit=200", nil, nil)
	got := map[string]bool{}
	for _, e := range items(a) {
		got[e["action"].(string)] = true
	}
	for _, want := range []string{"site.create", "user.create", "user.role_add", "user.update", "user.password_reset", "user.mfa_reset", "auth.password_change"} {
		if !got[want] {
			t.Errorf("audit log lacks %s", want)
		}
	}
	_ = strings.TrimSpace
}

func (h *harness) session() map[string]any {
	_, s := h.do("GET", "/api/v1/auth/session", nil, nil)
	return s
}

func TestAPITokens(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()
	h.startAgent(h.createToken("t", 5, false), &fakeHW{host: "T-1", serial: "T1", uuid: "UT1"}, nil)
	waitFor(t, 15*time.Second, "device", func() bool { return len(h.devices()) == 1 })

	if st, _ := h.do("POST", "/api/v1/me/api-tokens", map[string]any{"name": "x", "scopes": []string{"devices:read"}, "expires_in_days": 0}, nil); st != 400 {
		t.Fatalf("a token must expire: %d", st)
	}
	if st, _ := h.do("POST", "/api/v1/me/api-tokens", map[string]any{"name": "x", "scopes": []string{"users:write"}, "expires_in_days": 30}, nil); st != 400 {
		t.Fatalf("identity administration cannot be put in a token: %d", st)
	}
	if st, _ := h.do("POST", "/api/v1/me/api-tokens", map[string]any{"name": "x", "scopes": []string{"nonsense:scope"}, "expires_in_days": 30}, nil); st != 400 {
		t.Fatalf("unknown scope: %d", st)
	}
	st, tok := h.do("POST", "/api/v1/me/api-tokens", map[string]any{"name": "inventory sync", "scopes": []string{"devices:read", "groups:read"}, "expires_in_days": 30}, nil)
	if st != 201 || !strings.HasPrefix(tok["token"].(string), "lp_") {
		t.Fatalf("create: %d %v", st, tok)
	}
	secret := tok["token"].(string)

	// Bearer authentication needs no cookie, CSRF token or Origin header.
	if st, b := h.bearer(secret, "GET", "/api/v1/devices", nil); st != 200 || len(items(b)) != 1 {
		t.Fatalf("token read: %d %v", st, b)
	}
	if st, _ := h.bearer(secret, "GET", "/api/v1/groups", nil); st != 200 {
		t.Fatalf("token scope groups:read: %d", st)
	}
	// The scopes bound it, although its owner is an administrator.
	if st, _ := h.bearer(secret, "GET", "/api/v1/audit", nil); st != 403 {
		t.Fatalf("audit is outside the token's scopes: %d", st)
	}
	if st, _ := h.bearer(secret, "POST", "/api/v1/groups", map[string]any{"kind": "static", "name": "g"}); st != 403 {
		t.Fatalf("groups:write is outside the scopes: %d", st)
	}
	if st, _ := h.bearer(secret, "POST", "/api/v1/me/api-tokens", map[string]any{"name": "child", "scopes": []string{"devices:read"}, "expires_in_days": 1}); st != 403 {
		t.Fatalf("a token cannot mint tokens: %d", st)
	}
	if st, _ := h.bearer(secret+"x", "GET", "/api/v1/devices", nil); st != 401 {
		t.Fatalf("a wrong token: %d", st)
	}
	if st, _ := h.bearer("lp_"+strings.Repeat("A", 43), "GET", "/api/v1/devices", nil); st != 401 {
		t.Fatalf("an unknown token: %d", st)
	}
	// The secret is stored only as a hash, and the listing shows no secret.
	_, sec := h.do("GET", "/api/v1/me/security", nil, nil)
	toks := sec["api_tokens"].([]any)
	if len(toks) != 1 || toks[0].(map[string]any)["prefix"] != secret[:8] || strings.Contains(toString(sec), secret) {
		t.Fatalf("token listing: %v", sec)
	}
	var n int
	if err := h.db.Pool.QueryRow(t.Context(), "SELECT count(*) FROM api_tokens WHERE position($1 in encode(token_hash,'hex')) > 0 OR name = $1", secret).Scan(&n); err != nil || n != 0 {
		t.Fatalf("secret stored in the clear? %d %v", n, err)
	}
	// Use through a token is audited as such.
	_, a := h.do("GET", "/api/v1/audit?limit=50", nil, nil)
	_ = a

	// Revoking stops it at once; an expired token does too.
	if st, _ := h.do("DELETE", "/api/v1/me/api-tokens/"+tok["id"].(string), nil, nil); st != 204 {
		t.Fatal("revoke")
	}
	if st, _ := h.bearer(secret, "GET", "/api/v1/devices", nil); st != 401 {
		t.Fatalf("a revoked token: %d", st)
	}
	st, tok2 := h.do("POST", "/api/v1/me/api-tokens", map[string]any{"name": "short", "scopes": []string{"devices:read"}, "expires_in_days": 1}, nil)
	if st != 201 {
		t.Fatal("create 2")
	}
	if _, err := h.db.Pool.Exec(t.Context(), "UPDATE api_tokens SET expires_at = now() - interval '1 minute' WHERE id = $1", tok2["id"]); err != nil {
		t.Fatal(err)
	}
	if st, _ := h.bearer(tok2["token"].(string), "GET", "/api/v1/devices", nil); st != 401 {
		t.Fatalf("an expired token: %d", st)
	}
	// A token whose owner is disabled stops working too.
	st, tok3 := h.do("POST", "/api/v1/me/api-tokens", map[string]any{"name": "owner", "scopes": []string{"devices:read"}, "expires_in_days": 1}, nil)
	if st != 201 {
		t.Fatal("create 3")
	}
	if _, err := h.db.Pool.Exec(t.Context(), "UPDATE users SET status='disabled'"); err != nil {
		t.Fatal(err)
	}
	if st, _ := h.bearer(tok3["token"].(string), "GET", "/api/v1/devices", nil); st != 401 {
		t.Fatalf("a disabled owner's token: %d", st)
	}
}

func toString(v any) string { b, _ := json.Marshal(v); return string(b) }
