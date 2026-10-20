package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/server/config"
	"github.com/auzring1/librepatch/internal/server/kek"
	"github.com/auzring1/librepatch/internal/server/settings"
	"github.com/auzring1/librepatch/internal/server/sso"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

type provider struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	issuer string
	claims jwt.MapClaims // what the next token says (sub, email, ... ; iss/aud/nonce/exp are added)
}

func newProvider(t *testing.T) *provider {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &provider{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/t/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(sso.Discovery{Issuer: p.issuer, AuthorizationEndpoint: p.issuer + "/authorize", TokenEndpoint: p.issuer + "/token", JWKSURI: p.issuer + "/keys"})
	})
	mux.HandleFunc("/t/v2.0/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "RSA", "kid": "k", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("/t/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		c := jwt.MapClaims{"iss": p.issuer, "aud": "client-1", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": r.PostForm.Get("code")}
		for k, v := range p.claims {
			c[k] = v
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
		tok.Header["kid"] = "k"
		s, _ := tok.SignedString(key)
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": s})
	})
	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)
	p.issuer = p.srv.URL + "/t/v2.0"
	return p
}

type ssoFx struct {
	t    *testing.T
	s    *server
	db   *pgtest.DB
	org  uuid.UUID
	boss uuid.UUID
	idp  *provider
	rev  int64
}

func newSSOFx(t *testing.T) *ssoFx {
	db := pgtest.New(t)
	ctx := t.Context()
	q := dbq.New(db.Pool)
	sealer, err := kek.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f := &ssoFx{t: t, db: db, org: uuid.New(), boss: uuid.New(), idp: newProvider(t)}
	pub, _ := url.Parse("https://lp.example.test")
	f.s = &server{Deps: Deps{Pool: db.Pool, Log: slog.New(slog.DiscardHandler), Cfg: &config.Config{PublicURL: pub},
		Sealer: sealer, Settings: &settings.Service{Pool: db.Pool, Sealer: sealer}, SSO: &sso.Provider{HTTP: f.idp.srv.Client()},
		Sessions: &auth.Sessions{Q: func(context.Context) *dbq.Queries { return q }, Secure: true}}, loginIP: auth.NewLimiter(1000, time.Minute, 1000)}
	for _, e := range []error{
		q.CreateOrganization(ctx, dbq.CreateOrganizationParams{ID: f.org, Name: "Contoso Health"}),
		q.CreateUser(ctx, dbq.CreateUserParams{ID: f.boss, OrgID: f.org, Email: "boss@example.test", DisplayName: "Boss", PasswordHash: "x"}),
		q.CreateRoleBinding(ctx, dbq.CreateRoleBindingParams{ID: uuid.New(), UserID: f.boss, Role: auth.RoleAdmin, ScopeType: auth.ScopeOrg, ScopeID: f.org}),
	} {
		if e != nil {
			t.Fatal(e)
		}
	}
	f.configure(map[string]any{})
	return f
}

// configure saves the single sign-on settings (on top of working defaults).
func (f *ssoFx) configure(over map[string]any) {
	f.t.Helper()
	in := map[string]any{"enabled": true, "label": "Microsoft", "issuer": f.idp.issuer, "client_id": "client-1", "client_secret": "s3cret", "role_claim": "roles",
		"role_map":    []any{map[string]any{"value": "LP.Admin", "role": "admin"}, map[string]any{"value": "LP.Operator", "role": "operator"}, map[string]any{"value": "LP.Read", "role": "readonly"}},
		"auto_create": true, "link_by_email": false, "allowed_domains": []any{}, "idp_mfa_counts": false}
	for k, v := range over {
		in[k] = v
	}
	doc, err := f.s.Settings.Get(context.Background(), f.org, "sso")
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.s.Settings.Put(context.Background(), settings.Actor{Org: f.org, User: f.boss}, "sso", doc.Revision, in); err != nil {
		f.t.Fatalf("settings: %v", err)
	}
}

// signIn runs start and callback; the provider will say claims. It returns the callback response.
func (f *ssoFx) signIn(claims jwt.MapClaims) *httptest.ResponseRecorder {
	f.t.Helper()
	f.idp.claims = claims
	w := httptest.NewRecorder()
	f.s.ssoStart(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/start", nil))
	if w.Code != http.StatusFound {
		f.t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	q := loc.Query()
	// The fake token endpoint puts the code in the nonce claim, so make the code equal to the nonce of this sign-in.
	cb := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/callback?code="+url.QueryEscape(q.Get("nonce"))+"&state="+url.QueryEscape(q.Get("state")), nil)
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c) // the browser that began the sign-in comes back with its cookie
	}
	f.s.ssoCallback(cb, req)
	return cb
}

func (f *ssoFx) user(email string) (dbq.User, bool) {
	u, err := dbq.New(f.db.Pool).GetUserByEmail(context.Background(), email)
	return u, err == nil
}

func (f *ssoFx) roles(u uuid.UUID) map[string]string {
	rows, _ := f.db.Pool.Query(context.Background(), "SELECT role, source FROM role_bindings WHERE user_id = $1", u)
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var r, s string
		_ = rows.Scan(&r, &s)
		out[r] = s
	}
	return out
}

func where(w *httptest.ResponseRecorder) string { return w.Header().Get("Refresh") }

func TestSignInCreatesTheAccountWithTheMappedRoleAndAsksForTheSecondFactor(t *testing.T) {
	f := newSSOFx(t)
	w := f.signIn(jwt.MapClaims{"sub": "oid-1", "email": "Ann@Example.test", "name": "Ann Example", "roles": []string{"LP.Operator", "Unrelated"}})
	if !strings.Contains(where(w), "/login?sso=continue") {
		t.Fatalf("%q", where(w))
	}
	u, ok := f.user("ann@example.test")
	if !ok || u.DisplayName != "Ann Example" || u.PasswordHash != unusablePassword || u.OrgID != f.org {
		t.Fatalf("%v %+v", ok, u)
	}
	if r := f.roles(u.ID); len(r) != 1 || r["operator"] != "sso" {
		t.Fatalf("%v", r)
	}
	// The cookie is a session that still needs the second factor, and a password sign-in is impossible.
	if !strings.Contains(strings.Join(w.Header().Values("Set-Cookie"), ";"), "HttpOnly") {
		t.Fatal("no session cookie")
	}
	var mfa *time.Time
	_ = f.db.Pool.QueryRow(context.Background(), "SELECT mfa_verified_at FROM sessions WHERE user_id = $1", u.ID).Scan(&mfa)
	if mfa != nil {
		t.Fatal("the session is already past the second factor")
	}
	if auth.VerifyPassword("", u.PasswordHash) || auth.VerifyPassword(unusablePassword, u.PasswordHash) {
		t.Fatal("a password matched the unusable hash")
	}
	// The continue step answers like a password sign-in does: this person has no factor yet, so one is offered for enrolment.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/continue", nil)
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}
	sess, err := f.s.Sessions.Lookup(context.Background(), f.s.Sessions.TokenFromRequest(req))
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.WithValue(req.Context(), ctxSession, sess))
	cw := httptest.NewRecorder()
	f.s.ssoContinue(cw, req)
	if cw.Code != 200 || !strings.Contains(cw.Body.String(), `"mfa":"enroll"`) {
		t.Fatalf("%d %s", cw.Code, cw.Body.String())
	}
}

func TestTheProvidersMultiFactorProofSkipsTheLocalStepOnlyWhenTheSettingIsOn(t *testing.T) {
	f := newSSOFx(t)
	claims := func() jwt.MapClaims {
		return jwt.MapClaims{"sub": "oid-2", "email": "bo@example.test", "roles": []string{"LP.Read"}, "amr": []string{"pwd", "mfa"}}
	}
	if w := f.signIn(claims()); !strings.Contains(where(w), "sso=continue") {
		t.Fatalf("setting off: %q", where(w))
	}
	f.configure(map[string]any{"idp_mfa_counts": true})
	if w := f.signIn(claims()); !strings.HasSuffix(strings.Split(where(w), "url=")[1], "/") {
		t.Fatalf("setting on, provider says mfa: %q", where(w))
	}
	noMFA := claims()
	noMFA["amr"] = []string{"pwd"}
	if w := f.signIn(noMFA); !strings.Contains(where(w), "sso=continue") {
		t.Fatalf("setting on, provider does not say mfa: %q", where(w))
	}
}

func TestRolesFollowTheProviderAtEverySignInButHandSetRolesAreKept(t *testing.T) {
	f := newSSOFx(t)
	u0 := func() dbq.User { u, _ := f.user("cy@example.test"); return u }
	f.signIn(jwt.MapClaims{"sub": "oid-3", "email": "cy@example.test", "roles": []string{"LP.Read"}})
	if r := f.roles(u0().ID); r["readonly"] != "sso" || len(r) != 1 {
		t.Fatalf("%v", r)
	}
	// Promoted at the provider; an administrator also gave a role by hand.
	if _, err := f.db.Pool.Exec(context.Background(), "INSERT INTO role_bindings (id, user_id, role, scope_type, scope_id) VALUES ($1,$2,'operator','org',$3)", uuid.New(), u0().ID, f.org); err != nil {
		t.Fatal(err)
	}
	f.signIn(jwt.MapClaims{"sub": "oid-3", "email": "cy@example.test", "roles": []string{"LP.Read", "LP.Admin"}})
	if r := f.roles(u0().ID); r["admin"] != "sso" || r["operator"] != "local" || len(r) != 2 {
		t.Fatalf("the provider's role replaces its earlier role only: %v", r)
	}
	// Removed at the provider: the provider's binding goes, the hand-set one stays, and the person can still sign in through it.
	if w := f.signIn(jwt.MapClaims{"sub": "oid-3", "email": "cy@example.test", "roles": []string{}}); !strings.Contains(where(w), "sso=continue") {
		t.Fatalf("%q", where(w))
	}
	if r := f.roles(u0().ID); len(r) != 1 || r["operator"] != "local" {
		t.Fatalf("%v", r)
	}
	// Nothing at all left: turned away.
	if _, err := f.db.Pool.Exec(context.Background(), "DELETE FROM role_bindings WHERE user_id = $1", u0().ID); err != nil {
		t.Fatal(err)
	}
	if w := f.signIn(jwt.MapClaims{"sub": "oid-3", "email": "cy@example.test", "roles": []string{}}); !strings.Contains(where(w), "sso_error=no_access") {
		t.Fatalf("%q", where(w))
	}
}

func TestPeopleWithoutAMappedRoleOrOutsideTheDomainsAreTurnedAway(t *testing.T) {
	f := newSSOFx(t)
	if w := f.signIn(jwt.MapClaims{"sub": "oid-4", "email": "dee@example.test", "roles": []string{"Unmapped"}}); !strings.Contains(where(w), "sso_error=no_access") {
		t.Fatalf("%q", where(w))
	}
	if _, ok := f.user("dee@example.test"); ok {
		t.Fatal("an account was created for somebody without a role")
	}
	f.configure(map[string]any{"allowed_domains": []any{"corp.example.test"}})
	if w := f.signIn(jwt.MapClaims{"sub": "oid-5", "email": "eve@example.test", "roles": []string{"LP.Admin"}}); !strings.Contains(where(w), "sso_error=no_access") {
		t.Fatalf("a domain outside the list: %q", where(w))
	}
	f.configure(map[string]any{"allowed_domains": []any{}, "auto_create": false})
	if w := f.signIn(jwt.MapClaims{"sub": "oid-6", "email": "fay@example.test", "roles": []string{"LP.Admin"}}); !strings.Contains(where(w), "sso_error=no_access") {
		t.Fatalf("creation off: %q", where(w))
	}
}

func TestAnExistingLocalAccountIsNotTakenOverByEmail(t *testing.T) {
	f := newSSOFx(t)
	claims := jwt.MapClaims{"sub": "oid-7", "email": "boss@example.test", "roles": []string{"LP.Admin"}}
	if w := f.signIn(claims); !strings.Contains(where(w), "sso_error=account_exists") {
		t.Fatalf("link off: %q", where(w))
	}
	if n := f.countIdentities(f.boss); n != 0 {
		t.Fatalf("an identity was linked: %d", n)
	}
	f.configure(map[string]any{"link_by_email": true})
	if w := f.signIn(claims); !strings.Contains(where(w), "sso=continue") {
		t.Fatalf("link on: %q", where(w))
	}
	if n := f.countIdentities(f.boss); n != 1 {
		t.Fatalf("%d", n)
	}
	// The account is tied to that provider identity now: another subject with the same email address is refused.
	claims["sub"] = "oid-attacker"
	if w := f.signIn(claims); !strings.Contains(where(w), "sso_error=account_exists") {
		t.Fatalf("a second identity for the same account: %q", where(w))
	}
}

func (f *ssoFx) countIdentities(u uuid.UUID) (n int) {
	_ = f.db.Pool.QueryRow(context.Background(), "SELECT count(*) FROM user_identities WHERE user_id = $1 AND provider = 'oidc'", u).Scan(&n)
	return
}

func TestTheProviderCannotDemoteTheLastAdministratorAndDisabledPeopleAreRefused(t *testing.T) {
	f := newSSOFx(t)
	// The only administrator is a provider-managed one.
	f.signIn(jwt.MapClaims{"sub": "oid-8", "email": "gus@example.test", "roles": []string{"LP.Admin"}})
	gus, _ := f.user("gus@example.test")
	if _, err := f.db.Pool.Exec(context.Background(), "DELETE FROM role_bindings WHERE user_id = $1", f.boss); err != nil {
		t.Fatal(err)
	}
	f.signIn(jwt.MapClaims{"sub": "oid-8", "email": "gus@example.test", "roles": []string{"LP.Read"}})
	if r := f.roles(gus.ID); r["admin"] != "sso" {
		t.Fatalf("the last administrator was demoted by the provider: %v", r)
	}
	var n int
	_ = f.db.Pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_log WHERE action = 'sso.keep_last_admin'").Scan(&n)
	if n != 1 {
		t.Fatalf("the refusal must be audited: %d", n)
	}
	if _, err := f.db.Pool.Exec(context.Background(), "UPDATE users SET status = 'disabled' WHERE id = $1", gus.ID); err != nil {
		t.Fatal(err)
	}
	if w := f.signIn(jwt.MapClaims{"sub": "oid-8", "email": "gus@example.test", "roles": []string{"LP.Admin"}}); !strings.Contains(where(w), "sso_error=disabled") {
		t.Fatalf("%q", where(w))
	}
}

func TestSignInFailuresAreSpecificInTheAuditLogAndGeneralOnScreen(t *testing.T) {
	f := newSSOFx(t)
	ctx := context.Background()
	// Unknown or reused state.
	w := httptest.NewRecorder()
	f.s.ssoCallback(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/callback?code=x&state=never-issued", nil))
	if !strings.Contains(where(w), "sso_error=expired") {
		t.Fatalf("%q", where(w))
	}
	// The provider says no.
	w = httptest.NewRecorder()
	f.s.ssoCallback(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/callback?error=access_denied&error_description=secret+detail", nil))
	if !strings.Contains(where(w), "sso_error=denied") || strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("%q", where(w))
	}
	// A state can be used once, and only by the browser that began the sign-in.
	f.idp.claims = jwt.MapClaims{"sub": "oid-9", "email": "hal@example.test", "roles": []string{"LP.Read"}}
	start := func() (path string, cookies []*http.Cookie) {
		sw := httptest.NewRecorder()
		f.s.ssoStart(sw, httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/start", nil))
		loc, _ := url.Parse(sw.Header().Get("Location"))
		return "/api/v1/auth/sso/callback?code=" + url.QueryEscape(loc.Query().Get("nonce")) + "&state=" + url.QueryEscape(loc.Query().Get("state")), sw.Result().Cookies()
	}
	call := func(path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		f.s.ssoCallback(w, req)
		return w
	}
	path, cookies := start()
	if w := call(path, nil); !strings.Contains(where(w), "sso_error=expired") {
		t.Fatalf("login CSRF: a callback from a browser without the cookie was accepted: %q", where(w))
	}
	if _, ok := f.user("hal@example.test"); ok {
		t.Fatal("an account was created for a callback that did not come from the browser that began the sign-in")
	}
	path, cookies = start()
	for i, want := range []string{"sso=continue", "sso_error=expired"} {
		if w := call(path, cookies); !strings.Contains(where(w), want) {
			t.Fatalf("use %d: %q", i, where(w))
		}
	}
	var denied int
	_ = f.db.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE action = 'auth.login' AND outcome = 'denied' AND details->>'method' = 'sso'").Scan(&denied)
	if denied < 4 {
		t.Fatalf("denied sign-ins must be audited with a reason: %d", denied)
	}
	// Single sign-on switched off: nothing starts.
	f.configure(map[string]any{"enabled": false})
	sw := httptest.NewRecorder()
	f.s.ssoStart(sw, httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/start", nil))
	if sw.Code != 200 || !strings.Contains(where(sw), "sso_error=unavailable") {
		t.Fatalf("%d %q", sw.Code, where(sw))
	}
	iw := httptest.NewRecorder()
	f.s.ssoInfo(iw, httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/info", nil))
	if !strings.Contains(iw.Body.String(), `"enabled":false`) || !strings.Contains(iw.Body.String(), "https://lp.example.test/api/v1/auth/sso/callback") {
		t.Fatal(iw.Body.String())
	}
}
