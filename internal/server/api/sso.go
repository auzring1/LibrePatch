package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"html"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/server/settings"
	"github.com/auzring1/librepatch/internal/server/sso"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/shared/ptr"
)

// Single sign-on with OpenID Connect (D128).

const (
	ssoProvider = "oidc"
	ssoCookie   = "lp_sso_flow"
	// unusablePassword is stored for accounts that sign in only through the provider: it is not a hash, so no password matches.
	unusablePassword = "!single-sign-on"
)

var roleRank = map[string]int{auth.RoleReadOnly: 1, auth.RoleOperator: 2, auth.RoleAdmin: 3}

type ssoSettings struct {
	cfg       sso.Config
	org       uuid.UUID
	label     string
	roleClaim string
	roleMap   []settings.V
	autoMake  bool
	linkMail  bool
	domains   []string
	idpMFA    bool
}

// ssoConfig reads the settings. ok is false unless single sign-on is switched on and complete.
func (s *server) ssoConfig(ctx context.Context) (c ssoSettings, ok bool) {
	if s.Settings == nil || s.SSO == nil {
		return c, false
	}
	org, err := s.Settings.Org(ctx)
	if err != nil {
		return c, false
	}
	v := s.Settings.Peek(ctx, org, "sso")
	if !v.Bool("enabled") {
		return c, false
	}
	secret, err := s.Settings.Secret(ctx, org, "sso", "client_secret")
	if err != nil || secret == "" || v.Str("issuer") == "" || v.Str("client_id") == "" {
		return c, false
	}
	c = ssoSettings{org: org, label: v.Str("label"), roleClaim: v.Str("role_claim"), roleMap: v.Items("role_map"), autoMake: v.Bool("auto_create"),
		linkMail: v.Bool("link_by_email"), domains: v.Strings("allowed_domains"), idpMFA: v.Bool("idp_mfa_counts"),
		cfg: sso.Config{Issuer: v.Str("issuer"), ClientID: v.Str("client_id"), ClientSecret: secret, RedirectURI: s.Cfg.Origin() + "/api/v1/auth/sso/callback"}}
	if c.label == "" {
		c.label = "single sign-on"
	}
	return c, true
}

// GET /auth/sso/info: whether the sign-in page offers the button, and the address to register at the provider.
func (s *server) ssoInfo(w http.ResponseWriter, r *http.Request) {
	c, ok := s.ssoConfig(r.Context())
	redirect := s.Cfg.Origin() + "/api/v1/auth/sso/callback"
	w.Header().Set("Cache-Control", "no-store")
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "label": "", "redirect_uri": redirect})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "label": c.label, "redirect_uri": redirect})
}

// finishSSO sends the browser on with a page rather than a redirect: the session cookie is SameSite=Strict, and a redirect
// that follows a cross-site navigation (the provider sending the person back) would not carry it.
func finishSSO(w http.ResponseWriter, to string) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Refresh", "0; url="+to)
	h.Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=` + html.EscapeString(to) + `"><title>Signing in</title><p>Signing in…</p>`))
}

func ssoFail(w http.ResponseWriter, code string) {
	finishSSO(w, "/login?sso_error="+url.QueryEscape(code))
}

// GET /auth/sso/start
func (s *server) ssoStart(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.loginIP.Allow(ip) {
		w.Header().Set("Retry-After", "60")
		ssoFail(w, "rate_limited")
		return
	}
	c, ok := s.ssoConfig(r.Context())
	if !ok {
		ssoFail(w, "unavailable")
		return
	}
	d, err := s.SSO.Discover(r.Context(), c.cfg.Issuer)
	if err != nil {
		s.Log.Warn("single sign-on: discovery failed", "err", err)
		ssoFail(w, "unavailable")
		return
	}
	state, err1 := sso.RandomToken()
	nonce, err2 := sso.RandomToken()
	verifier, challenge, err3 := sso.NewPKCE()
	if err := errors.Join(err1, err2, err3); err != nil {
		internalError(w)
		return
	}
	q := s.q()
	_ = q.PruneSSOFlows(r.Context(), s.now().Add(-sso.FlowLifetime))
	binding, err := sso.RandomToken()
	if err != nil {
		internalError(w)
		return
	}
	if err := q.InsertSSOFlow(r.Context(), dbq.InsertSSOFlowParams{StateHash: sso.HashState(state), Nonce: nonce, Verifier: verifier, BindingHash: sso.HashState(binding)}); err != nil {
		internalError(w)
		return
	}
	// The sign-in is tied to this browser: a callback address given to somebody else (login CSRF) carries a state this
	// browser has no cookie for. Lax, because the provider sends the browser back with a top-level GET.
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: binding, Path: "/api/v1/auth/sso", HttpOnly: true, Secure: s.Sessions.Secure, SameSite: http.SameSiteLaxMode, MaxAge: int(sso.FlowLifetime.Seconds())}) // #nosec G124 -- Secure follows the session cookie
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, sso.AuthURL(d, c.cfg, state, nonce, challenge), http.StatusFound)
}

func (s *server) ssoDenied(r *http.Request, reason string, details map[string]any) {
	if details == nil {
		details = map[string]any{}
	}
	details["reason"], details["method"] = reason, "sso"
	_ = audit.Log(r.Context(), s.Pool, audit.Entry{ActorType: audit.ActorAnonymous, ActorIP: clientIP(r), Action: "auth.login", Outcome: audit.Denied, Details: details})
}

// GET /auth/sso/callback
func (s *server) ssoCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.loginIP.Allow(clientIP(r)) {
		ssoFail(w, "rate_limited")
		return
	}
	c, ok := s.ssoConfig(ctx)
	if !ok {
		ssoFail(w, "unavailable")
		return
	}
	qs := r.URL.Query()
	if e := qs.Get("error"); e != "" {
		s.ssoDenied(r, "provider_refused", map[string]any{"error": truncStr(e, 60)})
		ssoFail(w, "denied")
		return
	}
	state, code := qs.Get("state"), qs.Get("code")
	if state == "" || code == "" || len(state) > 200 || len(code) > 4096 {
		ssoFail(w, "failed")
		return
	}
	q := s.q()
	flow, err := q.TakeSSOFlow(ctx, dbq.TakeSSOFlowParams{StateHash: sso.HashState(state), CreatedAt: s.now().Add(-sso.FlowLifetime)})
	bc, cerr := r.Cookie(ssoCookie)
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: "", Path: "/api/v1/auth/sso", HttpOnly: true, Secure: s.Sessions.Secure, SameSite: http.SameSiteLaxMode, MaxAge: -1}) // #nosec G124 -- deletion
	if err == nil && (cerr != nil || subtle.ConstantTimeCompare(sso.HashState(bc.Value), flow.BindingHash) != 1) {
		s.ssoDenied(r, "state_not_from_this_browser", nil)
		ssoFail(w, "expired")
		return
	}
	if err != nil {
		s.ssoDenied(r, "unknown_or_expired_state", nil)
		ssoFail(w, "expired")
		return
	}
	d, err := s.SSO.Discover(ctx, c.cfg.Issuer)
	if err != nil {
		s.Log.Warn("single sign-on: discovery failed", "err", err)
		ssoFail(w, "unavailable")
		return
	}
	raw, err := s.SSO.Exchange(ctx, d, c.cfg, code, flow.Verifier)
	if err != nil {
		s.Log.Warn("single sign-on: code exchange failed", "err", err)
		s.ssoDenied(r, "code_exchange_failed", nil)
		ssoFail(w, "failed")
		return
	}
	claims, err := s.SSO.Verify(ctx, d, c.cfg, raw, flow.Nonce)
	if err != nil {
		s.Log.Warn("single sign-on: token rejected", "err", err)
		s.ssoDenied(r, "token_rejected", nil)
		ssoFail(w, "failed")
		return
	}
	u, reason, err := s.ssoUser(r, c, claims)
	if err != nil {
		s.Log.Error("single sign-on: account", "err", err)
		internalError(w)
		return
	}
	if reason != "" {
		s.ssoDenied(r, reason, map[string]any{"email": truncStr(ssoEmail(claims), 120)})
		ssoFail(w, reason)
		return
	}
	// Signed in with the provider. Whether a second step follows depends on the setting and on what the provider says.
	idpMFA := c.idpMFA && slices.Contains(claims.Strings("amr"), "mfa")
	if prev := sessionFrom(r); prev != nil {
		_ = q.DeleteSession(ctx, prev.IDHash)
	}
	sess, err := s.Sessions.Create(ctx, q, u.ID, idpMFA, clientIP(r), r.UserAgent())
	if err != nil {
		internalError(w)
		return
	}
	s.Sessions.SetCookie(w, sess)
	details := map[string]any{"method": "sso", "mfa_method": "provider"}
	if !idpMFA {
		details["mfa_method"] = "pending_local"
	} else if err := q.SetUserLoginSuccess(ctx, dbq.SetUserLoginSuccessParams{ID: u.ID, LastLoginAt: ptr.Of(s.now())}); err != nil {
		s.Log.Error("single sign-on: record login", "err", err)
	}
	_ = audit.Log(ctx, s.Pool, audit.Entry{OrgID: &u.OrgID, ActorType: audit.ActorUser, ActorID: u.ID.String(), ActorIP: clientIP(r), Action: "auth.sso", Outcome: audit.Success, Details: details})
	if idpMFA {
		finishSSO(w, "/")
		return
	}
	finishSSO(w, "/login?sso=continue")
}

// GET /auth/sso/continue: what comes after the provider for a person who still has to confirm with a second factor here.
func (s *server) ssoContinue(w http.ResponseWriter, r *http.Request) {
	sess, u, ok := s.pendingSession(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.mfaChallenge(w, r, sess, u)
}

func truncStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ssoEmail is the address in the token: email, else a user name that looks like one.
func ssoEmail(c sso.Claims) string {
	for _, k := range []string{"email", "preferred_username", "upn"} {
		if v := strings.ToLower(strings.TrimSpace(c.Str(k))); strings.Contains(v, "@") {
			return v
		}
	}
	return ""
}

// ssoRole is the highest role the provider's claim gives, "" if none.
func ssoRole(c ssoSettings, claims sso.Claims) string {
	have := claims.Strings(c.roleClaim)
	best := ""
	for _, m := range c.roleMap {
		val, role := m.Str("value"), m.Str("role")
		if val == "" || roleRank[role] == 0 {
			continue
		}
		for _, h := range have {
			if strings.EqualFold(h, val) && roleRank[role] > roleRank[best] {
				best = role
			}
		}
	}
	return best
}

func domainAllowed(domains []string, email string) bool {
	if len(domains) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	return slices.ContainsFunc(domains, func(d string) bool {
		return strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(d), "@"), email[at+1:])
	})
}

// ssoUser finds or creates the account for a verified token and brings its roles in line with the provider. A non-empty
// reason means the person is turned away (the console shows a general message; the audit log has the reason).
func (s *server) ssoUser(r *http.Request, c ssoSettings, claims sso.Claims) (u dbq.User, reason string, err error) {
	ctx := r.Context()
	subject := c.cfg.Issuer + "|" + claims.Str("sub")
	if len(subject) > 500 {
		return u, "failed", nil
	}
	email := ssoEmail(claims)
	role := ssoRole(c, claims)
	if email != "" && !domainAllowed(c.domains, email) {
		return u, "no_access", nil
	}
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		found, err := q.GetUserByIdentity(ctx, dbq.GetUserByIdentityParams{Provider: ssoProvider, Subject: subject})
		switch {
		case err == nil:
			u = found
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		default:
			// First sign-in with this provider identity.
			if email == "" {
				reason = "no_access"
				return nil
			}
			existing, err := q.GetUserByEmail(ctx, email)
			switch {
			case err == nil:
				if !c.linkMail {
					reason = "account_exists"
					return nil
				}
				if has, err := q.UserHasIdentity(ctx, dbq.UserHasIdentityParams{UserID: existing.ID, Provider: ssoProvider}); err != nil {
					return err
				} else if has {
					reason = "account_exists" // that account is already linked to another provider identity
					return nil
				}
				u = existing
			case errors.Is(err, pgx.ErrNoRows):
				if !c.autoMake || role == "" {
					reason = "no_access"
					return nil
				}
				name := strings.TrimSpace(claims.Str("name"))
				if name == "" {
					name = email
				}
				u = dbq.User{ID: uuid.New(), OrgID: c.org, Email: email, DisplayName: truncStr(name, 200), Status: "active"}
				if err := q.CreateUser(ctx, dbq.CreateUserParams{ID: u.ID, OrgID: c.org, Email: email, DisplayName: u.DisplayName, PasswordHash: unusablePassword}); err != nil {
					return err
				}
				if _, err := audit.Write(ctx, tx, audit.Entry{OrgID: &c.org, ActorType: audit.ActorSystem, ActorID: "sso", ActorIP: clientIP(r), Action: "user.create", TargetType: "user",
					TargetIDs: []string{u.ID.String()}, Outcome: audit.Success, Details: map[string]any{"email": email, "via": "single sign-on", "role": role}}, s.now()); err != nil {
					return err
				}
			default:
				return err
			}
			if err := q.CreateUserIdentity(ctx, dbq.CreateUserIdentityParams{ID: uuid.New(), UserID: u.ID, Provider: ssoProvider, Subject: subject}); err != nil {
				return err
			}
		}
		if u.Status != "active" {
			reason = "disabled"
			return nil
		}
		if u.OrgID != c.org {
			reason = "no_access"
			return nil
		}
		return s.syncSSORoles(ctx, tx, q, r, u, role)
	})
	if err != nil || reason != "" {
		return u, reason, err
	}
	// Somebody with no role at all is let in nowhere: not by the provider's list, not by anything set by hand.
	bs, err := dbq.New(s.Pool).ListRoleBindingsForUser(ctx, u.ID)
	if err != nil {
		return u, "", err
	}
	if !slices.ContainsFunc(bs, func(b dbq.RoleBinding) bool { return b.ScopeType == auth.ScopeOrg || b.ScopeType == auth.ScopeSite }) {
		return u, "no_access", nil
	}
	return u, "", nil
}

// syncSSORoles makes the provider-managed bindings of a person equal to the role the provider gives. Bindings set by hand
// are never touched, and the last administrator is never demoted by the provider.
func (s *server) syncSSORoles(ctx context.Context, tx pgx.Tx, q *dbq.Queries, r *http.Request, u dbq.User, want string) error {
	have, err := q.ListSSOBindings(ctx, u.ID)
	if err != nil {
		return err
	}
	added, removed := "", []string{}
	hasWanted := false
	for _, b := range have {
		if b.Role == want && b.ScopeType == auth.ScopeOrg {
			hasWanted = true
			continue
		}
		if b.Role == auth.RoleAdmin && b.ScopeType == auth.ScopeOrg {
			if n, err := q.CountOtherActiveOrgAdmins(ctx, dbq.CountOtherActiveOrgAdminsParams{OrgID: u.OrgID, ID: u.ID}); err != nil {
				return err
			} else if n == 0 {
				_, _ = audit.Write(ctx, tx, audit.Entry{OrgID: &u.OrgID, ActorType: audit.ActorSystem, ActorID: "sso", ActorIP: clientIP(r), Action: "sso.keep_last_admin", TargetType: "user",
					TargetIDs: []string{u.ID.String()}, Outcome: audit.Denied, Details: map[string]any{"reason": "the provider no longer gives this person the administrator role, but they are the last administrator"}}, s.now())
				return nil
			}
		}
		if _, err := q.DeleteSSOBinding(ctx, dbq.DeleteSSOBindingParams{ID: b.ID, UserID: u.ID}); err != nil {
			return err
		}
		removed = append(removed, b.Role)
	}
	if want != "" && !hasWanted {
		if err := q.CreateSSOBinding(ctx, dbq.CreateSSOBindingParams{ID: uuid.New(), UserID: u.ID, Role: want, ScopeID: u.OrgID}); err != nil {
			return err
		}
		added = want
	}
	if added != "" || len(removed) > 0 {
		if _, err := audit.Write(ctx, tx, audit.Entry{OrgID: &u.OrgID, ActorType: audit.ActorSystem, ActorID: "sso", ActorIP: clientIP(r), Action: "sso.roles_synced", TargetType: "user",
			TargetIDs: []string{u.ID.String()}, Outcome: audit.Success, Details: map[string]any{"added": added, "removed": removed}}, s.now()); err != nil {
			return err
		}
	}
	return nil
}
