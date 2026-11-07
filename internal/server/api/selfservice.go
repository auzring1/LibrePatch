package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/shared/ptr"
)

// ---- password ----

// changePassword: POST /auth/change-password. It works on a password-verified session that must
// choose a new password (before MFA) and on a full session (settings). The current password is
// always required.
func (s *server) changePassword(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "Sign in first.")
		return
	}
	var req struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !decode(w, r, &req) {
		return
	}
	u, err := s.q().GetUserByID(r.Context(), sess.UserID)
	if err != nil || u.Status != "active" {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "Sign in first.")
		return
	}
	if !s.loginEmail.Allow("pw:" + u.ID.String()) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many attempts. Wait a minute and try again.")
		return
	}
	if len(req.Current) > 4*auth.MaxPasswordLen || !auth.VerifyPassword(req.Current, u.PasswordHash) {
		writeError(w, http.StatusUnauthorized, "bad_password", "The current password is not right.")
		return
	}
	if req.New == req.Current {
		badRequest(w, "Choose a password you have not used just now.")
		return
	}
	if err := auth.ValidatePasswordMin(req.New, u.Email, s.secSettings(r.Context(), u.OrgID).Int("password_min_length")); err != nil {
		badRequest(w, err.Error())
		return
	}
	hash, err := auth.HashPassword(req.New)
	if err != nil {
		internalError(w)
		return
	}
	if err := s.q().SetUserPassword(r.Context(), dbq.SetUserPasswordParams{ID: u.ID, PasswordHash: hash, MustChangePassword: false, PasswordChangedAt: s.now()}); err != nil {
		internalError(w)
		return
	}
	_ = s.q().DeleteOtherSessionsForUser(r.Context(), dbq.DeleteOtherSessionsForUserParams{UserID: u.ID, IDHash: sess.IDHash})
	// A password change is what people do when they suspect a compromise: tokens made before it go too.
	_ = s.q().RevokeAPITokensForUser(r.Context(), dbq.RevokeAPITokensForUserParams{UserID: u.ID, RevokedAt: ptr.Of(s.now())})
	_ = audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &u.OrgID, ActorType: audit.ActorUser, ActorID: u.ID.String(), ActorIP: clientIP(r), Action: "auth.password_change",
		TargetType: "user", TargetIDs: []string{u.ID.String()}, Outcome: audit.Success})
	u.MustChangePassword = false
	if sess.MFAVerified {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.mfaChallenge(w, r, sess, &u)
}

// ---- security overview ----

type keyView struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

type apiTokenView struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	LastUsedIP string     `json:"last_used_ip"`
	RevokedAt  *time.Time `json:"revoked_at"`
	Owner      string     `json:"owner,omitempty"`
}

func (s *server) mySecurity(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	ctx := r.Context()
	_, totpErr := s.q().GetTOTP(ctx, p.UserID)
	creds, err := s.q().ListWebAuthnCredentials(ctx, p.UserID)
	if err != nil {
		internalError(w)
		return
	}
	toks, err := s.q().ListAPITokensForUser(ctx, p.UserID)
	if err != nil {
		internalError(w)
		return
	}
	keys := make([]keyView, 0, len(creds))
	for _, c := range creds {
		keys = append(keys, keyView{ID: c.ID, Name: c.Name, CreatedAt: c.CreatedAt, LastUsedAt: c.LastUsedAt})
	}
	tv := make([]apiTokenView, 0, len(toks))
	for _, t := range toks {
		tv = append(tv, apiTokenView{ID: t.ID, Name: t.Name, Prefix: t.Prefix, Scopes: t.Scopes, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
			LastUsedAt: t.LastUsedAt, LastUsedIP: t.LastUsedIp, RevokedAt: t.RevokedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"totp": totpErr == nil, "security_keys": keys, "api_tokens": tv,
		"webauthn_available": s.webauthn != nil, "token_scopes": s.tokenScopesFor(p)})
}

// tokenScopesFor lists the permissions the caller could put in a token.
func (s *server) tokenScopesFor(p *Principal) []string {
	var out []string
	for _, perm := range auth.AllPermissions() {
		if auth.TokenScopable(perm) && p.Access.HasAnywhere(perm) {
			out = append(out, perm)
		}
	}
	return out
}

// ---- API tokens ----

const (
	maxTokensPerUser = 20
	maxTokenDays     = 365
)

func (s *server) createAPIToken(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	if p.TokenID != "" {
		writeError(w, http.StatusForbidden, "forbidden", "An API token cannot create other tokens.")
		return
	}
	var req struct {
		Name        string   `json:"name"`
		Scopes      []string `json:"scopes"`
		ExpiresDays int      `json:"expires_in_days"`
	}
	if !decode(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if n := utf8.RuneCountInString(name); n < 1 || n > 100 {
		badRequest(w, "Give the token a name (1 to 100 characters).")
		return
	}
	maxDays := maxTokenDays
	if v := s.secSettings(r.Context(), principalFrom(r).OrgID).Int("api_token_max_days"); v > 0 && v < maxDays {
		maxDays = v
	}
	if req.ExpiresDays < 1 || req.ExpiresDays > maxDays {
		badRequest(w, "A token must expire within 1 to "+strconv.Itoa(maxDays)+" days.")
		return
	}
	if len(req.Scopes) == 0 || len(req.Scopes) > 64 {
		badRequest(w, "Choose at least one scope.")
		return
	}
	scopes := slices.Clone(req.Scopes)
	slices.Sort(scopes)
	scopes = slices.Compact(scopes)
	for _, sc := range scopes {
		if !slices.Contains(auth.AllPermissions(), sc) || !auth.TokenScopable(sc) {
			badRequest(w, "Unknown or not allowed scope: "+sc)
			return
		}
		if !p.Access.HasAnywhere(sc) {
			writeError(w, http.StatusForbidden, "forbidden", "You cannot grant a scope you do not have yourself: "+sc)
			return
		}
	}
	if n, _ := s.q().CountActiveAPITokensForUser(r.Context(), p.UserID); n >= maxTokensPerUser {
		writeError(w, http.StatusConflict, "too_many_tokens", "You already have the maximum number of active tokens. Revoke one first.")
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		internalError(w)
		return
	}
	secret := apiTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(secret))
	id := uuid.New()
	now := s.now()
	exp := now.Add(time.Duration(req.ExpiresDays) * 24 * time.Hour)
	err := store.Tx(r.Context(), s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.InsertAPIToken(r.Context(), dbq.InsertAPITokenParams{ID: id, OrgID: p.OrgID, UserID: p.UserID, Name: name, Prefix: secret[:8], TokenHash: sum[:], Scopes: scopes, ExpiresAt: exp}); err != nil {
			return err
		}
		_, err := audit.Write(r.Context(), tx, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r), Action: "apitoken.create",
			TargetType: "api_token", TargetIDs: []string{id.String()}, Outcome: audit.Success, Details: map[string]any{"name": name, "scopes": scopes, "expires": exp.Format(time.RFC3339)}}, now)
		return err
	})
	if err != nil {
		s.Log.Error("create api token", "err", err)
		internalError(w)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "token": secret, "expires_at": exp, "scopes": scopes})
}

func (s *server) revokeOwnAPIToken(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	toks, _ := s.q().ListAPITokensForUser(r.Context(), p.UserID)
	if !slices.ContainsFunc(toks, func(t dbq.ListAPITokensForUserRow) bool { return t.ID == id }) {
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
		return
	}
	s.revokeToken2(w, r, p, id)
}

func (s *server) revokeAnyAPIToken(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	s.revokeToken2(w, r, principalFrom(r), id)
}

func (s *server) revokeToken2(w http.ResponseWriter, r *http.Request, p *Principal, id uuid.UUID) {
	n, err := s.q().RevokeAPIToken(r.Context(), dbq.RevokeAPITokenParams{ID: id, OrgID: p.OrgID, RevokedAt: ptr.Of(s.now())})
	if err != nil {
		internalError(w)
		return
	}
	if n == 0 {
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
		return
	}
	s.audit(r, p, "apitoken.revoke", "api_token", []string{id.String()}, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) listAllAPITokens(w http.ResponseWriter, r *http.Request) {
	rows, err := s.q().ListAPITokensInOrg(r.Context(), principalFrom(r).OrgID)
	if err != nil {
		internalError(w)
		return
	}
	out := make([]apiTokenView, 0, len(rows))
	for _, t := range rows {
		out = append(out, apiTokenView{ID: t.ID, Name: t.Name, Prefix: t.Prefix, Scopes: t.Scopes, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
			LastUsedAt: t.LastUsedAt, LastUsedIP: t.LastUsedIp, RevokedAt: t.RevokedAt, Owner: t.OwnerEmail})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// ---- WebAuthn ----

const ceremonyTTL = 5 * time.Minute

// waUser adapts a user and their stored credentials to the library.
type waUser struct {
	u     dbq.User
	creds []webauthn.Credential
}

func (w *waUser) WebAuthnID() []byte                         { return w.u.ID[:] }
func (w *waUser) WebAuthnName() string                       { return w.u.Email }
func (w *waUser) WebAuthnDisplayName() string                { return w.u.DisplayName }
func (w *waUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

func (s *server) waUserFor(r *http.Request, u dbq.User) (*waUser, []dbq.WebauthnCredential, error) {
	rows, err := s.q().ListWebAuthnCredentials(r.Context(), u.ID)
	if err != nil {
		return nil, nil, err
	}
	wu := &waUser{u: u}
	for _, row := range rows {
		var c webauthn.Credential
		if json.Unmarshal(row.Record, &c) == nil {
			wu.creds = append(wu.creds, c)
		}
	}
	return wu, rows, nil
}

func (s *server) saveCeremony(r *http.Request, user uuid.UUID, kind string, sd *webauthn.SessionData) (uuid.UUID, error) {
	b, err := json.Marshal(sd)
	if err != nil {
		return uuid.Nil, err
	}
	id := uuid.New()
	q := s.q()
	_ = q.DeleteExpiredWebAuthnCeremonies(r.Context(), s.now())
	return id, q.InsertWebAuthnCeremony(r.Context(), dbq.InsertWebAuthnCeremonyParams{ID: id, UserID: user, Kind: kind, Data: b, ExpiresAt: s.now().Add(ceremonyTTL)})
}

func (s *server) takeCeremony(r *http.Request, user uuid.UUID, kind string) (*webauthn.SessionData, bool) {
	id, err := uuid.Parse(r.URL.Query().Get("ceremony"))
	if err != nil {
		return nil, false
	}
	data, err := s.q().TakeWebAuthnCeremony(r.Context(), dbq.TakeWebAuthnCeremonyParams{ID: id, UserID: user, Kind: kind, ExpiresAt: s.now()})
	if err != nil {
		return nil, false
	}
	var sd webauthn.SessionData
	if json.Unmarshal(data, &sd) != nil {
		return nil, false
	}
	return &sd, true
}

func (s *server) waAvailable(w http.ResponseWriter) bool {
	if s.webauthn == nil {
		writeError(w, http.StatusServiceUnavailable, "webauthn_unavailable", "Security keys need the console to be opened at its https address (or localhost).")
		return false
	}
	return true
}

// beginSecurityKey: POST /me/security-keys/begin (full session).
func (s *server) beginSecurityKey(w http.ResponseWriter, r *http.Request) {
	if !s.waAvailable(w) {
		return
	}
	p := principalFrom(r)
	if v := s.secSettings(r.Context(), p.OrgID); !v.Bool("allow_security_keys") {
		writeError(w, http.StatusForbidden, "security_keys_off", "Your administrator has turned off adding security keys.")
		return
	}
	if p.TokenID != "" {
		writeError(w, http.StatusForbidden, "forbidden", "Use the console to manage security keys.")
		return
	}
	u, err := s.q().GetUserByID(r.Context(), p.UserID)
	if err != nil {
		internalError(w)
		return
	}
	wu, _, err := s.waUserFor(r, u)
	if err != nil {
		internalError(w)
		return
	}
	creation, sd, err := s.webauthn.BeginRegistration(wu,
		webauthn.WithExclusions(webauthn.Credentials(wu.creds).CredentialDescriptors()),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{UserVerification: protocol.VerificationPreferred, ResidentKey: protocol.ResidentKeyRequirementDiscouraged}))
	if err != nil {
		s.Log.Error("webauthn begin registration", "err", err)
		internalError(w)
		return
	}
	cid, err := s.saveCeremony(r, u.ID, "register", sd)
	if err != nil {
		internalError(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": cid, "options": creation})
}

// finishSecurityKey: POST /me/security-keys/finish?ceremony=ID&name=NAME with the browser's credential as the body.
func (s *server) finishSecurityKey(w http.ResponseWriter, r *http.Request) {
	if !s.waAvailable(w) {
		return
	}
	p := principalFrom(r)
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if n := utf8.RuneCountInString(name); n < 1 || n > 100 {
		badRequest(w, "Give the key a name (1 to 100 characters).")
		return
	}
	sd, ok := s.takeCeremony(r, p.UserID, "register")
	if !ok {
		badRequest(w, "That registration expired. Start again.")
		return
	}
	u, err := s.q().GetUserByID(r.Context(), p.UserID)
	if err != nil {
		internalError(w)
		return
	}
	wu, _, err := s.waUserFor(r, u)
	if err != nil {
		internalError(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	cred, err := s.webauthn.FinishRegistration(wu, *sd, r)
	if err != nil {
		s.Log.Info("webauthn registration refused", "err", err)
		badRequest(w, "The security key could not be registered.")
		return
	}
	rec, _ := json.Marshal(cred)
	id := uuid.New()
	err = store.Tx(r.Context(), s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.InsertWebAuthnCredential(r.Context(), dbq.InsertWebAuthnCredentialParams{ID: id, UserID: u.ID, CredentialID: cred.ID, Record: rec, SignCount: int64(cred.Authenticator.SignCount), Name: name}); err != nil {
			return err
		}
		_, err := audit.Write(r.Context(), tx, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r), Action: "auth.securitykey_add",
			TargetType: "user", TargetIDs: []string{u.ID.String()}, Outcome: audit.Success, Details: map[string]any{"name": name}}, s.now())
		return err
	})
	if isUnique(err) {
		writeError(w, http.StatusConflict, "conflict", "That security key is already registered.")
		return
	}
	if err != nil {
		internalError(w)
		return
	}
	writeJSON(w, http.StatusCreated, keyView{ID: id, Name: name, CreatedAt: s.now()})
}

func (s *server) deleteSecurityKey(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	if p.TokenID != "" {
		writeError(w, http.StatusForbidden, "forbidden", "Use the console to manage security keys.")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
		return
	}
	creds, _ := s.q().ListWebAuthnCredentials(r.Context(), p.UserID)
	_, totpErr := s.q().GetTOTP(r.Context(), p.UserID)
	if errors.Is(totpErr, pgx.ErrNoRows) && len(creds) <= 1 {
		writeError(w, http.StatusConflict, "last_factor", "That is your only second factor. Set up an authenticator app or another key first.")
		return
	}
	n, err := s.q().DeleteWebAuthnCredential(r.Context(), dbq.DeleteWebAuthnCredentialParams{ID: id, UserID: p.UserID})
	if err != nil {
		internalError(w)
		return
	}
	if n == 0 {
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
		return
	}
	s.audit(r, p, "auth.securitykey_remove", "user", []string{p.UserID.String()}, nil)
	w.WriteHeader(http.StatusNoContent)
}

// beginKeyLogin: POST /auth/webauthn/begin on a password-verified session.
func (s *server) beginKeyLogin(w http.ResponseWriter, r *http.Request) {
	if !s.waAvailable(w) {
		return
	}
	sess, u, ok := s.pendingSession(w, r)
	if !ok {
		return
	}
	_ = sess
	wu, _, err := s.waUserFor(r, *u)
	if err != nil {
		internalError(w)
		return
	}
	if len(wu.creds) == 0 {
		writeError(w, http.StatusConflict, "no_security_key", "No security key is registered for this account.")
		return
	}
	assertion, sd, err := s.webauthn.BeginLogin(wu, webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		internalError(w)
		return
	}
	cid, err := s.saveCeremony(r, u.ID, "login", sd)
	if err != nil {
		internalError(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": cid, "options": assertion})
}

// finishKeyLogin: POST /auth/webauthn/finish?ceremony=ID with the browser's assertion as the body.
func (s *server) finishKeyLogin(w http.ResponseWriter, r *http.Request) {
	if !s.waAvailable(w) {
		return
	}
	sess, u, ok := s.pendingSession(w, r)
	if !ok {
		return
	}
	sd, found := s.takeCeremony(r, u.ID, "login")
	if !found {
		badRequest(w, "That sign-in step expired. Start again.")
		return
	}
	wu, _, err := s.waUserFor(r, *u)
	if err != nil {
		internalError(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	cred, err := s.webauthn.FinishLogin(wu, *sd, r)
	if err != nil || cred.Authenticator.CloneWarning {
		if err == nil {
			s.Log.Warn("webauthn clone warning", "user", u.ID)
		}
		s.mfaFailure(w, r, sess, u, "webauthn")
		return
	}
	rec, _ := json.Marshal(cred)
	_ = s.q().UpdateWebAuthnCredentialUsage(r.Context(), dbq.UpdateWebAuthnCredentialUsageParams{UserID: u.ID, CredentialID: cred.ID, Record: rec, SignCount: int64(cred.Authenticator.SignCount), LastUsedAt: ptr.Of(s.now())})
	s.finishLogin(w, r, sess, u, "webauthn", nil)
}
