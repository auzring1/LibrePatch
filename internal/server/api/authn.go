package api

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/server/kek"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/shared/ptr"
)

const (
	maxLoginFailures = 10
	lockoutDuration  = 15 * time.Minute
	maxMFAFailures   = 5
)

const loginFailedMsg = "Sign-in failed. Check your email and password. After repeated failures an account is locked for 15 minutes."

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if !decode(w, r, &req) {
		return
	}
	ip := clientIP(r)
	email, _ := normEmail(req.Email)
	if !s.loginIP.Allow(ip) || !s.loginEmail.Allow("e:"+email) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many sign-in attempts. Wait a minute and try again.")
		return
	}
	if len(req.Password) > 4*auth.MaxPasswordLen {
		writeError(w, http.StatusUnauthorized, "login_failed", loginFailedMsg)
		return
	}
	ctx := r.Context()
	q := s.q()
	now := s.now()
	u, err := q.GetUserByEmail(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		auth.VerifyPassword(req.Password, "") // equalize timing
		_ = audit.Log(ctx, s.Pool, audit.Entry{ActorType: audit.ActorAnonymous, ActorIP: ip, Action: "auth.login",
			Outcome: audit.Denied, Details: map[string]any{"email": email, "reason": "unknown_user"}})
		writeError(w, http.StatusUnauthorized, "login_failed", loginFailedMsg)
		return
	} else if err != nil {
		internalError(w)
		return
	}
	locked := u.LockedUntil != nil && now.Before(*u.LockedUntil)
	pwOK := auth.VerifyPassword(req.Password, u.PasswordHash)
	if !pwOK || locked || u.Status != "active" {
		reason := "bad_password"
		switch {
		case locked:
			reason = "locked"
		case u.Status != "active":
			reason = "disabled"
		}
		if !pwOK && !locked {
			s.recordLoginFailure(r, u)
		}
		_ = audit.Log(ctx, s.Pool, audit.Entry{OrgID: &u.OrgID, ActorType: audit.ActorUser, ActorID: u.ID.String(), ActorIP: ip,
			Action: "auth.login", Outcome: audit.Denied, Details: map[string]any{"reason": reason}})
		writeError(w, http.StatusUnauthorized, "login_failed", loginFailedMsg)
		return
	}
	// Password OK: issue a short-lived, MFA-pending session.
	if prev := sessionFrom(r); prev != nil {
		_ = q.DeleteSession(ctx, prev.IDHash)
	}
	sess, err := s.Sessions.Create(ctx, q, u.ID, false, ip, r.UserAgent())
	if err != nil {
		internalError(w)
		return
	}
	s.Sessions.SetCookie(w, sess)
	s.mfaChallenge(w, r, sess, &u)
}

// mfaChallenge tells a password-verified (MFA-pending) session what comes next: a forced password
// change, enrolling a first factor, or verifying one.
func (s *server) mfaChallenge(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *dbq.User) {
	ctx := r.Context()
	q := s.q()
	if u.MustChangePassword {
		writeJSON(w, http.StatusOK, map[string]any{"mfa": "change_password", "csrf_token": sess.CSRFToken})
		return
	}
	resp := map[string]any{"mfa": "verify", "csrf_token": sess.CSRFToken}
	creds, err := q.ListWebAuthnCredentials(ctx, u.ID)
	if err != nil {
		internalError(w)
		return
	}
	_, totpErr := q.GetTOTP(ctx, u.ID)
	switch {
	case errors.Is(totpErr, pgx.ErrNoRows) && len(creds) == 0:
		// No second factor at all (new account or MFA reset by an administrator): enroll one now.
		secret, err := auth.NewTOTPSecret()
		if err != nil {
			internalError(w)
			return
		}
		enc, err := s.Sealer.Seal(kek.PurposeTOTP, secret)
		if err != nil {
			internalError(w)
			return
		}
		if err := q.SetSessionPendingTOTP(ctx, dbq.SetSessionPendingTOTPParams{IDHash: sess.IDHash, PendingTotpEnc: enc}); err != nil {
			internalError(w)
			return
		}
		resp = map[string]any{"mfa": "enroll", "csrf_token": sess.CSRFToken,
			"totp_secret": auth.TOTPSecretString(secret), "otpauth_uri": auth.TOTPURI(s.productName(r), u.Email, secret)}
	case totpErr != nil && !errors.Is(totpErr, pgx.ErrNoRows):
		internalError(w)
		return
	}
	resp["methods"] = s.mfaMethods(totpErr == nil, len(creds) > 0)
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) mfaMethods(totp, webauthn bool) []string {
	var m []string
	if totp {
		m = append(m, "totp")
	}
	if webauthn {
		m = append(m, "webauthn")
	}
	return m
}

func (s *server) recordLoginFailure(r *http.Request, u dbq.User) {
	failures := u.FailedLogins + 1
	var until *time.Time
	threshold, lockFor := int32(maxLoginFailures), lockoutDuration
	if s.Settings != nil {
		v := s.secSettings(r.Context(), u.OrgID)
		threshold, lockFor = int32(v.Int("lockout_threshold")), time.Duration(v.Int("lockout_minutes"))*time.Minute // #nosec G115 -- validated to 3..20
	}
	if failures >= threshold {
		t := s.now().Add(lockFor)
		until, failures = &t, 0
		_ = audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &u.OrgID, ActorType: audit.ActorSystem, ActorIP: clientIP(r),
			Action: "auth.lockout", TargetType: "user", TargetIDs: []string{u.ID.String()}, Outcome: audit.Success,
			Details: map[string]any{"minutes": int(lockFor.Minutes())}})
	}
	if err := s.q().SetUserLoginFailure(r.Context(), dbq.SetUserLoginFailureParams{ID: u.ID, FailedLogins: failures, LockedUntil: until}); err != nil {
		s.Log.Error("record login failure", "err", err)
	}
}

type codeReq struct {
	Code string `json:"code"`
}

// pendingSession returns the MFA-pending session and its user.
func (s *server) pendingSession(w http.ResponseWriter, r *http.Request) (*auth.Session, *dbq.User, bool) {
	sess := sessionFrom(r)
	if sess == nil || sess.MFAVerified {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "Sign in with your password first.")
		return nil, nil, false
	}
	u, err := s.q().GetUserByID(r.Context(), sess.UserID)
	if err != nil || u.Status != "active" {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "Sign in with your password first.")
		return nil, nil, false
	}
	if u.MustChangePassword {
		writeError(w, http.StatusConflict, "password_change_required", "Choose a new password first.")
		return nil, nil, false
	}
	if u.LockedUntil != nil && u.LockedUntil.After(s.now()) {
		writeError(w, http.StatusUnauthorized, "locked", "This account is temporarily locked. Try again later.")
		return nil, nil, false
	}
	return sess, &u, true
}

func (s *server) mfaFailure(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *dbq.User, method string) {
	q := s.q()
	n, err := q.IncrementSessionMFAFailures(r.Context(), sess.IDHash)
	_ = audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &u.OrgID, ActorType: audit.ActorUser, ActorID: u.ID.String(),
		ActorIP: clientIP(r), Action: "auth.mfa", Outcome: audit.Denied, Details: map[string]any{"method": method}})
	// Every wrong code counts toward the account lockout, not just the fifth: otherwise someone who knows
	// the password could keep trying new sign-ins at five codes each (docs/THREAT-MODEL.md T-WEB-1).
	s.recordLoginFailure(r, *u)
	if err != nil || n >= maxMFAFailures {
		_ = q.DeleteSession(r.Context(), sess.IDHash)
		s.Sessions.ClearCookie(w)
		writeError(w, http.StatusUnauthorized, "mfa_locked", "Too many wrong codes. Sign in again.")
		return
	}
	writeError(w, http.StatusUnauthorized, "bad_code", "That code is not valid.")
}

func (s *server) mfaVerify(w http.ResponseWriter, r *http.Request) {
	var req codeReq
	if !decode(w, r, &req) {
		return
	}
	sess, u, ok := s.pendingSession(w, r)
	if !ok {
		return
	}
	if sess.PendingTOTPEnc != nil {
		writeError(w, http.StatusConflict, "mfa_enroll_required", "Set up your authenticator first.")
		return
	}
	ctx := r.Context()
	q := s.q()
	method := "totp"
	verified := false
	if auth.LooksLikeRecoveryCode(req.Code) {
		method = "recovery_code"
		codes, err := q.ListUnusedRecoveryCodes(ctx, u.ID)
		if err != nil {
			internalError(w)
			return
		}
		h := auth.HashRecoveryCode(req.Code)
		for _, c := range codes {
			if subtle.ConstantTimeCompare(c.CodeHash, h) == 1 {
				n, err := q.UseRecoveryCode(ctx, dbq.UseRecoveryCodeParams{ID: c.ID, UsedAt: ptr.Of(s.now())})
				verified = err == nil && n == 1
			}
		}
	} else {
		t, err := q.GetTOTP(ctx, u.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			s.mfaFailure(w, r, sess, u, method) // security-key-only account: a code cannot be right
			return
		}
		if err != nil {
			internalError(w)
			return
		}
		secret, err := s.Sealer.Open(kek.PurposeTOTP, t.SecretEnc)
		if err != nil {
			s.Log.Error("unseal totp", "err", err)
			internalError(w)
			return
		}
		if step, ok := auth.VerifyTOTP(secret, req.Code, s.now()); ok {
			n, err := q.ConsumeTOTPStep(ctx, dbq.ConsumeTOTPStepParams{UserID: u.ID, LastUsedStep: step})
			verified = err == nil && n == 1 // n == 0: code replayed
		}
	}
	if !verified {
		s.mfaFailure(w, r, sess, u, method)
		return
	}
	s.finishLogin(w, r, sess, u, method, nil)
}

func (s *server) mfaEnroll(w http.ResponseWriter, r *http.Request) {
	var req codeReq
	if !decode(w, r, &req) {
		return
	}
	sess, u, ok := s.pendingSession(w, r)
	if !ok {
		return
	}
	if sess.PendingTOTPEnc == nil {
		writeError(w, http.StatusConflict, "mfa_already_enrolled", "MFA is already set up for this account.")
		return
	}
	secret, err := s.Sealer.Open(kek.PurposeTOTP, sess.PendingTOTPEnc)
	if err != nil {
		internalError(w)
		return
	}
	step, ok := auth.VerifyTOTP(secret, req.Code, s.now())
	if !ok {
		s.mfaFailure(w, r, sess, u, "totp_enroll")
		return
	}
	codes, err := auth.NewRecoveryCodes(auth.RecoveryCodeCount)
	if err != nil {
		internalError(w)
		return
	}
	err = store.Tx(r.Context(), s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.UpsertTOTP(r.Context(), dbq.UpsertTOTPParams{UserID: u.ID, SecretEnc: sess.PendingTOTPEnc, LastUsedStep: step, ConfirmedAt: s.now()}); err != nil {
			return err
		}
		if err := insertRecoveryCodes(r, q, u.ID, codes); err != nil {
			return err
		}
		_, err := audit.Write(r.Context(), tx, audit.Entry{OrgID: &u.OrgID, ActorType: audit.ActorUser, ActorID: u.ID.String(),
			ActorIP: clientIP(r), Action: "auth.mfa_enroll", TargetType: "user", TargetIDs: []string{u.ID.String()}, Outcome: audit.Success}, s.now())
		return err
	})
	if err != nil {
		s.Log.Error("mfa enroll", "err", err)
		internalError(w)
		return
	}
	s.finishLogin(w, r, sess, u, "totp_enroll", codes)
}

// finishLogin rotates the pending session into a full session.
func (s *server) finishLogin(w http.ResponseWriter, r *http.Request, pending *auth.Session, u *dbq.User, method string, codes []string) {
	ctx := r.Context()
	var full *auth.Session
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.DeleteSession(ctx, pending.IDHash); err != nil {
			return err
		}
		var err error
		if full, err = s.Sessions.Create(ctx, q, u.ID, true, clientIP(r), r.UserAgent()); err != nil {
			return err
		}
		if err := q.SetUserLoginSuccess(ctx, dbq.SetUserLoginSuccessParams{ID: u.ID, LastLoginAt: ptr.Of(s.now())}); err != nil {
			return err
		}
		_, err = audit.Write(ctx, tx, audit.Entry{OrgID: &u.OrgID, ActorType: audit.ActorUser, ActorID: u.ID.String(),
			ActorIP: clientIP(r), Action: "auth.login", Outcome: audit.Success, Details: map[string]any{"mfa_method": method}}, s.now())
		return err
	})
	if err != nil {
		s.Log.Error("finish login", "err", err)
		internalError(w)
		return
	}
	s.Sessions.SetCookie(w, full)
	resp := map[string]any{"csrf_token": full.CSRFToken}
	if codes != nil {
		resp["recovery_codes"] = codes
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if sess := sessionFrom(r); sess != nil {
		_ = s.q().DeleteSession(r.Context(), sess.IDHash)
		_ = audit.Log(r.Context(), s.Pool, audit.Entry{ActorType: audit.ActorUser, ActorID: sess.UserID.String(),
			ActorIP: clientIP(r), Action: "auth.logout", Outcome: audit.Success})
	}
	s.Sessions.ClearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) session(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess == nil || !sess.MFAVerified {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "Sign in required.")
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	org, err := s.q().GetOrganization(r.Context(), p.OrgID)
	if err != nil {
		internalError(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":        map[string]any{"id": p.UserID, "email": p.Email, "display_name": p.DisplayName},
		"org":         map[string]any{"id": org.ID, "name": org.Name},
		"permissions": p.Permissions,
		// Permissions held only for some sites, so the console can offer device pages to site-limited users.
		"scoped_permissions": p.Access.ScopedPermissions(),
		"site_permissions":   p.Access.SitePermissions(),
		"csrf_token":         sess.CSRFToken,
		// True until the administrator has saved the master key the stack generated for itself (decision D109).
		"master_key_pending": s.keyPending(),
	})
}
