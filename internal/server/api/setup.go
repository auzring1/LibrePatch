package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/server/branding"
	"github.com/auzring1/librepatch/internal/server/kek"
	"github.com/auzring1/librepatch/internal/server/pki"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/shared/brand"
)

func (s *server) setupStatus(w http.ResponseWriter, r *http.Request) {
	req, err := s.Setup.Required(r.Context())
	if err != nil {
		internalError(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"setup_required": req})
}

// guardSetup rate-limits and checks that setup is pending and the token is valid.
func (s *server) guardSetup(w http.ResponseWriter, r *http.Request, token string) bool {
	if !s.setupIP.Allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many attempts. Wait a minute.")
		return false
	}
	req, err := s.Setup.Required(r.Context())
	if err != nil {
		internalError(w)
		return false
	}
	if !req {
		writeError(w, http.StatusConflict, "already_setup", "Setup has already been completed.")
		return false
	}
	if !s.Setup.CheckToken(token) {
		_ = audit.Log(r.Context(), s.Pool, audit.Entry{ActorType: audit.ActorAnonymous, ActorIP: clientIP(r),
			Action: "setup.token", Outcome: audit.Denied})
		writeError(w, http.StatusForbidden, "bad_setup_token", "The setup token is not valid. Copy it from the server log.")
		return false
	}
	return true
}

type setupBeginReq struct {
	SetupToken string `json:"setup_token"`
	Email      string `json:"email"`
}

func (s *server) setupBegin(w http.ResponseWriter, r *http.Request) {
	var req setupBeginReq
	if !decode(w, r, &req) || !s.guardSetup(w, r, req.SetupToken) {
		return
	}
	email, ok := normEmail(req.Email)
	if !ok {
		badRequest(w, "A valid email address is required.")
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		internalError(w)
		return
	}
	enc, err := s.Sealer.Seal(kek.PurposeSetupTOTP, secret)
	if err != nil {
		internalError(w)
		return
	}
	if err := s.q().UpsertSetupState(r.Context(), enc); err != nil {
		s.Log.Error("setup state", "err", err)
		internalError(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"totp_secret": auth.TOTPSecretString(secret),
		"otpauth_uri": auth.TOTPURI(brand.Name, email, secret),
	})
}

type setupCompleteReq struct {
	SetupToken     string `json:"setup_token"`
	OrgName        string `json:"org_name"`
	DisplayName    string `json:"display_name"`
	Email          string `json:"email"`
	Password       string `json:"password"`
	RootPassphrase string `json:"root_passphrase"`
	TOTPCode       string `json:"totp_code"`
	// LogoBase64 is an optional PNG or JPEG (base64, at most branding.MaxUploadBytes decoded).
	LogoBase64 string `json:"logo_base64,omitempty"`
}

// setupBodyLimit leaves room for a base64-encoded logo (4/3 of the decoded size) plus the form fields.
const setupBodyLimit = branding.MaxUploadBytes*4/3 + 16<<10

func (s *server) setupComplete(w http.ResponseWriter, r *http.Request) {
	var req setupCompleteReq
	if !decodeMax(w, r, &req, setupBodyLimit) || !s.guardSetup(w, r, req.SetupToken) {
		return
	}
	email, ok := normEmail(req.Email)
	org := strings.TrimSpace(req.OrgName)
	name := strings.TrimSpace(req.DisplayName)
	switch {
	case !ok:
		badRequest(w, "A valid email address is required.")
		return
	case org == "" || utf8.RuneCountInString(org) > 120:
		badRequest(w, "Organization name is required (max 120 characters).")
		return
	case name == "" || utf8.RuneCountInString(name) > 200:
		badRequest(w, "Your name is required (max 200 characters).")
		return
	}
	if err := auth.ValidatePassword(req.Password, email); err != nil {
		badRequest(w, err.Error())
		return
	}
	var logo *branding.Processed
	if req.LogoBase64 != "" {
		raw, err := base64.StdEncoding.DecodeString(req.LogoBase64)
		if err != nil || len(raw) > branding.MaxUploadBytes {
			badRequest(w, "The logo must be a PNG or JPEG image of at most 512 KB.")
			return
		}
		p, err := branding.Process(branding.KindLogoLight, raw)
		if err != nil {
			var ie *branding.ImageError
			if errors.As(err, &ie) {
				badRequest(w, ie.Error())
				return
			}
			internalError(w)
			return
		}
		logo = &p
	}
	if _, err := branding.Validate(branding.Settings{OrgName: org}); err != nil {
		badRequest(w, "Organization name contains characters that are not allowed.")
		return
	}
	if utf8.RuneCountInString(req.RootPassphrase) < pki.MinRootPassphraseLen || utf8.RuneCountInString(req.RootPassphrase) > 1024 {
		badRequest(w, "The CA root passphrase must be at least 16 characters.")
		return
	}
	if req.RootPassphrase == req.Password {
		badRequest(w, "The CA root passphrase must be different from your password.")
		return
	}
	pwHash, err := auth.HashPassword(req.Password)
	if err != nil {
		internalError(w)
		return
	}
	now := s.now()
	hier, err := pki.NewHierarchy(org, now)
	if err != nil {
		s.Log.Error("create CA", "err", err)
		internalError(w)
		return
	}
	codes, err := auth.NewRecoveryCodes(auth.RecoveryCodeCount)
	if err != nil {
		internalError(w)
		return
	}
	orgID, siteID, userID := uuid.New(), uuid.New(), uuid.New()
	var badCode bool
	err = store.Tx(r.Context(), s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		// Serialize concurrent setup attempts.
		if _, err := tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock(7231002)"); err != nil {
			return err
		}
		if n, err := q.CountUsers(r.Context()); err != nil || n > 0 {
			if err == nil {
				err = errAlreadySetup
			}
			return err
		}
		st, err := q.GetSetupState(r.Context())
		if err != nil {
			badCode = true
			return errBadCode
		}
		secret, err := s.Sealer.Open(kek.PurposeSetupTOTP, st.TotpSecretEnc)
		if err != nil {
			return err
		}
		step, ok := auth.VerifyTOTP(secret, req.TOTPCode, now)
		if !ok {
			badCode = true
			return errBadCode
		}
		totpEnc, err := s.Sealer.Seal(kek.PurposeTOTP, secret)
		if err != nil {
			return err
		}
		steps := []func() error{
			func() error {
				return q.CreateOrganization(r.Context(), dbq.CreateOrganizationParams{ID: orgID, Name: org})
			},
			func() error {
				return q.CreateSite(r.Context(), dbq.CreateSiteParams{ID: siteID, OrgID: orgID, Name: "Default", Timezone: "UTC"})
			},
			func() error {
				return q.CreateUser(r.Context(), dbq.CreateUserParams{ID: userID, OrgID: orgID, Email: email, DisplayName: name, PasswordHash: pwHash})
			},
			func() error {
				return branding.SetInitial(r.Context(), q, orgID, userID, org, logo, now)
			},
			func() error {
				return q.CreateUserIdentity(r.Context(), dbq.CreateUserIdentityParams{ID: uuid.New(), UserID: userID, Provider: "local", Subject: userID.String()})
			},
			func() error {
				return q.CreateRoleBinding(r.Context(), dbq.CreateRoleBindingParams{ID: uuid.New(), UserID: userID, Role: auth.RoleAdmin, ScopeType: "org", ScopeID: orgID})
			},
			func() error {
				return q.UpsertTOTP(r.Context(), dbq.UpsertTOTPParams{UserID: userID, SecretEnc: totpEnc, LastUsedStep: step, ConfirmedAt: now})
			},
			func() error { return insertRecoveryCodes(r, q, userID, codes) },
			func() error { return pki.SaveHierarchy(r.Context(), q, s.Sealer, hier, req.RootPassphrase) },
			func() error { return q.DeleteSetupState(r.Context()) },
		}
		for _, f := range steps {
			if err := f(); err != nil {
				return err
			}
		}
		_, err = audit.Write(r.Context(), tx, audit.Entry{OrgID: &orgID, ActorType: audit.ActorUser, ActorID: userID.String(),
			ActorIP: clientIP(r), Action: "setup.complete", TargetType: "organization", TargetIDs: []string{orgID.String()},
			Outcome: audit.Success, Details: map[string]any{"admin_email": email, "root_ca_pin": rootPin(hier), "org_name": org, "logo": logo != nil}}, now)
		return err
	})
	switch {
	case badCode:
		writeError(w, http.StatusBadRequest, "bad_totp", "That authenticator code is not valid. Check the time on your phone and try again.")
		return
	case errors.Is(err, errAlreadySetup):
		writeError(w, http.StatusConflict, "already_setup", "Setup has already been completed.")
		return
	case err != nil:
		s.Log.Error("setup complete", "err", err)
		internalError(w)
		return
	}
	if err := s.Setup.Completed(r.Context()); err != nil {
		s.Log.Error("post-setup start", "err", err)
	}
	s.Log.Info("first-run setup completed", "org", orgID, "admin", email)
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

var (
	errAlreadySetup = errors.New("already set up")
	errBadCode      = errors.New("bad code")
)

func insertRecoveryCodes(r *http.Request, q *dbq.Queries, userID uuid.UUID, codes []string) error {
	if err := q.DeleteRecoveryCodes(r.Context(), userID); err != nil {
		return err
	}
	for _, c := range codes {
		if err := q.InsertRecoveryCode(r.Context(), dbq.InsertRecoveryCodeParams{ID: uuid.New(), UserID: userID, CodeHash: auth.HashRecoveryCode(c)}); err != nil {
			return err
		}
	}
	return nil
}

func rootPin(h *pki.Hierarchy) string { return spkiPin(h.Root.Cert) }

func normEmail(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 3 || len(s) > 254 {
		return "", false
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || a.Name != "" {
		return "", false
	}
	return strings.ToLower(s), true
}
