package api

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/shared/bundle"
	"github.com/auzring1/librepatch/internal/shared/pkix"
)

type tokenView struct {
	ID              uuid.UUID  `json:"id"`
	Name            string     `json:"name"`
	MaxUses         int32      `json:"max_uses"`
	UsedCount       int32      `json:"used_count"`
	ExpiresAt       time.Time  `json:"expires_at"`
	RequireApproval bool       `json:"require_approval"`
	CreatedAt       time.Time  `json:"created_at"`
	RevokedAt       *time.Time `json:"revoked_at"`
	State           string     `json:"state"`
}

func viewToken(t dbq.EnrollmentToken, now time.Time) tokenView {
	state := "active"
	switch {
	case t.RevokedAt != nil:
		state = "revoked"
	case !now.Before(t.ExpiresAt):
		state = "expired"
	case t.UsedCount >= t.MaxUses:
		state = "exhausted"
	}
	return tokenView{ID: t.ID, Name: t.Name, MaxUses: t.MaxUses, UsedCount: t.UsedCount, ExpiresAt: t.ExpiresAt,
		RequireApproval: t.RequireApproval, CreatedAt: t.CreatedAt, RevokedAt: t.RevokedAt, State: state}
}

func (s *server) listTokens(w http.ResponseWriter, r *http.Request) {
	rows, err := s.q().ListEnrollmentTokens(r.Context(), principalFrom(r).OrgID)
	if err != nil {
		internalError(w)
		return
	}
	now := s.now()
	items := make([]tokenView, 0, len(rows))
	for _, t := range rows {
		items = append(items, viewToken(t, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type createTokenReq struct {
	Name            string `json:"name"`
	MaxUses         int32  `json:"max_uses"`
	ExpiresInHours  int32  `json:"expires_in_hours"`
	RequireApproval bool   `json:"require_approval"`
	// SiteID is the site new devices join (default: the organization's first site).
	SiteID *uuid.UUID `json:"site_id"`
}

func (s *server) createToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenReq
	if !decode(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	switch {
	case req.Name == "" || utf8.RuneCountInString(req.Name) > 200:
		badRequest(w, "name is required (max 200 characters)")
		return
	case req.MaxUses < 1 || req.MaxUses > 100000:
		badRequest(w, "max_uses must be between 1 and 100000")
		return
	case req.ExpiresInHours < 1 || req.ExpiresInHours > 24*365:
		badRequest(w, "expires_in_hours must be between 1 and 8760")
		return
	}
	a := s.Authority()
	if a == nil {
		writeError(w, http.StatusServiceUnavailable, "pki_unavailable", "The certificate authority is not ready.")
		return
	}
	p := principalFrom(r)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		internalError(w)
		return
	}
	tokStr := base64.RawURLEncoding.EncodeToString(secret)
	enc, err := bundle.Bundle{V: 1, Gateway: s.Cfg.GatewayPublicAddr, RootPin: pkix.SPKIPin(a.Root),
		Token: tokStr, Org: p.OrgID.String()}.Encode()
	if err != nil {
		s.Log.Error("encode bundle", "err", err)
		internalError(w)
		return
	}
	now := s.now()
	var created dbq.EnrollmentToken
	err = store.Tx(r.Context(), s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		var site dbq.Site
		var err error
		if req.SiteID != nil {
			site, err = q.GetSiteInOrg(r.Context(), dbq.GetSiteInOrgParams{ID: *req.SiteID, OrgID: p.OrgID})
			if err != nil {
				return errUnknownSite
			}
		} else if site, err = q.GetDefaultSite(r.Context(), p.OrgID); err != nil {
			return err
		}
		id := uuid.New()
		h := auth.EnrollmentTokenHash(tokStr)
		if err := q.CreateEnrollmentToken(r.Context(), dbq.CreateEnrollmentTokenParams{ID: id, OrgID: p.OrgID, SiteID: site.ID,
			Name: req.Name, TokenHash: h, MaxUses: req.MaxUses, ExpiresAt: now.Add(time.Duration(req.ExpiresInHours) * time.Hour),
			RequireApproval: req.RequireApproval, CreatedBy: p.UserID}); err != nil {
			return err
		}
		created = dbq.EnrollmentToken{ID: id, Name: req.Name, MaxUses: req.MaxUses, ExpiresAt: now.Add(time.Duration(req.ExpiresInHours) * time.Hour),
			RequireApproval: req.RequireApproval, CreatedAt: now}
		_, err = audit.Write(r.Context(), tx, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(),
			ActorIP: clientIP(r), Action: "enrollment_token.create", TargetType: "enrollment_token", TargetIDs: []string{id.String()},
			Outcome: audit.Success, Details: map[string]any{"name": req.Name, "max_uses": req.MaxUses,
				"expires_in_hours": req.ExpiresInHours, "require_approval": req.RequireApproval}}, now)
		return err
	})
	if errors.Is(err, errUnknownSite) {
		badRequest(w, "Unknown site.")
		return
	}
	if err != nil {
		s.Log.Error("create token", "err", err)
		internalError(w)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":             viewToken(created, now),
		"enrollment_string": enc,
		"install_command":   `librepatch-agent.exe install --server ` + s.Cfg.GatewayPublicAddr + ` --token ` + enc,
		"install":           s.installCommands(enc),
		"root_ca_pin":       pkix.SPKIPin(a.Root),
	})
}

func (s *server) revokeToken(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Token not found.")
		return
	}
	p := principalFrom(r)
	now := s.now()
	err = store.Tx(r.Context(), s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		n, err := q.RevokeEnrollmentToken(r.Context(), dbq.RevokeEnrollmentTokenParams{ID: id, OrgID: p.OrgID, RevokedAt: &now})
		if err != nil {
			return err
		}
		if n == 0 {
			return errConflict
		}
		_, err = audit.Write(r.Context(), tx, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(),
			ActorIP: clientIP(r), Action: "enrollment_token.revoke", TargetType: "enrollment_token", TargetIDs: []string{id.String()},
			Outcome: audit.Success}, now)
		return err
	})
	if errors.Is(err, errConflict) {
		writeError(w, http.StatusNotFound, "not_found", "Token not found or already revoked.")
		return
	} else if err != nil {
		internalError(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func spkiPin(c *x509.Certificate) string { return pkix.SPKIPin(c) }

var (
	errUnknownSite  = errors.New("unknown site")
	errTokenMissing = errors.New("token not found")
)

// deleteToken: DELETE /enrollment-tokens/{id}. Removes a token that can no longer enroll anything
// (revoked, expired or used up) so the list does not fill with dead entries. A token that can still
// be used must be revoked first, so a click cannot silently take away a rollout's token and a
// leaked one stays visible until it is revoked. Devices enrolled with it are kept (D106).
func (s *server) deleteToken(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Token not found.")
		return
	}
	p := principalFrom(r)
	now := s.now()
	err = store.Tx(r.Context(), s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		t, err := q.GetEnrollmentTokenInOrg(r.Context(), dbq.GetEnrollmentTokenInOrgParams{ID: id, OrgID: p.OrgID})
		if errors.Is(err, pgx.ErrNoRows) {
			return errTokenMissing
		} else if err != nil {
			return err
		}
		v := viewToken(t, now)
		if v.State == "active" {
			return errConflict
		}
		if _, err := q.DeleteEnrollmentToken(r.Context(), dbq.DeleteEnrollmentTokenParams{ID: id, OrgID: p.OrgID}); err != nil {
			return err
		}
		_, err = audit.Write(r.Context(), tx, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(),
			ActorIP: clientIP(r), Action: "enrollment_token.delete", TargetType: "enrollment_token", TargetIDs: []string{id.String()},
			Outcome: audit.Success, Details: map[string]any{"name": t.Name, "state": v.State, "used_count": t.UsedCount}}, now)
		return err
	})
	switch {
	case errors.Is(err, errTokenMissing):
		writeError(w, http.StatusNotFound, "not_found", "Token not found.")
	case errors.Is(err, errConflict):
		writeError(w, http.StatusConflict, "token_active", "This token can still be used. Revoke it before deleting it.")
	case err != nil:
		s.Log.Error("delete token", "err", err)
		internalError(w)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
