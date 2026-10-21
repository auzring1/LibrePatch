package api

import (
	"crypto/rand"
	"math/big"
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
	"github.com/auzring1/librepatch/internal/shared/ptr"
)

func (s *server) audit(r *http.Request, p *Principal, action, targetType string, targets []string, details map[string]any) {
	if err := audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r),
		Action: action, TargetType: targetType, TargetIDs: targets, Outcome: audit.Success, Details: details}); err != nil {
		s.Log.Error("audit", "action", action, "err", err)
	}
}

// ---- sites ----

type siteView struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Timezone  string    `json:"timezone"`
	CreatedAt time.Time `json:"created_at"`
	Devices   int64     `json:"devices"`
}

func (s *server) listSites(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	rows, err := s.q().ListSitesWithCounts(r.Context(), p.OrgID)
	if err != nil {
		internalError(w)
		return
	}
	items := make([]siteView, 0, len(rows))
	for _, x := range rows {
		v := siteView{ID: x.ID, Name: x.Name, Timezone: x.Timezone, CreatedAt: x.CreatedAt}
		if p.Access.OrgHas(auth.PermSitesRead) {
			v.Devices = x.Devices
		}
		items = append(items, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type siteBody struct {
	Name     string `json:"name"`
	Timezone string `json:"timezone"`
}

func (b *siteBody) valid() string {
	b.Name = strings.TrimSpace(b.Name)
	if n := utf8.RuneCountInString(b.Name); n < 1 || n > 200 {
		return "The name must be between 1 and 200 characters."
	}
	if b.Timezone == "" {
		b.Timezone = "UTC"
	}
	if _, err := time.LoadLocation(b.Timezone); err != nil {
		return "Unknown time zone (use an IANA name such as Europe/Berlin)."
	}
	return ""
}

func (s *server) createSite(w http.ResponseWriter, r *http.Request) {
	var b siteBody
	if !decode(w, r, &b) {
		return
	}
	if m := b.valid(); m != "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", m)
		return
	}
	p := principalFrom(r)
	id := uuid.New()
	if err := s.q().CreateSite(r.Context(), dbq.CreateSiteParams{ID: id, OrgID: p.OrgID, Name: b.Name, Timezone: b.Timezone}); err != nil {
		if isUnique(err) {
			writeError(w, http.StatusConflict, "conflict", "A site with that name already exists.")
			return
		}
		internalError(w)
		return
	}
	s.audit(r, p, "site.create", "site", []string{id.String()}, map[string]any{"name": b.Name})
	writeJSON(w, http.StatusCreated, siteView{ID: id, Name: b.Name, Timezone: b.Timezone, CreatedAt: s.now()})
}

func (s *server) updateSite(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var b siteBody
	if !decode(w, r, &b) {
		return
	}
	if m := b.valid(); m != "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", m)
		return
	}
	p := principalFrom(r)
	n, err := s.q().UpdateSite(r.Context(), dbq.UpdateSiteParams{ID: id, OrgID: p.OrgID, Name: b.Name, Timezone: b.Timezone})
	switch {
	case isUnique(err):
		writeError(w, http.StatusConflict, "conflict", "A site with that name already exists.")
	case err != nil:
		internalError(w)
	case n == 0:
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
	default:
		s.audit(r, p, "site.update", "site", []string{id.String()}, map[string]any{"name": b.Name})
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *server) deleteSite(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	q := s.q()
	if _, err := q.GetSiteInOrg(r.Context(), dbq.GetSiteInOrgParams{ID: id, OrgID: p.OrgID}); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
		return
	}
	devs, _ := q.CountSiteDevices(r.Context(), id)
	toks, _ := q.CountSiteTokens(r.Context(), id)
	if devs > 0 || toks > 0 {
		writeError(w, http.StatusConflict, "site_in_use", "The site still has devices or enrollment tokens. Move or delete them first.")
		return
	}
	if sites, _ := q.ListSitesWithCounts(r.Context(), p.OrgID); len(sites) <= 1 {
		writeError(w, http.StatusConflict, "last_site", "An organization needs at least one site.")
		return
	}
	err := store.Tx(r.Context(), s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.DeleteBindingsForSite(r.Context(), id); err != nil {
			return err
		}
		_, err := q.DeleteSite(r.Context(), dbq.DeleteSiteParams{ID: id, OrgID: p.OrgID})
		return err
	})
	if err != nil {
		internalError(w)
		return
	}
	s.audit(r, p, "site.delete", "site", []string{id.String()}, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- users ----

type bindingView struct {
	ID        uuid.UUID `json:"id"`
	Role      string    `json:"role"`
	ScopeType string    `json:"scope_type"`
	ScopeID   uuid.UUID `json:"scope_id"`
	// Source is "sso" for a role that follows the identity provider and "local" for one set by hand.
	Source string `json:"source"`
}

type userView struct {
	ID                 uuid.UUID     `json:"id"`
	Email              string        `json:"email"`
	DisplayName        string        `json:"display_name"`
	Status             string        `json:"status"`
	LockedUntil        *time.Time    `json:"locked_until"`
	LastLoginAt        *time.Time    `json:"last_login_at"`
	CreatedAt          time.Time     `json:"created_at"`
	MustChangePassword bool          `json:"must_change_password"`
	HasTOTP            bool          `json:"has_totp"`
	SecurityKeys       int           `json:"security_keys"`
	Bindings           []bindingView `json:"bindings"`
	// SSO is true for somebody who signs in with the organization's identity provider.
	SSO bool `json:"sso"`
}

func (s *server) listUsers(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	rows, err := s.q().ListUsersInOrg(r.Context(), p.OrgID)
	if err != nil {
		internalError(w)
		return
	}
	binds, err := s.q().ListRoleBindingsInOrg(r.Context(), p.OrgID)
	if err != nil {
		internalError(w)
		return
	}
	by := map[uuid.UUID][]bindingView{}
	for _, b := range binds {
		by[b.UserID] = append(by[b.UserID], bindingView{ID: b.ID, Role: b.Role, ScopeType: b.ScopeType, ScopeID: b.ScopeID, Source: b.Source})
	}
	ssoIDs, err := s.q().ListSSOUsers(r.Context(), ssoProvider)
	if err != nil {
		internalError(w)
		return
	}
	viaSSO := map[uuid.UUID]bool{}
	for _, id := range ssoIDs {
		viaSSO[id] = true
	}
	items := make([]userView, 0, len(rows))
	for _, u := range rows {
		bs := by[u.ID]
		if bs == nil {
			bs = []bindingView{}
		}
		items = append(items, userView{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, Status: u.Status, LockedUntil: u.LockedUntil, LastLoginAt: u.LastLoginAt,
			CreatedAt: u.CreatedAt, MustChangePassword: u.MustChangePassword, HasTOTP: u.HasTotp, SecurityKeys: int(u.WebauthnCount), Bindings: bs, SSO: viaSSO[u.ID]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type bindingBody struct {
	Role      string    `json:"role"`
	ScopeType string    `json:"scope_type"`
	ScopeID   uuid.UUID `json:"scope_id"`
}

// checkBinding validates a role binding against the organization's sites.
func (s *server) checkBinding(r *http.Request, p *Principal, b bindingBody) string {
	if !auth.ValidRole(b.Role) {
		return "Unknown role."
	}
	switch b.ScopeType {
	case auth.ScopeOrg:
		if b.ScopeID != p.OrgID {
			return "An organization-wide role must use the organization's id as its scope."
		}
	case auth.ScopeSite:
		if _, err := s.q().GetSiteInOrg(r.Context(), dbq.GetSiteInOrgParams{ID: b.ScopeID, OrgID: p.OrgID}); err != nil {
			return "Unknown site."
		}
	default:
		return "scope_type must be org or site."
	}
	return ""
}

const tempPasswordAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func generatePassword() (string, error) {
	out := make([]byte, 20)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(tempPasswordAlphabet))))
		if err != nil {
			return "", err
		}
		out[i] = tempPasswordAlphabet[n.Int64()]
	}
	return string(out), nil
}

func (s *server) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string        `json:"email"`
		DisplayName string        `json:"display_name"`
		Password    string        `json:"password"`
		Roles       []bindingBody `json:"roles"`
	}
	if !decode(w, r, &req) {
		return
	}
	p := principalFrom(r)
	email, ok := normEmail(req.Email)
	name := strings.TrimSpace(req.DisplayName)
	if !ok {
		badRequest(w, "Enter a valid email address.")
		return
	}
	if n := utf8.RuneCountInString(name); n < 1 || n > 200 {
		badRequest(w, "The display name must be between 1 and 200 characters.")
		return
	}
	if len(req.Roles) == 0 || len(req.Roles) > 20 {
		badRequest(w, "Give the user at least one role.")
		return
	}
	for _, b := range req.Roles {
		if m := s.checkBinding(r, p, b); m != "" {
			badRequest(w, m)
			return
		}
	}
	pw, generated := req.Password, false
	if pw == "" {
		var err error
		if pw, err = generatePassword(); err != nil {
			internalError(w)
			return
		}
		generated = true
	} else if err := auth.ValidatePasswordMin(pw, email, s.secSettings(r.Context(), principalFrom(r).OrgID).Int("password_min_length")); err != nil {
		badRequest(w, err.Error())
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		internalError(w)
		return
	}
	id := uuid.New()
	err = store.Tx(r.Context(), s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.CreateManagedUser(r.Context(), dbq.CreateManagedUserParams{ID: id, OrgID: p.OrgID, Email: email, DisplayName: name, PasswordHash: hash,
			MustChangePassword: true, CreatedBy: &p.UserID}); err != nil {
			return err
		}
		if err := q.CreateUserIdentity(r.Context(), dbq.CreateUserIdentityParams{ID: uuid.New(), UserID: id, Provider: "local", Subject: id.String()}); err != nil {
			return err
		}
		for _, b := range req.Roles {
			if err := q.CreateRoleBinding(r.Context(), dbq.CreateRoleBindingParams{ID: uuid.New(), UserID: id, Role: b.Role, ScopeType: b.ScopeType, ScopeID: b.ScopeID}); err != nil {
				return err
			}
		}
		_, err := audit.Write(r.Context(), tx, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r), Action: "user.create",
			TargetType: "user", TargetIDs: []string{id.String()}, Outcome: audit.Success, Details: map[string]any{"email": email, "roles": len(req.Roles)}}, s.now())
		return err
	})
	if isUnique(err) {
		writeError(w, http.StatusConflict, "conflict", "A user with that email already exists.")
		return
	}
	if err != nil {
		s.Log.Error("create user", "err", err)
		internalError(w)
		return
	}
	resp := map[string]any{"id": id}
	if generated {
		resp["temporary_password"] = pw // shown once
	}
	writeJSON(w, http.StatusCreated, resp)
}

// lastAdminGuard refuses a change that would leave the organization without an active admin.
func (s *server) lastAdminGuard(r *http.Request, p *Principal, target uuid.UUID) bool {
	n, err := s.q().CountOtherActiveOrgAdmins(r.Context(), dbq.CountOtherActiveOrgAdminsParams{OrgID: p.OrgID, ID: target})
	return err != nil || n == 0
}

func (s *server) userFromURL(w http.ResponseWriter, r *http.Request) (dbq.User, bool) {
	id, ok := idParam(w, r)
	if !ok {
		return dbq.User{}, false
	}
	u, err := s.q().GetUserInOrg(r.Context(), dbq.GetUserInOrgParams{ID: id, OrgID: principalFrom(r).OrgID})
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
		return dbq.User{}, false
	}
	return u, true
}

func (s *server) isOrgAdmin(r *http.Request, user uuid.UUID, org uuid.UUID) bool {
	binds, err := s.q().ListRoleBindingsForUser(r.Context(), user)
	if err != nil {
		return false
	}
	for _, b := range binds {
		if b.Role == auth.RoleAdmin && b.ScopeType == auth.ScopeOrg && b.ScopeID == org {
			return true
		}
	}
	return false
}

func (s *server) updateUser(w http.ResponseWriter, r *http.Request) {
	// Serializes the check-then-act of the last-administrator guard (one server process owns the organization).
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	u, ok := s.userFromURL(w, r)
	if !ok {
		return
	}
	var req struct {
		DisplayName string `json:"display_name"`
		Status      string `json:"status"`
	}
	if !decode(w, r, &req) {
		return
	}
	p := principalFrom(r)
	name := strings.TrimSpace(req.DisplayName)
	if n := utf8.RuneCountInString(name); n < 1 || n > 200 || (req.Status != "active" && req.Status != "disabled") {
		badRequest(w, "Give a display name (1 to 200 characters) and a status of active or disabled.")
		return
	}
	if req.Status == "disabled" && u.Status == "active" {
		if u.ID == p.UserID {
			writeError(w, http.StatusConflict, "self", "You cannot disable your own account.")
			return
		}
		if s.isOrgAdmin(r, u.ID, p.OrgID) && s.lastAdminGuard(r, p, u.ID) {
			writeError(w, http.StatusConflict, "last_admin", "That is the last active administrator.")
			return
		}
	}
	if _, err := s.q().UpdateUserProfile(r.Context(), dbq.UpdateUserProfileParams{ID: u.ID, OrgID: p.OrgID, DisplayName: name, Status: req.Status}); err != nil {
		internalError(w)
		return
	}
	if req.Status == "disabled" {
		_ = s.q().DeleteSessionsForUser(r.Context(), u.ID)
	}
	s.audit(r, p, "user.update", "user", []string{u.ID.String()}, map[string]any{"status": req.Status})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) addBinding(w http.ResponseWriter, r *http.Request) {
	u, ok := s.userFromURL(w, r)
	if !ok {
		return
	}
	var b bindingBody
	if !decode(w, r, &b) {
		return
	}
	p := principalFrom(r)
	if m := s.checkBinding(r, p, b); m != "" {
		badRequest(w, m)
		return
	}
	err := s.q().CreateRoleBinding(r.Context(), dbq.CreateRoleBindingParams{ID: uuid.New(), UserID: u.ID, Role: b.Role, ScopeType: b.ScopeType, ScopeID: b.ScopeID})
	if isUnique(err) {
		writeError(w, http.StatusConflict, "conflict", "The user already has that role.")
		return
	} else if err != nil {
		internalError(w)
		return
	}
	s.audit(r, p, "user.role_add", "user", []string{u.ID.String()}, map[string]any{"role": b.Role, "scope_type": b.ScopeType, "scope_id": b.ScopeID.String()})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) removeBinding(w http.ResponseWriter, r *http.Request) {
	// Serializes the check-then-act of the last-administrator guard (one server process owns the organization).
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	u, ok := s.userFromURL(w, r)
	if !ok {
		return
	}
	bid, err := uuid.Parse(chi.URLParam(r, "bid"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
		return
	}
	p := principalFrom(r)
	binds, _ := s.q().ListRoleBindingsForUser(r.Context(), u.ID)
	for _, b := range binds {
		if b.ID == bid && b.Role == auth.RoleAdmin && b.ScopeType == auth.ScopeOrg {
			if u.ID == p.UserID {
				writeError(w, http.StatusConflict, "self", "You cannot remove your own administrator role.")
				return
			}
			if s.lastAdminGuard(r, p, u.ID) {
				writeError(w, http.StatusConflict, "last_admin", "That is the last active administrator.")
				return
			}
		}
	}
	n, err := s.q().DeleteRoleBinding(r.Context(), dbq.DeleteRoleBindingParams{ID: bid, UserID: u.ID})
	if err != nil {
		internalError(w)
		return
	}
	if n == 0 {
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
		return
	}
	s.audit(r, p, "user.role_remove", "user", []string{u.ID.String()}, nil)
	w.WriteHeader(http.StatusNoContent)
}

// resetUserPassword sets a temporary password; the user must change it at the next sign-in.
func (s *server) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	u, ok := s.userFromURL(w, r)
	if !ok {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	pw, generated := req.Password, false
	if pw == "" {
		var err error
		if pw, err = generatePassword(); err != nil {
			internalError(w)
			return
		}
		generated = true
	} else if err := auth.ValidatePasswordMin(pw, u.Email, s.secSettings(r.Context(), principalFrom(r).OrgID).Int("password_min_length")); err != nil {
		badRequest(w, err.Error())
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		internalError(w)
		return
	}
	p := principalFrom(r)
	if err := s.q().SetUserPassword(r.Context(), dbq.SetUserPasswordParams{ID: u.ID, PasswordHash: hash, MustChangePassword: true, PasswordChangedAt: s.now()}); err != nil {
		internalError(w)
		return
	}
	_ = s.q().DeleteSessionsForUser(r.Context(), u.ID)
	_ = s.q().RevokeAPITokensForUser(r.Context(), dbq.RevokeAPITokensForUserParams{UserID: u.ID, RevokedAt: ptr.Of(s.now())})
	s.audit(r, p, "user.password_reset", "user", []string{u.ID.String()}, nil)
	resp := map[string]any{}
	if generated {
		resp["temporary_password"] = pw
	}
	writeJSON(w, http.StatusOK, resp)
}

// resetUserMFA removes every second factor; the user enrolls a new one at the next sign-in.
func (s *server) resetUserMFA(w http.ResponseWriter, r *http.Request) {
	u, ok := s.userFromURL(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	err := store.Tx(r.Context(), s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.DeleteTOTP(r.Context(), u.ID); err != nil {
			return err
		}
		if err := q.DeleteWebAuthnCredentialsForUser(r.Context(), u.ID); err != nil {
			return err
		}
		if err := q.DeleteRecoveryCodes(r.Context(), u.ID); err != nil {
			return err
		}
		if err := q.DeleteSessionsForUser(r.Context(), u.ID); err != nil {
			return err
		}
		if err := q.RevokeAPITokensForUser(r.Context(), dbq.RevokeAPITokensForUserParams{UserID: u.ID, RevokedAt: ptr.Of(s.now())}); err != nil {
			return err
		}
		_, err := audit.Write(r.Context(), tx, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r), Action: "user.mfa_reset",
			TargetType: "user", TargetIDs: []string{u.ID.String()}, Outcome: audit.Success}, s.now())
		return err
	})
	if err != nil {
		internalError(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) deleteUser(w http.ResponseWriter, r *http.Request) {
	// Serializes the check-then-act of the last-administrator guard (one server process owns the organization).
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	u, ok := s.userFromURL(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	if u.ID == p.UserID {
		writeError(w, http.StatusConflict, "self", "You cannot delete your own account.")
		return
	}
	if s.isOrgAdmin(r, u.ID, p.OrgID) && s.lastAdminGuard(r, p, u.ID) {
		writeError(w, http.StatusConflict, "last_admin", "That is the last active administrator.")
		return
	}
	if _, err := s.q().DeleteUserInOrg(r.Context(), dbq.DeleteUserInOrgParams{ID: u.ID, OrgID: p.OrgID}); err != nil {
		s.Log.Error("delete user", "err", err)
		writeError(w, http.StatusConflict, "in_use", "The user cannot be deleted. Disable the account instead.")
		return
	}
	s.audit(r, p, "user.delete", "user", []string{u.ID.String()}, map[string]any{"email": u.Email})
	w.WriteHeader(http.StatusNoContent)
}
