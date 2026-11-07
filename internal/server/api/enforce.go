package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/server/settings"
)

// secSettings returns the organization's Security settings (never nil; defaults if settings are unavailable).
func (s *server) secSettings(ctx context.Context, org uuid.UUID) settings.V {
	if s.Settings == nil {
		sec, _ := settings.ByID("security")
		return settings.V(sec.Defaults())
	}
	return s.Settings.Peek(ctx, org, "security")
}

func (s *server) singleOrgSecurity(ctx context.Context) settings.V {
	if s.Settings == nil {
		return s.secSettings(ctx, uuid.Nil)
	}
	org, err := s.Settings.Org(ctx)
	if err != nil {
		return s.secSettings(ctx, uuid.Nil)
	}
	return s.secSettings(ctx, org)
}

// ipAllow enforces the console IP allow-list (Settings > Security) on the whole API. Only the public pieces the
// sign-in page needs stay open, so that a blocked person sees a clear message instead of a blank page. Agents do not
// use this listener's API, so they are not affected.
func (s *server) ipAllow(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Settings == nil || (s.Cfg != nil && s.Cfg.IgnoreIPAllowlist) {
			next.ServeHTTP(w, r)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/api/v1")
		if path == "/branding" || strings.HasPrefix(path, "/branding/") || path == "/auth/notice" || path == "/setup/status" {
			next.ServeHTTP(w, r)
			return
		}
		list := s.singleOrgSecurity(r.Context()).Strings("ip_allowlist")
		if !settings.InAllowlist(list, clientIP(r)) {
			writeError(w, http.StatusForbidden, "ip_not_allowed", "This address is not allowed to use the console. Ask an administrator.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sessionLimits gives the session manager the organization's timeouts once Security has been saved; until then the
// server's own configuration (environment) applies.
func (s *server) sessionLimits(ctx context.Context) (idle, abs time.Duration) {
	if s.Settings == nil {
		return 0, 0
	}
	org, err := s.Settings.Org(ctx)
	if err != nil || !s.Settings.Saved(ctx, org, "security") {
		return 0, 0
	}
	v := s.Settings.Peek(ctx, org, "security")
	return time.Duration(v.Int("session_idle_minutes")) * time.Minute, time.Duration(v.Int("session_absolute_hours")) * time.Hour
}

// SessionLimits is the hook the application plugs into auth.Sessions.Timeouts.
func SessionLimits(d Deps) func(ctx context.Context) (time.Duration, time.Duration) {
	s := &server{Deps: d}
	return s.sessionLimits
}

// GET /auth/notice (public): the notice shown on the sign-in page, if the organization set one.
func (s *server) authNotice(w http.ResponseWriter, r *http.Request) {
	v := s.singleOrgSecurity(r.Context())
	on := v.Bool("login_banner_enabled") && v.Str("login_banner") != ""
	out := map[string]any{"enabled": on, "text": "", "require_ack": false}
	if on {
		out["text"] = v.Str("login_banner")
		out["require_ack"] = v.Bool("login_banner_require_ack")
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}
