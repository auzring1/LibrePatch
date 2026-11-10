package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/settings"
	"github.com/auzring1/librepatch/internal/server/store"
)

func (s *server) setSvc(w http.ResponseWriter) bool {
	if s.Settings == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "Settings are not available.")
		return false
	}
	return true
}

func (s *server) setActor(r *http.Request) settings.Actor {
	p := principalFrom(r)
	return settings.Actor{Org: p.OrgID, User: p.UserID, IP: clientIP(r)}
}

// sectionFor finds the section named in the URL and checks the caller may use it. Unknown sections are 404, not 403,
// and a caller without the permission gets 403.
func (s *server) sectionFor(w http.ResponseWriter, r *http.Request) (settings.Section, bool) {
	sec, ok := settings.ByID(chi.URLParam(r, "section"))
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "There is no such settings section.")
		return sec, false
	}
	if !principalFrom(r).Access.OrgHas(sec.Perm) {
		writeError(w, http.StatusForbidden, "forbidden", "You do not have permission to do that.")
		return sec, false
	}
	return sec, true
}

func (s *server) settingsError(w http.ResponseWriter, err error) {
	var fe settings.FieldErrors
	switch {
	case errors.As(err, &fe):
		writeJSON(w, http.StatusUnprocessableEntity, apiError{Error: errorBody{Code: "invalid_settings", Message: "Some settings are not valid.", Fields: fe}})
	case errors.Is(err, settings.ErrConflict):
		writeError(w, http.StatusConflict, "settings_changed", "Someone else changed these settings after you opened them. Reload to see their changes.")
	case errors.Is(err, settings.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "There is no such settings section.")
	case errors.Is(err, settings.ErrFormat):
		writeError(w, http.StatusUnprocessableEntity, "invalid_settings_file", err.Error())
	default:
		s.Log.Error("settings", "err", err)
		internalError(w)
	}
}

type sectionView struct {
	settings.Section
	Editable bool `json:"editable"`
}

// GET /settings/schema: the sections the caller may open, with every field's label, help, default and limits.
func (s *server) settingsSchema(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	out := []sectionView{}
	for _, sec := range settings.Sections {
		if p.Access.OrgHas(sec.Perm) {
			out = append(out, sectionView{Section: sec, Editable: true})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": settings.SchemaVersion, "sections": out, "events": settings.Events})
}

// GET /settings/sections/{section}
func (s *server) getSettingsSection(w http.ResponseWriter, r *http.Request) {
	if !s.setSvc(w) {
		return
	}
	sec, ok := s.sectionFor(w, r)
	if !ok {
		return
	}
	d, err := s.Settings.Get(r.Context(), principalFrom(r).OrgID, sec.ID)
	if err != nil {
		s.settingsError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// PUT /settings/sections/{section}: {"revision": n, "values": {...}}. Keys left out keep their saved values.
func (s *server) putSettingsSection(w http.ResponseWriter, r *http.Request) {
	if !s.setSvc(w) {
		return
	}
	sec, ok := s.sectionFor(w, r)
	if !ok {
		return
	}
	var in struct {
		Revision int64          `json:"revision"`
		Values   map[string]any `json:"values"`
	}
	if !decodeMax(w, r, &in, 1<<20) {
		return
	}
	d, err := s.Settings.Put(r.Context(), s.setActor(r), sec.ID, in.Revision, in.Values)
	if err != nil {
		s.settingsError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// GET /settings/effective: the organization's display and formatting choices, for any signed-in person. Only
// non-sensitive values; no secrets, no security settings.
func (s *server) settingsEffective(w http.ResponseWriter, r *http.Request) {
	if !s.setSvc(w) {
		return
	}
	org := principalFrom(r).OrgID
	ctx := r.Context()
	dev := s.Settings.Values(ctx, org, "devices")
	fields := []map[string]any{}
	for _, f := range dev.Items("custom_fields") {
		fields = append(fields, map[string]any{"key": f.Str("key"), "label": f.Str("label"), "type": f.Str("type"), "options": f.Strings("options"), "show_in_list": f.Bool("show_in_list")})
	}
	up := s.Settings.Values(ctx, org, "updates")
	writeJSON(w, http.StatusOK, map[string]any{
		"appearance": s.Settings.Values(ctx, org, "appearance"),
		"devices":    map[string]any{"offline_hours": dev.Int("offline_hours"), "naming_pattern": dev.Str("naming_pattern"), "default_columns": dev.Strings("default_columns"), "custom_fields": fields},
		"updates":    map[string]any(up),
	})
}

// GET /settings/export: every section's values as a JSON file. Secrets are never included.
func (s *server) exportSettings(w http.ResponseWriter, r *http.Request) {
	if !s.setSvc(w) {
		return
	}
	p := principalFrom(r)
	doc, err := s.Settings.Export(r.Context(), p.OrgID)
	if err != nil {
		s.settingsError(w, err)
		return
	}
	_ = s.auditSimple(r, "settings.export", "settings", []string{"all"}, map[string]any{"sections": len(doc.Sections)})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="librepatch-settings-`+s.now().UTC().Format("2006-01-02")+`.json"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(doc)
}

// POST /settings/import?dry_run=1: applies (or only checks) a settings file made by export.
func (s *server) importSettings(w http.ResponseWriter, r *http.Request) {
	if !s.setSvc(w) {
		return
	}
	var doc settings.ExportDoc
	if !decodeMax(w, r, &doc, 2<<20) {
		return
	}
	dry := r.URL.Query().Get("dry_run") == "1" || r.URL.Query().Get("dry_run") == "true"
	p := principalFrom(r)
	reports, err := s.Settings.Import(r.Context(), s.setActor(r), doc, dry, func(perm string) bool { return p.Access.OrgHas(perm) })
	if err != nil {
		var fe settings.FieldErrors
		if !errors.As(err, &fe) {
			s.settingsError(w, err)
			return
		}
		s.settingsError(w, err)
		return
	}
	failed := false
	for _, rep := range reports {
		failed = failed || len(rep.Errors) > 0
	}
	if !dry && !failed {
		_ = s.auditSimple(r, "settings.import", "settings", []string{"all"}, map[string]any{"sections": len(reports)})
	}
	status := http.StatusOK
	if failed {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, map[string]any{"dry_run": dry, "applied": !dry && !failed, "sections": reports})
}

func (s *server) auditSimple(r *http.Request, action, targetType string, targets []string, details map[string]any) error {
	p := principalFrom(r)
	org := p.OrgID
	return s.auditWrite(r, audit.Entry{OrgID: &org, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r), Action: action,
		TargetType: targetType, TargetIDs: targets, Outcome: audit.Success, Details: details})
}

func (s *server) auditWrite(r *http.Request, e audit.Entry) error {
	return store.Tx(r.Context(), s.Pool, func(tx pgx.Tx, _ *dbq.Queries) error {
		_, err := audit.Write(r.Context(), tx, e, s.now())
		return err
	})
}

// POST /settings/notifications/test-email {"to": "..."}: sends a test message with the saved mail settings.
func (s *server) testEmail(w http.ResponseWriter, r *http.Request) {
	if !s.setSvc(w) || s.Notify == nil {
		return
	}
	var in struct {
		To string `json:"to"`
	}
	if !decode(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	err := s.Notify.TestEmail(ctx, principalFrom(r).OrgID, in.To)
	_ = s.auditResult(r, "settings.test_email", []string{"notifications"}, err)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "test_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /settings/integrations/webhooks/{id}/test
func (s *server) testWebhook(w http.ResponseWriter, r *http.Request) {
	if !s.setSvc(w) || s.Notify == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	err := s.Notify.TestWebhook(ctx, principalFrom(r).OrgID, chi.URLParam(r, "id"))
	_ = s.auditResult(r, "settings.test_webhook", []string{chi.URLParam(r, "id")}, err)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "test_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *server) auditResult(r *http.Request, action string, targets []string, err error) error {
	p := principalFrom(r)
	org := p.OrgID
	e := audit.Entry{OrgID: &org, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r), Action: action, TargetType: "settings", TargetIDs: targets, Outcome: audit.Success}
	if err != nil {
		e.Outcome = audit.Error
		e.Details = map[string]any{"error": err.Error()}
	}
	return s.auditWrite(r, e)
}

// GET /settings/notifications/log: recent deliveries and failures.
func (s *server) notificationLog(w http.ResponseWriter, r *http.Request) {
	limit := int32(50)
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 200 {
		limit = int32(v) // #nosec G109 G115 -- bounded to 1..200 above
	}
	rows, err := s.q().ListNotificationLog(r.Context(), dbq.ListNotificationLogParams{OrgID: principalFrom(r).OrgID, Limit: limit})
	if err != nil {
		internalError(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rows})
}

// GET /settings/events: the webhook event reference.
func (s *server) settingsEvents(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"events": settings.EventReference(), "signature": "HMAC-SHA256 of \"<X-" + brand.Name + "-Timestamp>.<body>\" with the webhook's secret, sent as X-" + brand.Name + "-Signature: sha256=<hex>"})
}
