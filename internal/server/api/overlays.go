package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/catalog"
)

func (s *server) overlayError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, catalog.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "invalid_overlay", strings.TrimPrefix(err.Error(), catalog.ErrInvalid.Error()+": "))
	case errors.Is(err, catalog.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
	case errors.Is(err, catalog.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", strings.TrimPrefix(err.Error(), catalog.ErrConflict.Error()+": "))
	default:
		s.Log.Error("catalog overlay", "err", err)
		internalError(w)
	}
}

func (s *server) overlayAudit(r *http.Request, action, id string, details map[string]any) {
	p := principalFrom(r)
	_ = audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r),
		Action: action, TargetType: "catalog_overlay", TargetIDs: []string{id}, Outcome: audit.Success, Details: details})
}

// GET /catalog/overlays: the overlay sources, highest priority first, and how many entries the built-in overlay has.
func (s *server) listOverlays(w http.ResponseWriter, r *http.Request) {
	if !s.catalogSvc(w) {
		return
	}
	items, err := s.Catalog.ListOverlays(r.Context(), principalFrom(r).OrgID)
	if err != nil {
		s.overlayError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "builtin_entries": len(s.Catalog.Overlay.Known())})
}

// POST /catalog/overlays: add a source, from an uploaded signed file or a URL, under the public key of its author.
func (s *server) addOverlay(w http.ResponseWriter, r *http.Request) {
	if !s.catalogSvc(w) {
		return
	}
	var in struct {
		Label     string `json:"label"`
		PublicKey string `json:"public_key"`
		URL       string `json:"url"`
		Bundle    string `json:"bundle"`
	}
	if !decode(w, r, &in) {
		return
	}
	p := principalFrom(r)
	v, err := s.Catalog.AddOverlay(r.Context(), p.OrgID, p.UserID, in.Label, in.PublicKey, in.URL, []byte(in.Bundle))
	if err != nil {
		s.overlayError(w, err)
		return
	}
	s.overlayAudit(r, "catalog.overlay_add", v.ID.String(), map[string]any{"label": v.Label, "kind": v.Kind, "url": v.URL, "key_id": v.KeyID, "document": v.DocName, "version": v.DocVersion, "entries": v.Entries})
	writeJSON(w, http.StatusCreated, v)
}

// PUT /catalog/overlays/{id}: rename, switch on or off, change the priority or the address.
func (s *server) updateOverlay(w http.ResponseWriter, r *http.Request) {
	if !s.catalogSvc(w) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in struct {
		Label    string `json:"label"`
		Enabled  bool   `json:"enabled"`
		Priority int32  `json:"priority"`
		URL      string `json:"url"`
	}
	if !decode(w, r, &in) {
		return
	}
	v, err := s.Catalog.UpdateOverlay(r.Context(), principalFrom(r).OrgID, id, in.Label, in.Enabled, in.Priority, in.URL)
	if err != nil {
		s.overlayError(w, err)
		return
	}
	s.overlayAudit(r, "catalog.overlay_update", id.String(), map[string]any{"label": v.Label, "enabled": v.Enabled, "priority": v.Priority, "url": v.URL})
	writeJSON(w, http.StatusOK, v)
}

// POST /catalog/overlays/{id}/upload: load a newer signed file into a source.
func (s *server) uploadOverlay(w http.ResponseWriter, r *http.Request) {
	if !s.catalogSvc(w) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in struct {
		Bundle string `json:"bundle"`
	}
	if !decode(w, r, &in) {
		return
	}
	ch, err := s.Catalog.ReplaceOverlay(r.Context(), principalFrom(r).OrgID, id, []byte(in.Bundle))
	if err != nil {
		s.overlayError(w, err)
		return
	}
	s.overlayAudit(r, "catalog.overlay_replace", id.String(), map[string]any{"label": ch.Label, "version": ch.DocVersion, "entries": ch.Entries, "changed": ch.Changed})
	writeJSON(w, http.StatusOK, map[string]any{"changed": ch.Changed, "version": ch.DocVersion, "entries": ch.Entries})
}

// POST /catalog/overlays/{id}/refresh: ask a URL source for a newer document now.
func (s *server) refreshOverlay(w http.ResponseWriter, r *http.Request) {
	if !s.catalogSvc(w) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	ch, err := s.Catalog.RefreshOverlay(r.Context(), principalFrom(r).OrgID, id)
	if err != nil {
		s.overlayError(w, err)
		return
	}
	s.overlayAudit(r, "catalog.overlay_refresh", id.String(), map[string]any{"label": ch.Label, "version": ch.DocVersion, "entries": ch.Entries, "changed": ch.Changed})
	writeJSON(w, http.StatusOK, map[string]any{"changed": ch.Changed, "version": ch.DocVersion, "entries": ch.Entries})
}

// DELETE /catalog/overlays/{id}
func (s *server) deleteOverlay(w http.ResponseWriter, r *http.Request) {
	if !s.catalogSvc(w) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	label, err := s.Catalog.DeleteOverlay(r.Context(), principalFrom(r).OrgID, id)
	if err != nil {
		s.overlayError(w, err)
		return
	}
	s.overlayAudit(r, "catalog.overlay_delete", id.String(), map[string]any{"label": label})
	w.WriteHeader(http.StatusNoContent)
}

// GET /catalog/overlay-template: an unsigned overlay document built from what this organization already set by hand.
func (s *server) overlayTemplate(w http.ResponseWriter, r *http.Request) {
	if !s.catalogSvc(w) {
		return
	}
	p := principalFrom(r)
	name := ""
	if o, err := dbq.New(s.Pool).GetOrganization(r.Context(), p.OrgID); err == nil {
		name = o.Name
	}
	doc, err := s.Catalog.Template(r.Context(), p.OrgID, name)
	if err != nil {
		s.overlayError(w, err)
		return
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="overlay.json"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(append(b, '\n'))
}
