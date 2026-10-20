package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/server/scripts"
)

func (s *server) scriptsSvc(w http.ResponseWriter) bool {
	if s.Scripts == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "Scripts are not available.")
		return false
	}
	return true
}

func (s *server) scriptsError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, scripts.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", strings.TrimPrefix(err.Error(), scripts.ErrInvalid.Error()+": "))
	case errors.Is(err, scripts.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
	case errors.Is(err, scripts.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", strings.TrimPrefix(err.Error(), scripts.ErrConflict.Error()+": "))
	case errors.Is(err, scripts.ErrForbidden):
		writeError(w, http.StatusForbidden, "forbidden", strings.TrimPrefix(err.Error(), scripts.ErrForbidden.Error()+": "))
	default:
		s.Log.Error("scripts", "err", err)
		internalError(w)
	}
}

func (s *server) scriptActor(r *http.Request) scripts.Actor {
	p := principalFrom(r)
	return scripts.Actor{Org: p.OrgID, User: p.UserID, IP: clientIP(r)}
}

func urlUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, name))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
		return uuid.Nil, false
	}
	return id, true
}

// GET /scripts
func (s *server) listScripts(w http.ResponseWriter, r *http.Request) {
	if !s.scriptsSvc(w) {
		return
	}
	items, err := s.Scripts.List(r.Context(), principalFrom(r).OrgID)
	if err != nil {
		s.scriptsError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// POST /scripts
func (s *server) createScript(w http.ResponseWriter, r *http.Request) {
	if !s.scriptsSvc(w) {
		return
	}
	var in scripts.Input
	if !decode(w, r, &in) {
		return
	}
	id, err := s.Scripts.Create(r.Context(), s.scriptActor(r), in)
	if err != nil {
		s.scriptsError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

// GET /scripts/{id}?version=n
func (s *server) getScript(w http.ResponseWriter, r *http.Request) {
	if !s.scriptsSvc(w) {
		return
	}
	id, ok := urlUUID(w, r, "id")
	if !ok {
		return
	}
	v, _ := strconv.Atoi(r.URL.Query().Get("version"))
	d, err := s.Scripts.Get(r.Context(), principalFrom(r).OrgID, id, int32(v)) // #nosec G115 -- a small number from a query
	if err != nil {
		s.scriptsError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, d)
}

// PUT /scripts/{id}
func (s *server) updateScript(w http.ResponseWriter, r *http.Request) {
	if !s.scriptsSvc(w) {
		return
	}
	id, ok := urlUUID(w, r, "id")
	if !ok {
		return
	}
	var in scripts.Input
	if !decode(w, r, &in) {
		return
	}
	v, err := s.Scripts.Update(r.Context(), s.scriptActor(r), id, in)
	if err != nil {
		s.scriptsError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": v})
}

// DELETE /scripts/{id}
func (s *server) deleteScript(w http.ResponseWriter, r *http.Request) {
	if !s.scriptsSvc(w) {
		return
	}
	id, ok := urlUUID(w, r, "id")
	if !ok {
		return
	}
	if err := s.Scripts.Delete(r.Context(), s.scriptActor(r), id); err != nil {
		s.scriptsError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /scripts/status
func (s *server) scriptStatus(w http.ResponseWriter, r *http.Request) {
	if !s.scriptsSvc(w) {
		return
	}
	p := principalFrom(r)
	writeJSON(w, http.StatusOK, map[string]any{"require_approval": s.Scripts.RequireApproval(r.Context(), p.OrgID),
		"other_approvers": s.Scripts.OtherApprovers(r.Context(), p.OrgID, p.UserID), "max_devices": scripts.MaxTargets})
}

// POST /scripts/runs
func (s *server) requestScriptRun(w http.ResponseWriter, r *http.Request) {
	if !s.scriptsSvc(w) {
		return
	}
	var in scripts.RunRequest
	if !decode(w, r, &in) {
		return
	}
	v, err := s.Scripts.RequestRun(r.Context(), s.scriptActor(r), in)
	if err != nil {
		s.scriptsError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

// GET /scripts/runs
func (s *server) listScriptRuns(w http.ResponseWriter, r *http.Request) {
	if !s.scriptsSvc(w) {
		return
	}
	items, err := s.Scripts.ListRuns(r.Context(), principalFrom(r).OrgID, 100)
	if err != nil {
		s.scriptsError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// GET /scripts/runs/{id}
func (s *server) getScriptRun(w http.ResponseWriter, r *http.Request) {
	if !s.scriptsSvc(w) {
		return
	}
	id, ok := urlUUID(w, r, "id")
	if !ok {
		return
	}
	d, err := s.Scripts.RunDetail(r.Context(), principalFrom(r).OrgID, id)
	if err != nil {
		s.scriptsError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, d)
}

func (s *server) decideScriptRun(w http.ResponseWriter, r *http.Request, f func(a scripts.Actor, id uuid.UUID, note string) (*scripts.RunView, error)) {
	if !s.scriptsSvc(w) {
		return
	}
	id, ok := urlUUID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Note string `json:"note"`
	}
	if r.ContentLength != 0 && !decode(w, r, &in) {
		return
	}
	v, err := f(s.scriptActor(r), id, in.Note)
	if err != nil {
		s.scriptsError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// POST /scripts/runs/{id}/approve
func (s *server) approveScriptRun(w http.ResponseWriter, r *http.Request) {
	s.decideScriptRun(w, r, func(a scripts.Actor, id uuid.UUID, note string) (*scripts.RunView, error) {
		return s.Scripts.Approve(r.Context(), a, id, note)
	})
}

// POST /scripts/runs/{id}/reject
func (s *server) rejectScriptRun(w http.ResponseWriter, r *http.Request) {
	s.decideScriptRun(w, r, func(a scripts.Actor, id uuid.UUID, note string) (*scripts.RunView, error) {
		return s.Scripts.Reject(r.Context(), a, id, note)
	})
}

// POST /scripts/runs/{id}/cancel
func (s *server) cancelScriptRun(w http.ResponseWriter, r *http.Request) {
	s.decideScriptRun(w, r, func(a scripts.Actor, id uuid.UUID, _ string) (*scripts.RunView, error) {
		return s.Scripts.Cancel(r.Context(), a, id)
	})
}

// GET /scripts/runs/{id}/jobs/{job}/output
func (s *server) scriptRunOutput(w http.ResponseWriter, r *http.Request) {
	if !s.scriptsSvc(w) {
		return
	}
	run, ok := urlUUID(w, r, "id")
	if !ok {
		return
	}
	job, ok := urlUUID(w, r, "job")
	if !ok {
		return
	}
	o, err := s.Scripts.GetOutput(r.Context(), principalFrom(r).OrgID, run, job)
	if err != nil {
		s.scriptsError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, o)
}
