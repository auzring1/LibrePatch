package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/server/agentrel"
	"github.com/auzring1/librepatch/internal/server/deploy"
)

func (s *server) relSvc(w http.ResponseWriter) bool {
	if s.Releases == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "Agent updates are not available.")
		return false
	}
	return true
}

func (s *server) relActor(r *http.Request) agentrel.Actor {
	p := principalFrom(r)
	return agentrel.Actor{Org: p.OrgID, User: p.UserID, IP: clientIP(r)}
}

func (s *server) relError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, agentrel.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", strings.TrimPrefix(err.Error(), agentrel.ErrInvalid.Error()+": "))
	case errors.Is(err, agentrel.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
	case errors.Is(err, agentrel.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", strings.TrimPrefix(err.Error(), agentrel.ErrConflict.Error()+": "))
	default:
		s.Log.Error("agent releases", "err", err)
		internalError(w)
	}
}

// GET /agent-releases — releases, the rollout setting and its progress.
func (s *server) listAgentReleases(w http.ResponseWriter, r *http.Request) {
	if !s.relSvc(w) {
		return
	}
	p := principalFrom(r)
	rels, ro, err := s.Releases.List(r.Context(), p.OrgID)
	if err != nil {
		s.relError(w, err)
		return
	}
	st, err := s.Releases.Status(r.Context(), p.OrgID)
	if err != nil {
		s.relError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rels, "rollout": ro, "status": st})
}

// POST /agent-releases — the agent binary as the raw body, the vendor bundle (.lprel) base64-encoded in X-Release-Bundle.
func (s *server) uploadAgentRelease(w http.ResponseWriter, r *http.Request) {
	if !s.relSvc(w) {
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/octet-stream") {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Send the binary as application/octet-stream.")
		return
	}
	bundle, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Release-Bundle"))
	if err != nil || len(bundle) == 0 {
		badRequest(w, "X-Release-Bundle must hold the base64-encoded release bundle (.lprel).")
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(15 * time.Minute))
	_ = rc.SetWriteDeadline(time.Now().Add(16 * time.Minute))
	rel, err := s.Releases.AddRelease(r.Context(), s.relActor(r), bundle, http.MaxBytesReader(w, r.Body, agentrel.MaxBinary+1))
	if err != nil {
		s.relError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, rel)
}

func (s *server) setAgentReleaseStatus(w http.ResponseWriter, r *http.Request) {
	if !s.relSvc(w) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in struct {
		Status string `json:"status"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := s.Releases.SetStatus(r.Context(), s.relActor(r), id, in.Status); err != nil {
		s.relError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) deleteAgentRelease(w http.ResponseWriter, r *http.Request) {
	if !s.relSvc(w) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.Releases.Delete(r.Context(), s.relActor(r), id); err != nil {
		s.relError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) getAgentRollout(w http.ResponseWriter, r *http.Request) {
	if !s.relSvc(w) {
		return
	}
	_, ro, err := s.Releases.List(r.Context(), principalFrom(r).OrgID)
	if err != nil {
		s.relError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ro)
}

type rolloutBody struct {
	ReleaseID        *uuid.UUID     `json:"release_id"`
	PilotGroupIDs    []uuid.UUID    `json:"pilot_group_ids"`
	SoakHours        int32          `json:"soak_hours"`
	SuccessThreshold int32          `json:"success_threshold"`
	BatchPerTick     int32          `json:"batch_per_tick"`
	Window           *deploy.Window `json:"window"`
	Paused           bool           `json:"paused"`
	AutoNewRelease   bool           `json:"auto_new_release"`
}

func (s *server) putAgentRollout(w http.ResponseWriter, r *http.Request) {
	if !s.relSvc(w) {
		return
	}
	var in rolloutBody
	if !decode(w, r, &in) {
		return
	}
	err := s.Releases.SetRollout(r.Context(), s.relActor(r), agentrel.Rollout{ReleaseID: in.ReleaseID, PilotGroupIDs: in.PilotGroupIDs, SoakHours: in.SoakHours,
		SuccessThreshold: in.SuccessThreshold, BatchPerTick: in.BatchPerTick, Window: in.Window, Paused: in.Paused, AutoNewRelease: in.AutoNewRelease})
	if err != nil {
		s.relError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
