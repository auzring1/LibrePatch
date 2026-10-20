package api

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/server/updates"
)

// remoteError maps the errors of Wake-on-LAN and the read-only views (D125).
func (s *server) remoteError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, updates.ErrOffline):
		writeError(w, http.StatusConflict, "device_offline", "The device is offline. A view is only taken from a device that is connected.")
	case errors.Is(err, updates.ErrAlreadyOnline):
		writeError(w, http.StatusConflict, "already_online", "The device is already online.")
	case errors.Is(err, updates.ErrNoAddress):
		writeError(w, http.StatusConflict, "no_address", "The server does not know a network card address for this device yet. It learns it while the device is online.")
	case errors.Is(err, updates.ErrNoHelper):
		writeError(w, http.StatusConflict, "no_helper", "No other online computer with the current agent is on the same network as this device, so nothing can send the wake-up packet.")
	default:
		s.updatesError(w, err)
	}
}

// wakeDevice: POST /devices/{id}/wake (devices:wake). The wake-up packet is sent by another online computer on the same network.
func (s *server) wakeDevice(w http.ResponseWriter, r *http.Request) {
	if !s.updatesSvc(w) {
		return
	}
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	id, helper, err := s.Updates.WakeDevice(r.Context(), s.actor(r), d.ID)
	if err != nil {
		s.remoteError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": id, "helper": helper})
}

// inspectDevice: POST /devices/{id}/inspect (devices:inspect).
func (s *server) inspectDevice(w http.ResponseWriter, r *http.Request) {
	if !s.updatesSvc(w) {
		return
	}
	var req updates.InspectRequest
	if !decode(w, r, &req) {
		return
	}
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	id, err := s.Updates.InspectDevice(r.Context(), s.actor(r), d.ID, req)
	if err != nil {
		s.remoteError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]uuid.UUID{"job_id": id})
}

// deviceView: GET /devices/{id}/views/{job} (devices:inspect).
func (s *server) deviceView(w http.ResponseWriter, r *http.Request) {
	if !s.updatesSvc(w) {
		return
	}
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	job, err := uuid.Parse(chi.URLParam(r, "job"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
		return
	}
	v, err := s.Updates.GetView(r.Context(), principalFrom(r).OrgID, d.ID, job)
	if err != nil {
		s.remoteError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, v)
}
