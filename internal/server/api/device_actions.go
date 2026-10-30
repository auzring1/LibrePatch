package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/server/deploy"
)

// deviceActionError maps the deploy service's device-level errors to HTTP responses.
func (s *server) deviceActionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, deploy.ErrDeviceOffline):
		writeError(w, http.StatusConflict, "device_offline", "The device is offline. Try again when it is connected.")
	case errors.Is(err, deploy.ErrProfileInUse):
		writeError(w, http.StatusConflict, "profile_in_use", "That person is signed in on the device, so their profile cannot be removed. Sign them out first.")
	case errors.Is(err, deploy.ErrNotActive):
		writeError(w, http.StatusConflict, "not_active", "This device is not an active, enrolled device.")
	case errors.Is(err, deploy.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", strings.TrimPrefix(err.Error(), deploy.ErrInvalid.Error()+": "))
	default:
		s.Log.Error("device action", "err", err)
		internalError(w)
	}
}

// refreshDevice: POST /devices/{id}/refresh. The device re-sends hardware, software and users now.
func (s *server) refreshDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	id, err := s.Deploy.RequestRefresh(r.Context(), p.OrgID, p.UserID, d.ID, clientIP(r))
	if err != nil {
		s.deviceActionError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]uuid.UUID{"job_id": id})
}

// uninstallDeviceSoftware: POST /devices/{id}/software/uninstall.
func (s *server) uninstallDeviceSoftware(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Items []deploy.SoftwareRef `json:"items"`
	}
	if !decode(w, r, &req) {
		return
	}
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	res, err := s.Deploy.UninstallSoftware(r.Context(), p.OrgID, p.UserID, d.ID, clientIP(r), req.Items)
	if err != nil {
		s.deviceActionError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

// removeDeviceProfile: POST /devices/{id}/users/{sid}/remove-profile (devices:profiles). The person's Windows profile is
// removed on the device. It needs the device online, and the request must say it is confirmed.
func (s *server) removeDeviceProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Confirm bool `json:"confirm"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !req.Confirm {
		writeError(w, http.StatusUnprocessableEntity, "confirmation_required", "Removing a profile deletes the person's files on that computer; confirm it.")
		return
	}
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	id, err := s.Deploy.RemoveProfile(r.Context(), p.OrgID, p.UserID, d.ID, clientIP(r), chi.URLParam(r, "sid"))
	if err != nil {
		s.deviceActionError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]uuid.UUID{"job_id": id})
}

// deviceUpdates: GET /devices/{id}/updates.
func (s *server) deviceUpdates(w http.ResponseWriter, r *http.Request) {
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	items, checks, err := s.Deploy.DeviceUpdateReport(r.Context(), principalFrom(r).OrgID, d.ID)
	if err != nil {
		s.deviceActionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "checks": checks})
}

// fleetSoftwareUpdates: GET /software/updates. The catalog packages that are out of date on at least one active
// device, with the devices that have an older version.
func (s *server) fleetSoftwareUpdates(w http.ResponseWriter, r *http.Request) {
	items, err := s.Deploy.FleetUpdates(r.Context(), principalFrom(r).OrgID)
	if err != nil {
		s.Log.Error("fleet software updates", "err", err)
		internalError(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
