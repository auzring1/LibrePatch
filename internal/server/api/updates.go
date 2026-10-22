package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/updates"
)

// updatesSvc is for the handlers that need the updates service but are not Windows update features (rings, restart,
// wake, the read-only views).
func (s *server) updatesSvc(w http.ResponseWriter) bool {
	if s.Updates == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "Windows Update management is not available.")
		return false
	}
	return true
}

// windowsUpdates guards every Windows update feature: it answers 404 when the organization has switched them off
// (Settings > Update defaults), so nothing here can scan, approve or install while the switch is off.
func (s *server) windowsUpdates(w http.ResponseWriter, r *http.Request) bool {
	if !s.updatesSvc(w) {
		return false
	}
	if !s.Updates.On(r.Context(), principalFrom(r).OrgID) {
		writeError(w, http.StatusNotFound, "windows_updates_off", "Windows updates are switched off for this organization (Settings, Update defaults).")
		return false
	}
	return true
}

func (s *server) actor(r *http.Request) updates.Actor {
	p := principalFrom(r)
	return updates.Actor{Org: p.OrgID, User: p.UserID, IP: clientIP(r)}
}

func idParam(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
		return uuid.Nil, false
	}
	return id, true
}

// updatesError maps the updates service's errors to HTTP responses.
func (s *server) updatesError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, updates.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", strings.TrimPrefix(err.Error(), updates.ErrInvalid.Error()+": "))
	case errors.Is(err, updates.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
	case errors.Is(err, updates.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", "An item with that name or order already exists.")
	case errors.Is(err, updates.ErrDisabled):
		writeError(w, http.StatusNotFound, "windows_updates_off", "Windows updates are switched off for this organization (Settings, Update defaults).")
	case errors.Is(err, updates.ErrOffline):
		writeError(w, http.StatusConflict, "device_offline", "The device is offline. A restart is only sent to a device that is connected.")
	default:
		s.Log.Error("updates", "err", err)
		internalError(w)
	}
}

type updateView struct {
	UpdateID             uuid.UUID  `json:"update_id"`
	Revision             int32      `json:"revision"`
	Title                string     `json:"title"`
	KB                   []string   `json:"kb"`
	Classification       string     `json:"classification"`
	Severity             string     `json:"severity"`
	Products             []string   `json:"products"`
	IsDriver             bool       `json:"is_driver"`
	ReleaseDate          *time.Time `json:"release_date"`
	RebootRequired       bool       `json:"reboot_required"`
	SupportURL           string     `json:"support_url"`
	FirstSeenAt          time.Time  `json:"first_seen_at"`
	Decision             string     `json:"decision"`
	DecisionSource       string     `json:"decision_source"`
	DecidedAt            *time.Time `json:"decided_at"`
	Note                 string     `json:"note"`
	DevicesMissing       int32      `json:"devices_missing"`
	DevicesPendingReboot int32      `json:"devices_pending_reboot"`
	DevicesInstalled     int32      `json:"devices_installed"`
	DevicesFailed        int32      `json:"devices_failed"`
	Holds                int32      `json:"holds"`
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// listUpdates: GET /updates
func (s *server) listUpdates(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	limit, offset, ok := paging(w, r, 100, 500)
	if !ok {
		return
	}
	qs := r.URL.Query()
	decision := qs.Get("decision")
	switch decision {
	case "", "pending", "approved", "declined", "hidden":
	default:
		badRequest(w, "decision must be pending, approved, declined or hidden")
		return
	}
	rows, err := s.q().ListUpdateCatalog(r.Context(), dbq.ListUpdateCatalogParams{OrgID: principalFrom(r).OrgID,
		Q: strings.ToLower(strings.TrimSpace(qs.Get("q"))), Classification: qs.Get("classification"), Severity: qs.Get("severity"), Decision: decision,
		OnlyMissing: qs.Get("missing") == "true", RowLimit: limit, RowOffset: offset})
	if err != nil {
		s.Log.Error("list updates", "err", err)
		internalError(w)
		return
	}
	items := make([]updateView, 0, len(rows))
	total := int32(0)
	for _, x := range rows {
		total = x.TotalCount
		items = append(items, updateView{UpdateID: x.UpdateID, Revision: x.Revision, Title: x.Title, KB: nz(x.Kb), Classification: x.Classification,
			Severity: x.Severity, Products: nz(x.Products), IsDriver: x.IsDriver, ReleaseDate: x.ReleaseDate, RebootRequired: x.RebootRequired,
			SupportURL: x.SupportUrl, FirstSeenAt: x.FirstSeenAt, Decision: x.Decision, DecisionSource: x.DecisionSource, DecidedAt: x.DecidedAt,
			Note: x.Note, DevicesMissing: x.DevicesMissing, DevicesPendingReboot: x.DevicesPendingReboot, DevicesInstalled: x.DevicesInstalled,
			DevicesFailed: x.DevicesFailed, Holds: x.Holds})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

// decideUpdates: POST /updates/decision
func (s *server) decideUpdates(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	var req struct {
		UpdateIDs []uuid.UUID `json:"update_ids"`
		Decision  string      `json:"decision"`
		Note      string      `json:"note"`
	}
	if !decode(w, r, &req) {
		return
	}
	res, err := s.Updates.Decide(r.Context(), s.actor(r), req.UpdateIDs, req.Decision, req.Note)
	if err != nil {
		s.updatesError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// updateDevices: GET /updates/{id}/devices
func (s *server) updateDevices(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	limit, offset, ok := paging(w, r, 200, 1000)
	if !ok {
		return
	}
	rows, err := s.q().ListUpdateDevices(r.Context(), dbq.ListUpdateDevicesParams{OrgID: principalFrom(r).OrgID, UpdateID: id, Limit: limit, Offset: offset})
	if err != nil {
		internalError(w)
		return
	}
	type view struct {
		DeviceID        uuid.UUID  `json:"device_id"`
		Hostname        string     `json:"hostname"`
		Online          bool       `json:"online"`
		State           string     `json:"state"`
		LastError       string     `json:"last_error"`
		ScannedAt       time.Time  `json:"scanned_at"`
		Revision        int32      `json:"revision"`
		AttemptState    string     `json:"attempt_state"`
		AttemptFailures int32      `json:"attempt_failures"`
		AttemptFinished *time.Time `json:"attempt_finished_at"`
		Ring            string     `json:"ring"`
	}
	items := make([]view, 0, len(rows))
	for _, x := range rows {
		items = append(items, view{x.DeviceID, x.Hostname, x.Online, x.State, x.LastError, x.ScannedAt, x.Revision, x.AttemptState, x.AttemptFailures, x.AttemptFinishedAt, x.RingName})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// installUpdate: POST /updates/{id}/install {device_ids?, restart?}
func (s *server) installUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var req struct {
		DeviceIDs []uuid.UUID       `json:"device_ids"`
		Restart   updates.RebootCfg `json:"restart"`
	}
	if !decode(w, r, &req) {
		return
	}
	n, err := s.Updates.InstallUpdate(r.Context(), s.actor(r), id, req.DeviceIDs, req.Restart)
	if err != nil {
		s.updatesError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int{"jobs": n})
}

func (s *server) getUpdateSettings(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, s.Updates.GetSettings(r.Context(), principalFrom(r).OrgID))
}

func (s *server) putUpdateSettings(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	var req updates.Settings
	if !decode(w, r, &req) {
		return
	}
	if err := s.Updates.SetSettings(r.Context(), s.actor(r), req); err != nil {
		s.updatesError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) listUpdateRules(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	items, err := s.Updates.ListRules(r.Context(), principalFrom(r).OrgID)
	if err != nil {
		s.updatesError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) createUpdateRule(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	var in updates.Rule
	if !decode(w, r, &in) {
		return
	}
	out, err := s.Updates.SaveRule(r.Context(), s.actor(r), nil, in)
	if err != nil {
		s.updatesError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *server) putUpdateRule(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in updates.Rule
	if !decode(w, r, &in) {
		return
	}
	out, err := s.Updates.SaveRule(r.Context(), s.actor(r), &id, in)
	if err != nil {
		s.updatesError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) deleteUpdateRule(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.Updates.DeleteRule(r.Context(), s.actor(r), id); err != nil {
		s.updatesError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) listUpdateRings(w http.ResponseWriter, r *http.Request) {
	if !s.updatesSvc(w) {
		return
	}
	items, err := s.Updates.ListRings(r.Context(), principalFrom(r).OrgID)
	if err != nil {
		s.updatesError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) createUpdateRing(w http.ResponseWriter, r *http.Request) {
	if !s.updatesSvc(w) {
		return
	}
	var in updates.Ring
	if !decode(w, r, &in) {
		return
	}
	out, err := s.Updates.SaveRing(r.Context(), s.actor(r), nil, in)
	if err != nil {
		s.updatesError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *server) putUpdateRing(w http.ResponseWriter, r *http.Request) {
	if !s.updatesSvc(w) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in updates.Ring
	if !decode(w, r, &in) {
		return
	}
	out, err := s.Updates.SaveRing(r.Context(), s.actor(r), &id, in)
	if err != nil {
		s.updatesError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) deleteUpdateRing(w http.ResponseWriter, r *http.Request) {
	if !s.updatesSvc(w) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.Updates.DeleteRing(r.Context(), s.actor(r), id); err != nil {
		s.updatesError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) listUpdateHolds(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	items, err := s.Updates.ListHolds(r.Context(), principalFrom(r).OrgID)
	if err != nil {
		s.updatesError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) releaseUpdateHold(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.Updates.ReleaseHold(r.Context(), s.actor(r), id); err != nil {
		s.updatesError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// updateConflicts: GET /update-conflicts — devices whose update policy is managed by something else.
func (s *server) updateConflicts(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	rows, err := s.q().CountPolicyConflicts(r.Context(), principalFrom(r).OrgID)
	if err != nil {
		internalError(w)
		return
	}
	type view struct {
		DeviceID uuid.UUID       `json:"device_id"`
		Hostname string          `json:"hostname"`
		Policy   json.RawMessage `json:"policy"`
	}
	items := make([]view, 0, len(rows))
	for _, x := range rows {
		items = append(items, view{x.ID, x.Hostname, x.WuPolicy})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// deviceWindowsUpdates: GET /devices/{id}/windows-updates
func (s *server) deviceWindowsUpdates(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	wu, err := s.q().GetDeviceWU(r.Context(), d.ID)
	if err != nil {
		internalError(w)
		return
	}
	rows, err := s.q().ListDeviceWUpdates(r.Context(), dbq.ListDeviceWUpdatesParams{OrgID: d.OrgID, DeviceID: d.ID})
	if err != nil {
		internalError(w)
		return
	}
	type view struct {
		UpdateID        uuid.UUID  `json:"update_id"`
		Revision        int32      `json:"revision"`
		State           string     `json:"state"`
		LastError       string     `json:"last_error"`
		Title           string     `json:"title"`
		KB              []string   `json:"kb"`
		Classification  string     `json:"classification"`
		Severity        string     `json:"severity"`
		IsDriver        bool       `json:"is_driver"`
		ReleaseDate     *time.Time `json:"release_date"`
		RebootRequired  bool       `json:"reboot_required"`
		SupportURL      string     `json:"support_url"`
		Decision        string     `json:"decision"`
		AttemptState    string     `json:"attempt_state"`
		AttemptFailures int32      `json:"attempt_failures"`
	}
	items := make([]view, 0, len(rows))
	for _, x := range rows {
		items = append(items, view{x.UpdateID, x.Revision, x.State, x.LastError, x.Title, nz(x.Kb), x.Classification, x.Severity, x.IsDriver, x.ReleaseDate,
			x.RebootRequired, x.SupportUrl, x.Decision, x.AttemptState, x.AttemptFailures})
	}
	// reboot_required is the live flag from the heartbeat, not the one saved with the last scan: a
	// restart since then must clear the banner without waiting for the next scan.
	writeJSON(w, http.StatusOK, map[string]any{"scanned_at": wu.WuScannedAt, "scan_error": wu.WuScanError, "reboot_required": d.PendingReboot,
		"policy": json.RawMessage(wu.WuPolicy), "service": wu.WuService, "truncated": wu.WuTruncated, "items": items})
}

func (s *server) deviceJobResponse(w http.ResponseWriter, id uuid.UUID, err error) {
	if err != nil {
		s.updatesError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]uuid.UUID{"job_id": id})
}

func (s *server) scanDeviceUpdates(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	id, err := s.Updates.ScanDevice(r.Context(), s.actor(r), d.ID)
	s.deviceJobResponse(w, id, err)
}

// scanDeviceUpdatesOnline: POST /devices/{id}/windows-updates/scan-online (updates:policy).
func (s *server) scanDeviceUpdatesOnline(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	id, err := s.Updates.ScanDeviceOnline(r.Context(), s.actor(r), d.ID)
	s.deviceJobResponse(w, id, err)
}

func (s *server) installDeviceUpdates(w http.ResponseWriter, r *http.Request) {
	s.installOnDevice(w, r, false)
}

// installDeviceUpdatesOnline: POST /devices/{id}/windows-updates/install-online (updates:policy).
func (s *server) installDeviceUpdatesOnline(w http.ResponseWriter, r *http.Request) {
	s.installOnDevice(w, r, true)
}

func (s *server) installOnDevice(w http.ResponseWriter, r *http.Request, online bool) {
	if !s.windowsUpdates(w, r) {
		return
	}
	var req struct {
		UpdateIDs []string          `json:"update_ids"`
		Restart   updates.RebootCfg `json:"restart"`
	}
	if !decode(w, r, &req) {
		return
	}
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	install := s.Updates.InstallOnDevice
	if online {
		install = s.Updates.InstallOnDeviceOnline
	}
	id, err := install(r.Context(), s.actor(r), d.ID, req.UpdateIDs, req.Restart)
	s.deviceJobResponse(w, id, err)
}

func (s *server) hideDeviceUpdates(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	var req struct {
		UpdateIDs []string `json:"update_ids"`
		Hide      bool     `json:"hide"`
	}
	if !decode(w, r, &req) {
		return
	}
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	id, err := s.Updates.HideOnDevice(r.Context(), s.actor(r), d.ID, req.UpdateIDs, req.Hide)
	s.deviceJobResponse(w, id, err)
}

func (s *server) rebootDevice(w http.ResponseWriter, r *http.Request) {
	if !s.updatesSvc(w) {
		return
	}
	var req struct {
		Minutes int    `json:"minutes"`
		Reason  string `json:"reason"`
	}
	if !decode(w, r, &req) {
		return
	}
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	id, err := s.Updates.RebootDevice(r.Context(), s.actor(r), d.ID, req.Minutes, req.Reason)
	s.deviceJobResponse(w, id, err)
}
