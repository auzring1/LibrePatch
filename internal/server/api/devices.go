package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/events"
	"github.com/auzring1/librepatch/internal/server/store"
)

type deviceView struct {
	// Custom holds the values of the organization's custom device fields (Settings > Device defaults); present in lists only.
	Custom             map[string]string `json:"custom,omitempty"`
	ID                 uuid.UUID         `json:"id"`
	SiteID             uuid.UUID         `json:"site_id"`
	Status             string            `json:"status"`
	StatusReason       string            `json:"status_reason"`
	RevokePending      bool              `json:"revoke_pending"`
	Hostname           string            `json:"hostname"`
	OSCaption          string            `json:"os_caption"`
	OSBuild            string            `json:"os_build"`
	Arch               string            `json:"arch"`
	AgentVersion       string            `json:"agent_version"`
	Manufacturer       string            `json:"manufacturer"`
	Model              string            `json:"model"`
	Serial             string            `json:"serial"`
	Online             bool              `json:"online"`
	LastSeenAt         *time.Time        `json:"last_seen_at"`
	LastIP             string            `json:"last_ip"`
	EnrolledAt         time.Time         `json:"enrolled_at"`
	ApprovedAt         *time.Time        `json:"approved_at"`
	RevokedAt          *time.Time        `json:"revoked_at"`
	UptimeS            int64             `json:"uptime_s"`
	PendingReboot      bool              `json:"pending_reboot"`
	LoggedOnUser       string            `json:"logged_on_user"`
	PeerPort           int32             `json:"peer_port"`
	ReplacesDeviceID   *uuid.UUID        `json:"replaces_device_id"`
	Chassis            string            `json:"chassis"`
	SoftwareCount      int32             `json:"software_count"`
	SoftwareUpdatedAt  *time.Time        `json:"software_updated_at"`
	InventoryTruncated bool              `json:"inventory_truncated"`
	Hardware           json.RawMessage   `json:"hardware,omitempty"`
	Certificates       []certView        `json:"certificates,omitempty"`
}

type certView struct {
	Serial    string     `json:"serial"`
	NotBefore time.Time  `json:"not_before"`
	NotAfter  time.Time  `json:"not_after"`
	RevokedAt *time.Time `json:"revoked_at"`
}

func (s *server) listDevices(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	limit, offset, ok := paging(w, r, 100, 500)
	if !ok {
		return
	}
	var status *string
	if v := r.URL.Query().Get("status"); v != "" {
		switch v {
		case "pending", "active", "revoked", "retired":
			status = &v
		default:
			badRequest(w, "status must be one of pending, active, revoked, retired")
			return
		}
	}
	q := s.q()
	// A caller with only site-limited rights sees just the devices of those sites.
	var sites []uuid.UUID
	if all, ids := p.Access.SitesFor(auth.PermDevicesRead); !all {
		sites = append([]uuid.UUID{}, ids...)
	}
	rows, err := q.ListDevices(r.Context(), dbq.ListDevicesParams{OrgID: p.OrgID, Limit: limit, Offset: offset, Status: status, SiteIds: sites})
	if err != nil {
		s.Log.Error("list devices", "err", err)
		internalError(w)
		return
	}
	total, err := q.CountDevices(r.Context(), dbq.CountDevicesParams{OrgID: p.OrgID, Status: status, SiteIds: sites})
	if err != nil {
		internalError(w)
		return
	}
	items := make([]deviceView, 0, len(rows))
	for _, d := range rows {
		items = append(items, deviceView{ID: d.ID, SiteID: d.SiteID, Status: d.Status, StatusReason: d.StatusReason,
			Hostname: d.Hostname, OSCaption: d.OsCaption, OSBuild: d.OsBuild, Arch: d.Arch, AgentVersion: d.AgentVersion,
			Manufacturer: d.Manufacturer, Model: d.Model, Serial: d.Serial, Online: d.Online, LastSeenAt: d.LastSeenAt,
			LastIP: d.LastIp, EnrolledAt: d.EnrolledAt, ApprovedAt: d.ApprovedAt, RevokedAt: d.RevokedAt,
			UptimeS: d.UptimeS, PendingReboot: d.PendingReboot, LoggedOnUser: d.LoggedOnUser, ReplacesDeviceID: d.ReplacesDeviceID,
			Chassis: d.Chassis, SoftwareCount: d.SoftwareCount, SoftwareUpdatedAt: d.SoftwareUpdatedAt})
	}
	if s.Settings != nil && len(s.Settings.Values(r.Context(), p.OrgID, "devices").Items("custom_fields")) > 0 && len(rows) > 0 {
		ids := make([]uuid.UUID, 0, len(rows))
		pos := map[uuid.UUID]int{}
		for i, d := range rows {
			ids = append(ids, d.ID)
			pos[d.ID] = i
		}
		if cv, err := q.ListCustomValuesForDevices(r.Context(), ids); err == nil {
			for _, v := range cv {
				i := pos[v.DeviceID]
				if items[i].Custom == nil {
					items[i].Custom = map[string]string{}
				}
				items[i].Custom[v.FieldKey] = v.Value
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func (s *server) deviceFromURL(w http.ResponseWriter, r *http.Request) (dbq.Device, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Device not found.")
		return dbq.Device{}, false
	}
	d, err := s.q().GetDeviceInOrg(r.Context(), dbq.GetDeviceInOrgParams{ID: id, OrgID: principalFrom(r).OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "not_found", "Device not found.")
		return d, false
	} else if err != nil {
		internalError(w)
		return d, false
	}
	return d, true
}

func (s *server) getDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	v := deviceView{ID: d.ID, SiteID: d.SiteID, Status: d.Status, StatusReason: d.StatusReason, Hostname: d.Hostname,
		OSCaption: d.OsCaption, OSBuild: d.OsBuild, Arch: d.Arch, AgentVersion: d.AgentVersion, Serial: d.Serial,
		Online: d.Online, LastSeenAt: d.LastSeenAt, LastIP: d.LastIp, EnrolledAt: d.EnrolledAt, ApprovedAt: d.ApprovedAt,
		RevokedAt: d.RevokedAt, UptimeS: d.UptimeS, PendingReboot: d.PendingReboot, LoggedOnUser: d.LoggedOnUser, PeerPort: d.PeerPort,
		ReplacesDeviceID: d.ReplacesDeviceID, Certificates: []certView{}, Chassis: d.Chassis,
		SoftwareCount: d.SoftwareCount, SoftwareUpdatedAt: d.SoftwareUpdatedAt, InventoryTruncated: d.InventoryTruncated}
	if d.Status == "active" {
		_, perr := s.q().OpenAgentUninstall(r.Context(), d.ID)
		v.RevokePending = perr == nil
	}
	if len(d.Hardware) > 0 {
		v.Hardware = d.Hardware
		var hw struct {
			Manufacturer string `json:"manufacturer"`
			Model        string `json:"model"`
		}
		_ = json.Unmarshal(d.Hardware, &hw)
		v.Manufacturer, v.Model = hw.Manufacturer, hw.Model
	}
	rows, err := s.Pool.Query(r.Context(),
		`SELECT serial, not_before, not_after, revoked_at FROM device_certs WHERE device_id = $1 ORDER BY issued_at DESC LIMIT 20`, d.ID)
	if err == nil {
		for rows.Next() {
			var c certView
			if rows.Scan(&c.Serial, &c.NotBefore, &c.NotAfter, &c.RevokedAt) == nil {
				v.Certificates = append(v.Certificates, c)
			}
		}
		rows.Close()
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *server) approveDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	now := s.now()
	// The enrolling agent chooses the hardware identity that links it to an older device. Whoever approves
	// must also be allowed to retire that older device, or a site-limited approver could revoke another
	// site's machine by naming it.
	if d.ReplacesDeviceID != nil {
		old, err := s.q().GetDeviceInOrg(r.Context(), dbq.GetDeviceInOrgParams{ID: *d.ReplacesDeviceID, OrgID: p.OrgID})
		if err == nil && !p.Access.SiteHas(old.SiteID, auth.PermDevicesWrite) {
			writeError(w, http.StatusForbidden, "forbidden", "This enrollment claims to replace a device at a site you cannot manage. Ask an administrator to approve it.")
			return
		} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			internalError(w)
			return
		}
	}
	var replaced *uuid.UUID
	err := store.Tx(r.Context(), s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		n, err := q.ApproveDevice(r.Context(), dbq.ApproveDeviceParams{ID: d.ID, OrgID: p.OrgID, ApprovedBy: &p.UserID, ApprovedAt: &now})
		if err != nil {
			return err
		}
		if n == 0 {
			return errConflict
		}
		// Re-enrollment of known hardware: approving the new identity retires the old one.
		if d.ReplacesDeviceID != nil {
			if _, err := q.RevokeDevice(r.Context(), dbq.RevokeDeviceParams{ID: *d.ReplacesDeviceID, OrgID: p.OrgID,
				StatusReason: "replaced by re-enrollment " + d.ID.String(), RevokedBy: &p.UserID, RevokedAt: &now}); err != nil {
				return err
			}
			if err := q.RevokeDeviceCerts(r.Context(), dbq.RevokeDeviceCertsParams{DeviceID: *d.ReplacesDeviceID, RevokedAt: &now, RevokeReason: "replaced"}); err != nil {
				return err
			}
			replaced = d.ReplacesDeviceID
		}
		details := map[string]any{"hostname": d.Hostname}
		if replaced != nil {
			details["replaced_device_id"] = replaced.String()
		}
		_, err = audit.Write(r.Context(), tx, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(),
			ActorIP: clientIP(r), Action: "device.approve", TargetType: "device", TargetIDs: []string{d.ID.String()},
			Outcome: audit.Success, Details: details}, now)
		return err
	})
	if errors.Is(err, errConflict) {
		writeError(w, http.StatusConflict, "not_pending", "Only pending devices can be approved.")
		return
	} else if err != nil {
		s.Log.Error("approve device", "err", err)
		internalError(w)
		return
	}
	if replaced != nil {
		s.Devices.Disconnect(*replaced, "replaced")
		s.Events.Publish(p.OrgID, events.Event{Type: events.DeviceUpdated, DeviceID: *replaced})
	}
	s.Events.Publish(p.OrgID, events.Event{Type: events.DeviceUpdated, DeviceID: d.ID})
	w.WriteHeader(http.StatusNoContent)
}

type revokeReq struct {
	Reason string `json:"reason"`
	// UninstallAgent asks the device to uninstall its agent first and be revoked once it has (D158). The device is not revoked
	// until then, so the answer is 202 and the device page shows the revoke as pending.
	UninstallAgent bool `json:"uninstall_agent"`
}

func (s *server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	var req revokeReq
	if !decode(w, r, &req) {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if utf8.RuneCountInString(req.Reason) > 500 {
		badRequest(w, "reason must be at most 500 characters")
		return
	}
	if req.Reason == "" {
		req.Reason = "revoked by administrator"
	}
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	// Only an enrolled, active device has an agent that can be told to uninstall itself; a pending one is just rejected.
	if req.UninstallAgent && d.Status == "active" {
		id, err := s.Deploy.RequestRevokeWithUninstall(r.Context(), p.OrgID, p.UserID, d.ID, clientIP(r), req.Reason)
		if err != nil {
			s.deviceActionError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"job_id": id, "pending": true})
		return
	}
	// A plain revoke also drops an "uninstall, then revoke" request that was still waiting.
	if err := s.Deploy.CancelPendingUninstall(r.Context(), p.OrgID, p.UserID, d.ID, clientIP(r)); err != nil {
		s.Log.Error("cancel pending agent uninstall", "err", err)
	}
	err := s.Deploy.RevokeDevice(r.Context(), p.OrgID, &p.UserID, d.ID, req.Reason, clientIP(r), nil)
	if errors.Is(err, deploy.ErrAlreadyRevoked) {
		writeError(w, http.StatusConflict, "already_revoked", "Device is already revoked or retired.")
		return
	} else if err != nil {
		s.Log.Error("revoke device", "err", err)
		internalError(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

var errConflict = errors.New("conflict")

// removeDevice deletes one revoked device and its data, auditing it. Reports false when the device
// is not in a deletable state (still pending or active, or not found).
func (s *server) removeDevice(r *http.Request, p *Principal, d dbq.Device) (bool, error) {
	now := s.now()
	deleted := false
	err := store.Tx(r.Context(), s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.DeleteDeviceCerts(r.Context(), d.ID); err != nil {
			return err
		}
		if err := q.ClearReplacesDevice(r.Context(), &d.ID); err != nil {
			return err
		}
		n, err := q.DeleteDevice(r.Context(), dbq.DeleteDeviceParams{ID: d.ID, OrgID: p.OrgID})
		if err != nil {
			return err
		}
		if n == 0 {
			return errConflict // rolls back the certificate delete too
		}
		deleted = true
		_, err = audit.Write(r.Context(), tx, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(),
			ActorIP: clientIP(r), Action: "device.delete", TargetType: "device", TargetIDs: []string{d.ID.String()},
			Outcome: audit.Success, Details: map[string]any{"hostname": d.Hostname, "status": d.Status}}, now)
		return err
	})
	if errors.Is(err, errConflict) {
		return false, nil
	}
	return deleted, err
}

// deleteDevice: DELETE /devices/{id}. The device must be revoked first.
func (s *server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	done, err := s.removeDevice(r, p, d)
	switch {
	case err != nil:
		s.Log.Error("delete device", "err", err)
		internalError(w)
	case !done:
		writeError(w, http.StatusConflict, "not_revoked", "Revoke the device before deleting it.")
	default:
		s.Events.Publish(p.OrgID, events.Event{Type: events.DeviceUpdated, DeviceID: d.ID})
		w.WriteHeader(http.StatusNoContent)
	}
}

// deleteDevices: POST /devices/delete {ids}. Deletes every listed device that is revoked and
// reports how many it removed and how many it skipped (not revoked or not found).
func (s *server) deleteDevices(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []uuid.UUID `json:"ids"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > 500 {
		badRequest(w, "ids must list between 1 and 500 devices")
		return
	}
	p := principalFrom(r)
	deleted, skipped := 0, 0
	for _, id := range req.IDs {
		d, err := s.q().GetDeviceInOrg(r.Context(), dbq.GetDeviceInOrgParams{ID: id, OrgID: p.OrgID})
		if err != nil {
			skipped++
			continue
		}
		if !p.Access.SiteHas(d.SiteID, auth.PermDevicesWrite) {
			skipped++
			continue
		}
		done, err := s.removeDevice(r, p, d)
		if err != nil {
			s.Log.Error("delete device", "err", err)
			internalError(w)
			return
		}
		if done {
			deleted++
			s.Events.Publish(p.OrgID, events.Event{Type: events.DeviceUpdated, DeviceID: d.ID})
		} else {
			skipped++
		}
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": deleted, "skipped": skipped})
}

func paging(w http.ResponseWriter, r *http.Request, def, max int32) (int32, int32, bool) {
	limit, offset := def, int32(0)
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n < 1 || n > int64(max) {
			badRequest(w, "limit must be between 1 and "+strconv.Itoa(int(max)))
			return 0, 0, false
		}
		limit = int32(n)
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n < 0 || n > 10_000_000 {
			badRequest(w, "offset must be a non-negative integer")
			return 0, 0, false
		}
		offset = int32(n)
	}
	return limit, offset, true
}
