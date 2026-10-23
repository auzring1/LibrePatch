package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/server/dashboard"
	"github.com/auzring1/librepatch/internal/server/policies"
)

func (s *server) polSvc(w http.ResponseWriter) bool {
	if s.Policies == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "Software policies are not available.")
		return false
	}
	return true
}

func (s *server) polError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, policies.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", strings.TrimPrefix(err.Error(), policies.ErrInvalid.Error()+": "))
	case errors.Is(err, policies.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
	case errors.Is(err, policies.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", strings.TrimPrefix(err.Error(), policies.ErrConflict.Error()+": "))
	default:
		s.Log.Error("policies", "err", err)
		internalError(w)
	}
}

func (s *server) polActor(r *http.Request) policies.Actor {
	p := principalFrom(r)
	return policies.Actor{Org: p.OrgID, User: p.UserID, IP: clientIP(r)}
}

func (s *server) listPolicies(w http.ResponseWriter, r *http.Request) {
	if !s.polSvc(w) {
		return
	}
	items, err := s.Policies.List(r.Context(), principalFrom(r).OrgID)
	if err != nil {
		s.polError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// mayImport reports whether the caller may make a policy that adds apps to the catalog by itself (all-apps policies with
// "add apps from winget"): that is a catalog change, so it needs catalog:write as well as policies:write (D132).
func (s *server) mayImport(w http.ResponseWriter, r *http.Request, in *policies.Input) bool {
	if in.Kind != policies.KindAll || in.Filter == nil || !in.Filter.IncludeUnlisted {
		return true
	}
	if !principalFrom(r).Access.OrgHas(auth.PermCatalogWrite) {
		writeError(w, http.StatusForbidden, "forbidden", "Adding apps from the winget index to the catalog needs the catalog:write permission.")
		return false
	}
	return true
}

func (s *server) createPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.polSvc(w) {
		return
	}
	var in policies.Input
	if !decode(w, r, &in) {
		return
	}
	if !s.mayImport(w, r, &in) {
		return
	}
	id, err := s.Policies.Create(r.Context(), s.polActor(r), in)
	if err != nil {
		s.polError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.polSvc(w) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in policies.Input
	if !decode(w, r, &in) {
		return
	}
	if !s.mayImport(w, r, &in) {
		return
	}
	if err := s.Policies.Update(r.Context(), s.polActor(r), id, in); err != nil {
		s.polError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// previewPolicy lists the apps an all-apps policy would handle with the groups and filter in the request.
func (s *server) previewPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.polSvc(w) {
		return
	}
	var in struct {
		ID       uuid.UUID            `json:"id"`
		GroupIDs []uuid.UUID          `json:"group_ids"`
		Filter   *policies.AutoFilter `json:"filter"`
	}
	if !decode(w, r, &in) {
		return
	}
	f := policies.AutoFilter{VerifiedOnly: true}
	if in.Filter != nil {
		f = *in.Filter
	}
	res, err := s.Policies.Preview(r.Context(), principalFrom(r).OrgID, in.ID, in.GroupIDs, f)
	if err != nil {
		s.polError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// policyApps lists the apps an all-apps policy handles.
func (s *server) policyApps(w http.ResponseWriter, r *http.Request) {
	if !s.polSvc(w) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	items, err := s.Policies.Apps(r.Context(), principalFrom(r).OrgID, id)
	if err != nil {
		s.polError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.polSvc(w) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.Policies.Delete(r.Context(), s.polActor(r), id); err != nil {
		s.polError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- compliance report ----

const staleAfter = dashboard.StaleAfter

type complianceRow struct {
	DeviceID        string     `json:"device_id"`
	Hostname        string     `json:"hostname"`
	SiteID          string     `json:"site_id"`
	OS              string     `json:"os"`
	OSBuild         string     `json:"os_build"`
	AgentVersion    string     `json:"agent_version"`
	Online          bool       `json:"online"`
	LastSeenAt      *time.Time `json:"last_seen_at"`
	LastScanAt      *time.Time `json:"last_scan_at"`
	ApprovedMissing int32      `json:"approved_missing"`
	CriticalMissing int32      `json:"critical_missing"`
	FailedUpdates   int32      `json:"failed_updates"`
	RebootPending   bool       `json:"reboot_pending"`
	State           string     `json:"state"` // compliant | non_compliant | unknown
}

// complianceState: non-compliant when an approved or critical update is missing or an install failed;
// unknown when the device has never scanned or its scan is more than a week old; otherwise compliant.
func complianceState(r dbq.ComplianceReportRow, now time.Time) string { return dashboard.State(r, now) }

func (s *server) complianceRows(r *http.Request) ([]complianceRow, error) {
	rows, err := s.q().ComplianceReport(r.Context(), principalFrom(r).OrgID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]complianceRow, 0, len(rows))
	for _, x := range rows {
		out = append(out, complianceRow{DeviceID: x.ID.String(), Hostname: x.Hostname, SiteID: x.SiteID.String(), OS: x.OsCaption, OSBuild: x.OsBuild, AgentVersion: x.AgentVersion,
			Online: x.Online, LastSeenAt: x.LastSeenAt, LastScanAt: x.WuScannedAt, ApprovedMissing: x.ApprovedMissing, CriticalMissing: x.CriticalMissing,
			FailedUpdates: x.FailedUpdates, RebootPending: x.RebootPending != nil && *x.RebootPending, State: complianceState(x, now)})
	}
	return out, nil
}

// reportOverview: GET /reports/overview — fleet health at a glance.
func (s *server) reportOverview(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	rows, err := s.complianceRows(r)
	if err != nil {
		internalError(w)
		return
	}
	counts, err := s.q().ReportDeviceCounts(r.Context(), dbq.ReportDeviceCountsParams{OrgID: p.OrgID, StaleBefore: s.now().Add(-staleAfter)})
	if err != nil {
		internalError(w)
		return
	}
	comp := map[string]int{"compliant": 0, "non_compliant": 0, "unknown": 0}
	reboot := 0
	for _, x := range rows {
		comp[x.State]++
		if x.RebootPending {
			reboot++
		}
	}
	jobs, err := s.q().ReportJobCounts(r.Context(), dbq.ReportJobCountsParams{OrgID: p.OrgID, CreatedAt: s.now().Add(-30 * 24 * time.Hour)})
	if err != nil {
		internalError(w)
		return
	}
	type jc struct {
		Type   string `json:"type"`
		Status string `json:"status"`
		Count  int64  `json:"count"`
	}
	jl := make([]jc, 0, len(jobs))
	for _, j := range jobs {
		jl = append(jl, jc{j.Type, j.Status, j.N})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"devices":    map[string]any{"active": counts.Active, "pending": counts.Pending, "revoked": counts.Revoked, "online": counts.Online, "not_seen_for_a_week": counts.Stale, "reboot_pending": reboot},
		"compliance": comp,
		"jobs_30d":   jl,
		"generated":  s.now(),
	})
}

func (s *server) reportCompliance(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	rows, err := s.complianceRows(r)
	if err != nil {
		internalError(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rows})
}

func (s *server) complianceCSV(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	rows, err := s.complianceRows(r)
	if err != nil {
		internalError(w)
		return
	}
	cw, ok := s.startCSV(w, r, "compliance", map[string]any{})
	if !ok {
		return
	}
	_ = csvRow(cw, "hostname", "state", "approved_updates_missing", "critical_updates_missing", "failed_updates", "restart_pending", "last_scan", "last_seen", "online", "os", "os_build", "agent_version")
	ts := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	}
	for _, x := range rows {
		if csvRow(cw, x.Hostname, x.State, strconv.Itoa(int(x.ApprovedMissing)), strconv.Itoa(int(x.CriticalMissing)), strconv.Itoa(int(x.FailedUpdates)),
			strconv.FormatBool(x.RebootPending), ts(x.LastScanAt), ts(x.LastSeenAt), strconv.FormatBool(x.Online), x.OS, x.OSBuild, x.AgentVersion) != nil {
			return
		}
	}
	cw.Flush()
}

// softwareApprovals: GET /software/approvals — versions waiting for a decision, recent decisions and open holds.
func (s *server) softwareApprovals(w http.ResponseWriter, r *http.Request) {
	if !s.polSvc(w) {
		return
	}
	q, err := s.Policies.Queue(r.Context(), principalFrom(r).OrgID)
	if err != nil {
		s.polError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, q)
}

// decideSoftware: POST /software/approvals — approve or decline one version of a package, or put it back to waiting.
func (s *server) decideSoftware(w http.ResponseWriter, r *http.Request) {
	if !s.polSvc(w) {
		return
	}
	var in struct {
		PackageID uuid.UUID `json:"package_id"`
		Version   string    `json:"version"`
		Decision  string    `json:"decision"`
		Note      string    `json:"note"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := s.Policies.Decide(r.Context(), s.polActor(r), in.PackageID, in.Version, in.Decision, in.Note); err != nil {
		s.polError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// releaseSoftwareHold: POST /software/holds/{id}/release
func (s *server) releaseSoftwareHold(w http.ResponseWriter, r *http.Request) {
	if !s.polSvc(w) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.Policies.ReleaseHold(r.Context(), s.polActor(r), id); err != nil {
		s.polError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
