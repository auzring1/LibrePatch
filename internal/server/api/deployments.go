package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/server/deploy"
)

type deploymentReq struct {
	Name                string          `json:"name"`
	Action              string          `json:"action"`
	PackageID           uuid.UUID       `json:"package_id"`
	Version             string          `json:"version"`
	Scope               string          `json:"scope"`
	GroupIDs            []uuid.UUID     `json:"group_ids"`
	DeviceIDs           []uuid.UUID     `json:"device_ids"`
	StartsAt            *time.Time      `json:"starts_at"`
	ExpiresInHours      int             `json:"expires_in_hours"`
	Window              *deploy.Window  `json:"window"`
	UnverifiedConfirmed bool            `json:"unverified_confirmed"`
	Prompts             *deploy.Prompts `json:"prompts"`
}

func (s *server) deploySvc(w http.ResponseWriter) bool {
	if s.Deploy == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "Deployments are not available.")
		return false
	}
	return true
}

func (s *server) createDeployment(w http.ResponseWriter, r *http.Request) {
	if !s.deploySvc(w) {
		return
	}
	var req deploymentReq
	if !decode(w, r, &req) {
		return
	}
	p := principalFrom(r)
	dr := deploy.Request{Name: req.Name, Action: req.Action, PackageID: req.PackageID, Version: strings.TrimSpace(req.Version), Scope: req.Scope,
		GroupIDs: req.GroupIDs, DeviceIDs: req.DeviceIDs, ExpiresIn: time.Duration(req.ExpiresInHours) * time.Hour, Window: req.Window,
		UnverifiedConfirmed: req.UnverifiedConfirmed, UserID: p.UserID, IP: clientIP(r), Prompts: req.Prompts}
	if req.StartsAt != nil {
		dr.StartsAt = *req.StartsAt
	}
	plan, err := s.Deploy.Create(r.Context(), p.OrgID, dr)
	switch {
	case errors.Is(err, deploy.ErrUnverified):
		writeError(w, http.StatusConflict, "unverified", "This package has not been verified. Confirm that you want to deploy it anyway, or have an administrator mark it as verified on its catalog page after testing it.")
		return
	case errors.Is(err, deploy.ErrExcluded):
		writeError(w, http.StatusConflict, "excluded", "This package is excluded by an administrator.")
		return
	case errors.Is(err, deploy.ErrSelfUpdating):
		writeError(w, http.StatusConflict, "self_updating", "This app updates itself, so "+s.productName(r)+" leaves updates to the vendor. To deploy updates anyway, set the package's self-update policy to “enforce” on its catalog page.")
		return
	case errors.Is(err, deploy.ErrNoTargets):
		writeError(w, http.StatusUnprocessableEntity, "no_targets", "No active devices match the chosen targets.")
		return
	case errors.Is(err, deploy.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "invalid_deployment", strings.TrimPrefix(err.Error(), deploy.ErrInvalid.Error()+": "))
		return
	case err != nil:
		s.Log.Error("create deployment", "err", err)
		internalError(w)
		return
	}
	writeJSON(w, http.StatusCreated, plan)
}

func (s *server) listDeployments(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := paging(w, r, 50, 200)
	if !ok {
		return
	}
	rows, err := s.q().ListDeployments(r.Context(), dbq.ListDeploymentsParams{OrgID: principalFrom(r).OrgID, Limit: limit, Offset: offset})
	if err != nil {
		s.Log.Error("list deployments", "err", err)
		internalError(w)
		return
	}
	type view struct {
		ID                uuid.UUID `json:"id"`
		Name              string    `json:"name"`
		Action            string    `json:"action"`
		Scope             string    `json:"scope"`
		Status            string    `json:"status"`
		PackageName       string    `json:"package_name"`
		PackageIdentifier string    `json:"package_identifier"`
		Version           *string   `json:"version"`
		CreatedAt         time.Time `json:"created_at"`
		StartsAt          time.Time `json:"starts_at"`
		ExpiresAt         time.Time `json:"expires_at"`
		JobsTotal         int32     `json:"jobs_total"`
		JobsSucceeded     int32     `json:"jobs_succeeded"`
		JobsFailed        int32     `json:"jobs_failed"`
	}
	items := make([]view, 0, len(rows))
	for _, x := range rows {
		items = append(items, view{x.ID, x.Name, x.Action, x.Scope, x.Status, x.PackageName, x.PackageIdentifier, x.Version, x.CreatedAt, x.StartsAt, x.ExpiresAt,
			x.JobsTotal, x.JobsSucceeded, x.JobsFailed})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) deploymentFromURL(w http.ResponseWriter, r *http.Request) (dbq.GetDeploymentRow, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Deployment not found.")
		return dbq.GetDeploymentRow{}, false
	}
	d, err := s.q().GetDeployment(r.Context(), dbq.GetDeploymentParams{ID: id, OrgID: principalFrom(r).OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "not_found", "Deployment not found.")
		return d, false
	} else if err != nil {
		internalError(w)
		return d, false
	}
	return d, true
}

func (s *server) getDeployment(w http.ResponseWriter, r *http.Request) {
	d, ok := s.deploymentFromURL(w, r)
	if !ok {
		return
	}
	counts := map[string]int32{}
	if rows, err := s.q().DeploymentJobCounts(r.Context(), &d.ID); err == nil {
		for _, c := range rows {
			counts[c.Status] = c.N
		}
	}
	var win json.RawMessage
	if len(d.MaintWindow) > 0 {
		win = d.MaintWindow
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": d.ID, "name": d.Name, "action": d.Action, "scope": d.Scope, "status": d.Status,
		"package_id": d.PackageID, "package_name": d.PackageName, "package_identifier": d.PackageIdentifier, "version": d.Version,
		"created_at": d.CreatedAt, "starts_at": d.StartsAt, "expires_at": d.ExpiresAt, "unverified_confirmed": d.UnverifiedConfirmed,
		"window": win, "prompts": deploy.ParsePrompts(d.Prompts), "job_counts": counts})
}

func (s *server) deploymentJobs(w http.ResponseWriter, r *http.Request) {
	d, ok := s.deploymentFromURL(w, r)
	if !ok {
		return
	}
	limit, offset, ok := paging(w, r, 200, 1000)
	if !ok {
		return
	}
	rows, err := s.q().ListJobsByDeployment(r.Context(), dbq.ListJobsByDeploymentParams{DeploymentID: &d.ID, OrgID: d.OrgID, Limit: limit, Offset: offset})
	if err != nil {
		internalError(w)
		return
	}
	type view struct {
		ID              uuid.UUID  `json:"id"`
		DeviceID        uuid.UUID  `json:"device_id"`
		Hostname        string     `json:"hostname"`
		UserSID         string     `json:"user_sid"`
		Type            string     `json:"type"`
		Title           string     `json:"title"`
		Status          string     `json:"status"`
		Reason          string     `json:"status_reason"`
		Attempt         int32      `json:"attempt"`
		CreatedAt       time.Time  `json:"created_at"`
		SentAt          *time.Time `json:"sent_at"`
		StartedAt       *time.Time `json:"started_at"`
		FinishedAt      *time.Time `json:"finished_at"`
		ExitCode        *int32     `json:"exit_code"`
		DetectionPassed *bool      `json:"detection_passed"`
		RebootRequired  bool       `json:"reboot_required"`
		DependsOn       *uuid.UUID `json:"depends_on"`
	}
	items := make([]view, 0, len(rows))
	for _, x := range rows {
		items = append(items, view{x.ID, x.DeviceID, x.Hostname, x.UserSid, x.Type, x.Title, x.Status, x.StatusReason, x.Attempt, x.CreatedAt,
			x.SentAt, x.StartedAt, x.FinishedAt, x.ExitCode, x.DetectionPassed, x.RebootRequired, x.DependsOn})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) cancelDeployment(w http.ResponseWriter, r *http.Request) {
	if !s.deploySvc(w) {
		return
	}
	d, ok := s.deploymentFromURL(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	if d.Status == "cancelled" {
		writeError(w, http.StatusConflict, "already_cancelled", "The deployment is already cancelled.")
		return
	}
	if err := s.Deploy.CancelDeployment(r.Context(), p.OrgID, p.UserID, d.ID, clientIP(r)); err != nil {
		s.Log.Error("cancel deployment", "err", err)
		internalError(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) getJob(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Job not found.")
		return
	}
	q := s.q()
	j, err := q.GetJob(r.Context(), dbq.GetJobParams{ID: id, OrgID: principalFrom(r).OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "not_found", "Job not found.")
		return
	} else if err != nil {
		internalError(w)
		return
	}
	if p := principalFrom(r); !p.Access.OrgHas(auth.PermDeploymentsRead) && !s.deviceInScope(r.Context(), p, auth.PermDeploymentsRead, j.DeviceID) {
		writeError(w, http.StatusNotFound, "not_found", "Job not found.")
		return
	}
	events, _ := q.ListJobEvents(r.Context(), j.ID)
	type ev struct {
		ID      int64     `json:"id"`
		Time    time.Time `json:"time"`
		Kind    string    `json:"kind"`
		Message string    `json:"message"`
	}
	evs := make([]ev, 0, len(events))
	for _, e := range events {
		evs = append(evs, ev{e.ID, e.Ts, e.Kind, e.Message})
	}
	var host string
	if d, err := q.GetDeviceInOrg(r.Context(), dbq.GetDeviceInOrgParams{ID: j.DeviceID, OrgID: j.OrgID}); err == nil {
		host = d.Hostname
	}
	var result json.RawMessage
	if len(j.Result) > 0 {
		result = j.Result
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": j.ID, "deployment_id": j.DeploymentID, "device_id": j.DeviceID, "hostname": host, "user_sid": j.UserSid,
		"type": j.Type, "title": j.Title, "status": j.Status, "status_reason": j.StatusReason, "attempt": j.Attempt, "created_at": j.CreatedAt,
		"not_before": j.NotBefore, "expires_at": j.ExpiresAt, "sent_at": j.SentAt, "acked_at": j.AckedAt, "started_at": j.StartedAt,
		"finished_at": j.FinishedAt, "exit_code": j.ExitCode, "detection_passed": j.DetectionPassed, "reboot_required": j.RebootRequired,
		"depends_on": j.DependsOn, "result": result, "events": evs})
}

func (s *server) retryJob(w http.ResponseWriter, r *http.Request) {
	if !s.deploySvc(w) {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Job not found.")
		return
	}
	p := principalFrom(r)
	if !p.Access.OrgHas(auth.PermDeploymentsWrite) {
		j, jerr := s.q().GetJob(r.Context(), dbq.GetJobParams{ID: id, OrgID: p.OrgID})
		if jerr != nil || !s.deviceInScope(r.Context(), p, auth.PermDeploymentsWrite, j.DeviceID) {
			writeError(w, http.StatusNotFound, "not_found", "Job not found.")
			return
		}
	}
	nid, err := s.Deploy.Retry(r.Context(), p.OrgID, p.UserID, id, clientIP(r))
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		writeError(w, http.StatusNotFound, "not_found", "Job not found.")
	case errors.Is(err, deploy.ErrNotRetryable):
		writeError(w, http.StatusConflict, "not_retryable", "Only failed, expired, rejected or cancelled jobs can be retried.")
	case err != nil:
		s.Log.Error("retry job", "err", err)
		internalError(w)
	default:
		writeJSON(w, http.StatusCreated, map[string]any{"job_id": nid})
	}
}

func (s *server) deviceJobs(w http.ResponseWriter, r *http.Request) {
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	rows, err := s.q().ListDeviceJobs(r.Context(), dbq.ListDeviceJobsParams{DeviceID: d.ID, OrgID: d.OrgID, Limit: 100})
	if err != nil {
		internalError(w)
		return
	}
	type view struct {
		ID             uuid.UUID  `json:"id"`
		DeploymentID   *uuid.UUID `json:"deployment_id"`
		UserSID        string     `json:"user_sid"`
		Type           string     `json:"type"`
		Title          string     `json:"title"`
		Status         string     `json:"status"`
		Reason         string     `json:"status_reason"`
		Attempt        int32      `json:"attempt"`
		CreatedAt      time.Time  `json:"created_at"`
		FinishedAt     *time.Time `json:"finished_at"`
		ExitCode       *int32     `json:"exit_code"`
		RebootRequired bool       `json:"reboot_required"`
	}
	items := make([]view, 0, len(rows))
	for _, x := range rows {
		items = append(items, view{x.ID, x.DeploymentID, x.UserSid, x.Type, x.Title, x.Status, x.StatusReason, x.Attempt, x.CreatedAt, x.FinishedAt, x.ExitCode, x.RebootRequired})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
