package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/shared/text"
	"google.golang.org/protobuf/proto"
)

// ErrUnknownJob is returned when a device reports on a job that is not its own.
var ErrUnknownJob = errors.New("deploy: unknown job for this device")

var stateStatus = map[agentv1.JobState]string{
	agentv1.JobState_JOB_STATE_ACCEPTED:         "accepted",
	agentv1.JobState_JOB_STATE_WAITING:          "waiting",
	agentv1.JobState_JOB_STATE_RUNNING:          "running",
	agentv1.JobState_JOB_STATE_SUCCEEDED:        "succeeded",
	agentv1.JobState_JOB_STATE_SUCCEEDED_REBOOT: "succeeded_reboot",
	agentv1.JobState_JOB_STATE_FAILED:           "failed",
	agentv1.JobState_JOB_STATE_EXPIRED:          "expired",
	agentv1.JobState_JOB_STATE_CANCELLED:        "cancelled",
	agentv1.JobState_JOB_STATE_REJECTED:         "rejected",
}

func terminal(status string) bool {
	switch status {
	case "succeeded", "succeeded_reboot", "failed", "expired", "cancelled", "rejected":
		return true
	}
	return false
}

// clean bounds and sanitizes agent-supplied text before it is stored.
func clean(s string, max int) string {
	return text.Truncate(strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), "�"), max)
}

// ApplyUpdate records a job update reported by a device.
func (s *Service) ApplyUpdate(ctx context.Context, dev dbq.Device, u *agentv1.JobUpdate) error {
	id, err := uuid.Parse(u.JobId)
	if err != nil {
		return ErrUnknownJob
	}
	status, ok := stateStatus[u.State]
	if !ok {
		return invalid("unknown job state")
	}
	now := s.now()
	var finished *time.Time
	var started *time.Time
	var exit *int32
	var det *bool
	reboot := false
	var resultJSON []byte
	if terminal(status) {
		finished = &now
	}
	if status == "running" {
		started = &now
	}
	if r := u.Result; r != nil {
		code := r.ExitCode
		exit = &code
		d := r.DetectionPassed
		det = &d
		reboot = r.RebootRequired
		resultJSON, _ = json.Marshal(map[string]any{
			"outcome": r.Outcome.String(), "message": clean(r.Message, 1024), "log_tail": clean(r.LogTail, 16<<10),
			"installed_version": clean(r.InstalledVersion, 128), "already_satisfied": r.AlreadySatisfied, "exit_code": r.ExitCode,
			"wu_results": wuResultsJSON(r.WuResults),
		})
		if r.StartedAt > 0 {
			t := time.Unix(r.StartedAt, 0)
			started = &t
		}
		if r.FinishedAt > 0 && terminal(status) {
			t := time.Unix(r.FinishedAt, 0)
			if t.Before(now.Add(time.Hour)) {
				finished = &t
			}
		}
	}
	var job dbq.Job
	var changed bool
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		j, err := q.GetJobForDevice(ctx, dbq.GetJobForDeviceParams{ID: id, DeviceID: dev.ID})
		if err != nil {
			return ErrUnknownJob
		}
		job = j
		if j.CancelPending && terminal(status) {
			_ = q.ClearCancelPending(ctx, dbq.ClearCancelPendingParams{ID: id, DeviceID: dev.ID})
		}
		// What a script printed is kept apart from the job result that job pages show to everyone who may read deployments (D127).
		scriptOutput := ""
		if j.Type == "run_script" {
			resultJSON = withoutLog(resultJSON)
			if u.Result != nil && terminal(status) {
				scriptOutput = clean(u.Result.LogTail, 16<<10)
			}
		}
		n, err := q.ApplyJobUpdate(ctx, dbq.ApplyJobUpdateParams{ID: id, DeviceID: dev.ID, Status: status, Reason: clean(u.Reason, 128), Now: now,
			StartedAt: started, FinishedAt: finished, ExitCode: exit, DetectionPassed: det, RebootRequired: reboot, Result: resultJSON})
		if err != nil {
			return err
		}
		changed = n > 0
		if !changed {
			return nil // late or duplicate update for a job that is already final
		}
		if j.Type == "run_script" && j.ScriptRunID != nil && u.Result != nil && terminal(status) {
			_ = q.PruneScriptOutputs(ctx, s.now().Add(-30*24*time.Hour))
			if err := q.InsertScriptOutput(ctx, dbq.InsertScriptOutputParams{JobID: id, RunID: *j.ScriptRunID, ExitCode: u.Result.ExitCode, Output: scriptOutput}); err != nil {
				return err
			}
		}
		// What a read-only view returned goes to its own short-lived table, never into the job result that job pages show (D125).
		if job.Type == "inspect" && u.Result != nil && u.Result.DataJson != "" && status == "succeeded" {
			if kind, raw, ok := viewData(u.Result.DataJson); ok {
				now := s.now()
				_ = q.PruneDeviceViews(ctx, now.Add(-time.Hour))
				if err := q.InsertDeviceView(ctx, dbq.InsertDeviceViewParams{JobID: id, OrgID: job.OrgID, DeviceID: dev.ID, Kind: kind, Data: raw}); err != nil {
					return err
				}
			}
		}
		// A device that finished an install from a file has that file in its cache and can be offered as a peer for it (D126).
		if (job.Type == "software_install" || job.Type == "software_update") && (status == "succeeded" || status == "succeeded_reboot") {
			if err := notePeerContent(ctx, q, dev.ID, job.Body, s.now()); err != nil {
				return err
			}
		}
		msg := clean(u.Reason, 128)
		if u.Result != nil && u.Result.Message != "" {
			msg = clean(u.Result.Message, 512)
		}
		return q.InsertJobEvent(ctx, dbq.InsertJobEventParams{JobID: id, Kind: status, Message: msg})
	})
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	s.publish(job.OrgID, "job.updated", job.DeviceID, job.ID, derefID(job.DeploymentID))
	if terminal(status) {
		if s.AfterTerminal != nil {
			s.AfterTerminal(ctx, job, status, u)
		}
		s.afterTerminal(ctx, job, status)
	}
	return nil
}

// wuResultsJSON is the per-update outcome of a Windows Update job, as stored in the job result.
func wuResultsJSON(rs []*agentv1.WuUpdateResult) []map[string]any {
	out := make([]map[string]any, 0, len(rs))
	for i, r := range rs {
		if i >= 200 {
			break
		}
		out = append(out, map[string]any{"update_id": clean(r.UpdateId, 36), "revision": r.Revision, "result": r.Result.String(), "hresult": r.Hresult})
	}
	return out
}

func derefID(p *uuid.UUID) uuid.UUID {
	if p == nil {
		return uuid.Nil
	}
	return *p
}

// afterTerminal releases or cancels dependent jobs and closes finished deployments.
func (s *Service) afterTerminal(ctx context.Context, j dbq.Job, status string) {
	q := dbq.New(s.Pool)
	deps, err := q.ListDependentJobs(ctx, &j.ID)
	if err == nil {
		now := s.now()
		for _, d := range deps {
			if status == "succeeded" || status == "succeeded_reboot" || (d.DependsWhen == "finished" && status != "cancelled") {
				s.signAndOffer(ctx, d)
				continue
			}
			if n, err := q.CancelJob(ctx, dbq.CancelJobParams{ID: d.ID, OrgID: d.OrgID, StatusReason: "dependency_failed", FinishedAt: &now}); err == nil && n > 0 {
				_ = q.InsertJobEvent(ctx, dbq.InsertJobEventParams{JobID: d.ID, Kind: "cancelled", Message: "the job it depends on did not succeed"})
				s.publish(d.OrgID, "job.updated", d.DeviceID, d.ID, derefID(d.DeploymentID))
			}
		}
	}
	if j.DeploymentID != nil {
		_ = q.CompleteDeploymentIfDone(ctx, *j.DeploymentID)
		s.publish(j.OrgID, "deployment.updated", uuid.Nil, uuid.Nil, *j.DeploymentID)
	}
}

// CancelDeployment cancels everything not yet finished.
func (s *Service) CancelDeployment(ctx context.Context, org, user, id uuid.UUID, ip string) error {
	q := dbq.New(s.Pool)
	dep, err := q.GetDeployment(ctx, dbq.GetDeploymentParams{ID: id, OrgID: org})
	if err != nil {
		return err
	}
	now := s.now()
	var cancelled []dbq.CancelJobsOfDeploymentRow
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.SetDeploymentStatus(ctx, dbq.SetDeploymentStatusParams{ID: id, OrgID: org, Status: "cancelled"}); err != nil {
			return err
		}
		rows, err := q.CancelJobsOfDeployment(ctx, dbq.CancelJobsOfDeploymentParams{DeploymentID: &id, FinishedAt: &now})
		if err != nil {
			return err
		}
		cancelled = rows
		for _, r := range rows {
			if err := q.MarkCancelPending(ctx, r.ID); err != nil {
				return err
			}
			if err := q.InsertJobEvent(ctx, dbq.InsertJobEventParams{JobID: r.ID, Kind: "cancelled", Message: "the deployment was cancelled"}); err != nil {
				return err
			}
		}
		_, err = audit.Write(ctx, tx, audit.Entry{OrgID: &org, ActorType: audit.ActorUser, ActorID: user.String(), ActorIP: ip,
			Action: "deployment.cancel", TargetType: "deployment", TargetIDs: []string{id.String()}, Outcome: audit.Success,
			Details: map[string]any{"name": dep.Name, "jobs_cancelled": len(rows)}}, now)
		return err
	})
	if err != nil {
		return err
	}
	// Tell connected devices to drop jobs they already hold; others are told on reconnect.
	for _, r := range cancelled {
		if j, err := q.GetJob(ctx, dbq.GetJobParams{ID: r.ID, OrgID: org}); err == nil && j.CancelPending {
			s.offerCancel(j)
		}
		s.publish(org, "job.updated", r.DeviceID, r.ID, id)
	}
	s.publish(org, "deployment.updated", uuid.Nil, uuid.Nil, id)
	return nil
}

// Retry queues a new attempt of a finished job.
func (s *Service) Retry(ctx context.Context, org, user, jobID uuid.UUID, ip string) (uuid.UUID, error) {
	q := dbq.New(s.Pool)
	j, err := q.GetJob(ctx, dbq.GetJobParams{ID: jobID, OrgID: org})
	if err != nil {
		return uuid.Nil, err
	}
	switch j.Status {
	case "failed", "expired", "rejected", "cancelled":
	default:
		return uuid.Nil, ErrNotRetryable
	}
	now := s.now()
	life := j.ExpiresAt.Sub(j.NotBefore)
	if life < 24*time.Hour {
		life = 72 * time.Hour
	}
	if life > maxLifetime {
		life = maxLifetime
	}
	nid, _ := uuid.NewV7()
	// The stored body carries the old job ID and window; rewrite the identifying fields.
	body, err := reidentify(j.Body, nid, uint32(j.Attempt+1), now, now.Add(life)) // #nosec G115 -- attempt is small
	if err != nil {
		return uuid.Nil, err
	}
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.InsertJob(ctx, dbq.InsertJobParams{ID: nid, OrgID: org, DeploymentID: j.DeploymentID, DeviceID: j.DeviceID, UserSid: j.UserSid, Type: j.Type,
			Title: j.Title, Body: body, DependsOn: nil, NotBefore: now, ExpiresAt: now.Add(life), Attempt: j.Attempt + 1}); err != nil {
			return err
		}
		if j.DeploymentID != nil {
			if err := q.SetDeploymentStatus(ctx, dbq.SetDeploymentStatusParams{ID: *j.DeploymentID, OrgID: org, Status: "active"}); err != nil {
				return err
			}
		}
		_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &org, ActorType: audit.ActorUser, ActorID: user.String(), ActorIP: ip,
			Action: "job.retry", TargetType: "job", TargetIDs: []string{jobID.String(), nid.String()}, Outcome: audit.Success,
			Details: map[string]any{"title": j.Title, "attempt": j.Attempt + 1}}, now)
		return err
	})
	if err != nil {
		return uuid.Nil, err
	}
	s.publish(org, "job.updated", j.DeviceID, nid, derefID(j.DeploymentID))
	s.bg.Add(1)
	go func() { // #nosec G118 -- delivery to the device must outlive the HTTP request
		defer s.bg.Done()
		s.Dispatch(context.Background(), j.DeviceID)
	}()
	return nid, nil
}

// Sweep expires jobs whose validity ended. Run it periodically.
func (s *Service) Sweep(ctx context.Context) {
	q := dbq.New(s.Pool)
	now := s.now()
	rows, err := q.ExpireJobs(ctx, &now)
	if err != nil {
		s.log().Error("expire jobs", "err", err)
		return
	}
	for _, r := range rows {
		_ = q.InsertJobEvent(ctx, dbq.InsertJobEventParams{JobID: r.ID, Kind: "expired", Message: "the job expired before it finished"})
		s.publish(r.OrgID, "job.updated", r.DeviceID, r.ID, derefID(r.DeploymentID))
		if r.DeploymentID != nil {
			_ = q.CompleteDeploymentIfDone(ctx, *r.DeploymentID)
		}
	}
}

// maxViewBytes caps what a device may store as the answer of a read-only view.
const maxViewBytes = 256 << 10

// viewData checks the JSON a device sent for a read-only view: size, well-formed, a known kind.
func viewData(data string) (kind string, raw []byte, ok bool) {
	if len(data) > maxViewBytes || !json.Valid([]byte(data)) {
		return "", nil, false
	}
	var head struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal([]byte(data), &head) != nil {
		return "", nil, false
	}
	switch head.Kind {
	case "processes", "services", "events":
		return head.Kind, []byte(data), true
	}
	return "", nil, false
}

// installerSHA is the SHA-256 of the installer a stored install job carries (nil when it has none).
func installerSHA(body []byte) []byte {
	var env agentv1.JobEnvelope
	if proto.Unmarshal(body, &env) != nil {
		return nil
	}
	if sha := env.GetInstall().GetInstaller().GetSha256(); len(sha) == 32 {
		return sha
	}
	return nil
}

// withoutLog removes the log tail from a stored job result (script output is kept elsewhere).
func withoutLog(raw []byte) []byte {
	if len(raw) == 0 {
		return raw
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return raw
	}
	m["log_tail"] = ""
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}
