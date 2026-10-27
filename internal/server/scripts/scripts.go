// Package scripts is the script library and the runs of scripts on devices (D127).
//
// This is the most powerful thing the product does: code an administrator wrote, run as SYSTEM on many computers. The
// controls are layered: administrators only (scripts:*), never in an API token, every version kept and fingerprinted, the
// exact content copied into the run and into each signed job, an optional second person who must approve a run, an agent
// that refuses scripts unless its owner switched them on, a time limit, output kept apart from job pages, and an audit entry
// for every step.
package scripts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/settings"
	"github.com/auzring1/librepatch/internal/server/store"
)

// Errors the API maps to HTTP statuses.
var (
	ErrInvalid   = errors.New("scripts: invalid request")
	ErrNotFound  = errors.New("scripts: not found")
	ErrConflict  = errors.New("scripts: conflict")
	ErrForbidden = errors.New("scripts: not allowed")
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Limits.
const (
	MaxContent       = 64 << 10
	MaxTargets       = 500
	DefaultTimeoutS  = 300
	ApprovalValidity = 24 * time.Hour
	jobLifetime      = 6 * time.Hour
	OutputRetention  = 30 * 24 * time.Hour
)

// Actor is who did something.
type Actor struct {
	Org  uuid.UUID
	User uuid.UUID
	IP   string
}

// Service owns the library and the runs.
type Service struct {
	Pool     *pgxpool.Pool
	Deploy   *deploy.Service
	Settings *settings.Service
	Log      *slog.Logger
	Now      func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Enabled: the organization allows running scripts at all (Settings > Scripts, on by default, D150).
func (s *Service) Enabled(ctx context.Context, org uuid.UUID) bool {
	return s.Settings == nil || s.Settings.Peek(ctx, org, "scripts").Bool("enabled")
}

// ErrDisabled is returned when an administrator switched running scripts off in Settings.
var ErrDisabled = errors.New("scripts: running scripts is switched off")

// RequireApproval: the organization wants a second person to approve every run.
func (s *Service) RequireApproval(ctx context.Context, org uuid.UUID) bool {
	return s.Settings != nil && s.Settings.Peek(ctx, org, "scripts").Bool("require_approval")
}

func (s *Service) audit(ctx context.Context, tx pgx.Tx, a Actor, action, targetType string, id uuid.UUID, details map[string]any) error {
	_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &a.Org, ActorType: audit.ActorUser, ActorID: a.User.String(), ActorIP: a.IP, Action: action,
		TargetType: targetType, TargetIDs: []string{id.String()}, Outcome: audit.Success, Details: details}, s.now())
	return err
}

func isUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func sum(content string) []byte { h := sha256.Sum256([]byte(content)); return h[:] }

func checkContent(c string) error {
	if strings.TrimSpace(c) == "" || len(c) > MaxContent || !utf8.ValidString(c) || strings.ContainsRune(c, 0) {
		return invalid("a script is 1 to %d bytes of text", MaxContent)
	}
	return nil
}

func checkMeta(name, desc string) (string, string, error) {
	name, desc = strings.TrimSpace(name), strings.TrimSpace(desc)
	if n := utf8.RuneCountInString(name); n < 1 || n > 100 {
		return "", "", invalid("the name must be 1 to 100 characters")
	}
	if utf8.RuneCountInString(desc) > 500 {
		return "", "", invalid("the description is at most 500 characters")
	}
	return name, desc, nil
}

// ---- library ----

// Input is a script as an administrator submits it.
type Input struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Content     string `json:"content"`
	Note        string `json:"note"` // what changed (kept with the version)
}

// Create adds a script (version 1).
func (s *Service) Create(ctx context.Context, a Actor, in Input) (uuid.UUID, error) {
	name, desc, err := checkMeta(in.Name, in.Description)
	if err != nil {
		return uuid.Nil, err
	}
	if err := checkContent(in.Content); err != nil {
		return uuid.Nil, err
	}
	note := truncate(in.Note, 200)
	id := uuid.New()
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.InsertScript(ctx, dbq.InsertScriptParams{ID: id, OrgID: a.Org, Name: name, Description: desc, Interpreter: "powershell", CreatedBy: &a.User}); err != nil {
			return err
		}
		if err := q.InsertScriptVersion(ctx, dbq.InsertScriptVersionParams{ScriptID: id, Version: 1, Content: in.Content, Sha256: sum(in.Content), Note: note, CreatedBy: &a.User}); err != nil {
			return err
		}
		return s.audit(ctx, tx, a, "script.create", "script", id, map[string]any{"name": name, "version": 1, "sha256": hex.EncodeToString(sum(in.Content)), "bytes": len(in.Content)})
	})
	if isUnique(err) {
		return uuid.Nil, fmt.Errorf("%w: a script with that name already exists", ErrConflict)
	}
	return id, err
}

// Update changes the name and description and, when the content differs from the current version, saves a new version.
// It returns the current version afterwards.
func (s *Service) Update(ctx context.Context, a Actor, id uuid.UUID, in Input) (int32, error) {
	name, desc, err := checkMeta(in.Name, in.Description)
	if err != nil {
		return 0, err
	}
	if err := checkContent(in.Content); err != nil {
		return 0, err
	}
	var version int32
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		sc, err := q.GetScript(ctx, dbq.GetScriptParams{ID: id, OrgID: a.Org})
		if err != nil {
			return ErrNotFound
		}
		version = sc.CurrentVersion
		cur, err := q.GetScriptVersion(ctx, dbq.GetScriptVersionParams{ScriptID: id, Version: sc.CurrentVersion})
		if err != nil {
			return err
		}
		if n, err := q.UpdateScriptMeta(ctx, dbq.UpdateScriptMetaParams{ID: id, OrgID: a.Org, Name: name, Description: desc}); err != nil || n == 0 {
			return err
		}
		details := map[string]any{"name": name}
		if cur.Content != in.Content {
			version = sc.CurrentVersion + 1
			if err := q.InsertScriptVersion(ctx, dbq.InsertScriptVersionParams{ScriptID: id, Version: version, Content: in.Content, Sha256: sum(in.Content), Note: truncate(in.Note, 200), CreatedBy: &a.User}); err != nil {
				return err
			}
			if _, err := q.SetScriptVersion(ctx, dbq.SetScriptVersionParams{ID: id, OrgID: a.Org, CurrentVersion: version}); err != nil {
				return err
			}
			details["version"], details["sha256"], details["bytes"] = version, hex.EncodeToString(sum(in.Content)), len(in.Content)
		}
		return s.audit(ctx, tx, a, "script.update", "script", id, details)
	})
	if isUnique(err) {
		return 0, fmt.Errorf("%w: a script with that name already exists", ErrConflict)
	}
	return version, err
}

// Delete removes a script and its versions. Runs keep their own copy of what ran.
func (s *Service) Delete(ctx context.Context, a Actor, id uuid.UUID) error {
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		sc, err := q.GetScript(ctx, dbq.GetScriptParams{ID: id, OrgID: a.Org})
		if err != nil {
			return ErrNotFound
		}
		if _, err := q.DeleteScript(ctx, dbq.DeleteScriptParams{ID: id, OrgID: a.Org}); err != nil {
			return err
		}
		return s.audit(ctx, tx, a, "script.delete", "script", id, map[string]any{"name": sc.Name})
	})
}

// ScriptItem is a library entry.
type ScriptItem struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Interpreter string     `json:"interpreter"`
	Version     int32      `json:"version"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Runs        int64      `json:"runs"`
	LastRunAt   *time.Time `json:"last_run_at"`
}

// List returns the library.
func (s *Service) List(ctx context.Context, org uuid.UUID) ([]ScriptItem, error) {
	rows, err := dbq.New(s.Pool).ListScripts(ctx, org)
	if err != nil {
		return nil, err
	}
	out := make([]ScriptItem, 0, len(rows))
	for _, r := range rows {
		it := ScriptItem{ID: r.ID, Name: r.Name, Description: r.Description, Interpreter: r.Interpreter, Version: r.CurrentVersion, UpdatedAt: r.UpdatedAt, Runs: r.Runs}
		if t, ok := r.LastRunAt.(time.Time); ok {
			it.LastRunAt = &t
		}
		out = append(out, it)
	}
	return out, nil
}

// VersionItem is one saved version.
type VersionItem struct {
	Version   int32     `json:"version"`
	SHA256    string    `json:"sha256"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
	By        string    `json:"created_by"`
}

// ScriptDetail is a script with its current content and history.
type ScriptDetail struct {
	ScriptItem
	Content  string        `json:"content"`
	SHA256   string        `json:"sha256"`
	Versions []VersionItem `json:"versions"`
}

// Get returns a script. version 0 = the current one.
func (s *Service) Get(ctx context.Context, org, id uuid.UUID, version int32) (*ScriptDetail, error) {
	q := dbq.New(s.Pool)
	sc, err := q.GetScript(ctx, dbq.GetScriptParams{ID: id, OrgID: org})
	if err != nil {
		return nil, ErrNotFound
	}
	if version == 0 {
		version = sc.CurrentVersion
	}
	v, err := q.GetScriptVersion(ctx, dbq.GetScriptVersionParams{ScriptID: id, Version: version})
	if err != nil {
		return nil, ErrNotFound
	}
	vs, err := q.ListScriptVersions(ctx, id)
	if err != nil {
		return nil, err
	}
	d := &ScriptDetail{ScriptItem: ScriptItem{ID: sc.ID, Name: sc.Name, Description: sc.Description, Interpreter: sc.Interpreter, Version: sc.CurrentVersion, UpdatedAt: sc.UpdatedAt},
		Content: v.Content, SHA256: hex.EncodeToString(v.Sha256), Versions: []VersionItem{}}
	for _, x := range vs {
		d.Versions = append(d.Versions, VersionItem{Version: x.Version, SHA256: hex.EncodeToString(x.Sha256), Note: x.Note, CreatedAt: x.CreatedAt, By: x.CreatedByName})
	}
	return d, nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// ---- runs ----

// RunRequest asks for a script to run.
type RunRequest struct {
	ScriptID  uuid.UUID   `json:"script_id"`
	Version   int32       `json:"version"` // 0 = the current version
	GroupIDs  []uuid.UUID `json:"group_ids"`
	DeviceIDs []uuid.UUID `json:"device_ids"`
	TimeoutS  int         `json:"timeout_s"` // 0 = 300
	Reason    string      `json:"reason"`    // why, recorded with the run
}

// RunView is a run as the console shows it.
type RunView struct {
	ID          uuid.UUID  `json:"id"`
	ScriptID    *uuid.UUID `json:"script_id"`
	ScriptName  string     `json:"script_name"`
	Version     int32      `json:"version"`
	SHA256      string     `json:"sha256"`
	Reason      string     `json:"reason"`
	Status      string     `json:"status"`
	Devices     int32      `json:"devices"`
	TimeoutS    int32      `json:"timeout_s"`
	RequestedAt time.Time  `json:"requested_at"`
	RequestedBy string     `json:"requested_by"`
	// RequestedByID lets the console hide "Approve" from the person who asked.
	RequestedByID *uuid.UUID `json:"requested_by_id"`
	DecidedAt     *time.Time `json:"decided_at"`
	DecidedBy     string     `json:"decided_by"`
	Note          string     `json:"decision_note"`
	Succeeded     int64      `json:"succeeded"`
	Failed        int64      `json:"failed"`
	// NeedsApproval is true while the run waits for a second person.
	NeedsApproval bool `json:"needs_approval"`
}

// RequestRun records a run. With approval required it waits for a second person; otherwise it starts at once.
func (s *Service) RequestRun(ctx context.Context, a Actor, r RunRequest) (*RunView, error) {
	reason := truncate(r.Reason, 200)
	if reason == "" {
		return nil, invalid("say why the script is being run; it is recorded with the run")
	}
	timeout := r.TimeoutS
	if timeout == 0 {
		timeout = DefaultTimeoutS
	}
	if timeout < 10 || timeout > 3600 {
		return nil, invalid("the time limit is 10 to 3600 seconds")
	}
	if len(r.GroupIDs)+len(r.DeviceIDs) == 0 {
		return nil, invalid("choose at least one group or device")
	}
	if !s.Enabled(ctx, a.Org) {
		return nil, ErrDisabled
	}
	q := dbq.New(s.Pool)
	sc, err := q.GetScript(ctx, dbq.GetScriptParams{ID: r.ScriptID, OrgID: a.Org})
	if err != nil {
		return nil, ErrNotFound
	}
	version := r.Version
	if version == 0 {
		version = sc.CurrentVersion
	}
	v, err := q.GetScriptVersion(ctx, dbq.GetScriptVersionParams{ScriptID: sc.ID, Version: version})
	if err != nil {
		return nil, invalid("that version does not exist")
	}
	devs, err := s.Deploy.ResolveTargets(ctx, a.Org, r.GroupIDs, r.DeviceIDs)
	if err != nil {
		return nil, err
	}
	if len(devs) == 0 {
		return nil, invalid("no active device matches the chosen targets")
	}
	if len(devs) > MaxTargets {
		return nil, invalid("a run is limited to %d devices; this one matches %d", MaxTargets, len(devs))
	}
	approval := s.RequireApproval(ctx, a.Org)
	status := "running"
	if approval {
		status = "pending_approval"
	}
	id := uuid.New()
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.InsertScriptRun(ctx, dbq.InsertScriptRunParams{ID: id, OrgID: a.Org, ScriptID: &sc.ID, ScriptName: sc.Name, Version: version, Interpreter: sc.Interpreter,
			Content: v.Content, Sha256: v.Sha256, TimeoutS: int32(timeout), Reason: reason, TargetGroupIds: nzu(r.GroupIDs), TargetDeviceIds: nzu(r.DeviceIDs), // #nosec G115 -- 10..3600
			Status: status, RequestedBy: &a.User, Devices: int32(len(devs))}); err != nil { // #nosec G115 -- at most 500
			return err
		}
		if err := s.audit(ctx, tx, a, "script.run_request", "script_run", id, map[string]any{"script": sc.Name, "script_id": sc.ID.String(), "version": version,
			"sha256": hex.EncodeToString(v.Sha256), "devices": len(devs), "timeout_s": timeout, "reason": reason, "needs_approval": approval}); err != nil {
			return err
		}
		if !approval {
			return s.startJobs(ctx, tx, q, a, id, sc.Name, version, v.Content, v.Sha256, timeout, devs, "script.run_start")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !approval {
		s.dispatch(ctx, devs)
	}
	return s.GetRun(ctx, a.Org, id)
}

func nzu(u []uuid.UUID) []uuid.UUID {
	if u == nil {
		return []uuid.UUID{}
	}
	return u
}

// startJobs creates one signed-on-dispatch job per device for the exact content of the run.
func (s *Service) startJobs(ctx context.Context, tx pgx.Tx, q *dbq.Queries, a Actor, run uuid.UUID, name string, version int32, content string, sha []byte, timeout int, devs []dbq.ListActiveDevicesByIDsRow, auditAction string) error {
	now := s.now()
	for _, d := range devs {
		job, err := s.Deploy.NewJob(a.Org, d.ID, deploy.JobSpec{Type: agentv1.JobType_JOB_TYPE_RUN_SCRIPT, DBType: "run_script", Title: "Run script " + truncate(name, 100),
			NotBefore: now, Expires: now.Add(jobLifetime),
			Body: &agentv1.RunScriptBody{Name: name, Version: uint32(version), Interpreter: agentv1.ScriptInterpreter_SCRIPT_INTERPRETER_POWERSHELL, // #nosec G115 -- positive
				Content: content, Sha256: sha, TimeoutS: uint32(timeout), RunId: run.String()}}) // #nosec G115 -- 10..3600
		if err != nil {
			return err
		}
		job.ScriptRunID = &run
		if err := q.InsertJob(ctx, job); err != nil {
			return err
		}
	}
	return s.audit(ctx, tx, a, auditAction, "script_run", run, map[string]any{"script": name, "version": version, "sha256": hex.EncodeToString(sha), "devices": len(devs)})
}

func (s *Service) dispatch(ctx context.Context, devs []dbq.ListActiveDevicesByIDsRow) {
	for _, d := range devs {
		s.Deploy.DispatchAsync(d.ID)
	}
}

// Approve lets a second person start a run that waits for approval.
func (s *Service) Approve(ctx context.Context, a Actor, id uuid.UUID, note string) (*RunView, error) {
	if !s.Enabled(ctx, a.Org) {
		return nil, ErrDisabled
	}
	var devs []dbq.ListActiveDevicesByIDsRow
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		run, err := q.GetScriptRun(ctx, dbq.GetScriptRunParams{ID: id, OrgID: a.Org})
		if err != nil {
			return ErrNotFound
		}
		if run.Status != "pending_approval" {
			return fmt.Errorf("%w: the run is %s", ErrConflict, strings.ReplaceAll(run.Status, "_", " "))
		}
		if run.RequestedBy != nil && *run.RequestedBy == a.User {
			return fmt.Errorf("%w: a run must be approved by someone other than the person who asked for it", ErrForbidden)
		}
		if s.now().Sub(run.RequestedAt) > ApprovalValidity {
			_, _ = q.DecideScriptRun(ctx, dbq.DecideScriptRunParams{ID: id, OrgID: a.Org, Status: "expired", DecidedBy: &a.User, DecidedAt: ptr(s.now()), Note: "not approved within 24 hours"})
			return fmt.Errorf("%w: the request is older than 24 hours; ask for the run again", ErrConflict)
		}
		// The targets are worked out again now (a group may have changed); the content is the copy that was requested.
		devs, err = s.Deploy.ResolveTargets(ctx, a.Org, run.TargetGroupIds, run.TargetDeviceIds)
		if err != nil {
			return err
		}
		if len(devs) == 0 || len(devs) > MaxTargets {
			return invalid("the targets now match %d devices", len(devs))
		}
		if n, err := q.DecideScriptRun(ctx, dbq.DecideScriptRunParams{ID: id, OrgID: a.Org, Status: "running", DecidedBy: &a.User, DecidedAt: ptr(s.now()), Note: truncate(note, 200)}); err != nil || n == 0 {
			if err == nil {
				err = ErrConflict
			}
			return err
		}
		if err := s.audit(ctx, tx, a, "script.run_approve", "script_run", id, map[string]any{"script": run.ScriptName, "version": run.Version, "sha256": hex.EncodeToString(run.Sha256), "note": truncate(note, 200)}); err != nil {
			return err
		}
		return s.startJobs(ctx, tx, q, a, id, run.ScriptName, run.Version, run.Content, run.Sha256, int(run.TimeoutS), devs, "script.run_start")
	})
	if err != nil {
		return nil, err
	}
	s.dispatch(ctx, devs)
	return s.GetRun(ctx, a.Org, id)
}

// Reject declines a run that waits for approval.
func (s *Service) Reject(ctx context.Context, a Actor, id uuid.UUID, note string) (*RunView, error) {
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		run, err := q.GetScriptRun(ctx, dbq.GetScriptRunParams{ID: id, OrgID: a.Org})
		if err != nil {
			return ErrNotFound
		}
		n, err := q.DecideScriptRun(ctx, dbq.DecideScriptRunParams{ID: id, OrgID: a.Org, Status: "rejected", DecidedBy: &a.User, DecidedAt: ptr(s.now()), Note: truncate(note, 200)})
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("%w: the run is %s", ErrConflict, strings.ReplaceAll(run.Status, "_", " "))
		}
		return s.audit(ctx, tx, a, "script.run_reject", "script_run", id, map[string]any{"script": run.ScriptName, "version": run.Version, "note": truncate(note, 200)})
	})
	if err != nil {
		return nil, err
	}
	return s.GetRun(ctx, a.Org, id)
}

// Cancel stops a run: a run waiting for approval is withdrawn, and jobs that have not started are cancelled (a script that
// is already running is not interrupted by this).
func (s *Service) Cancel(ctx context.Context, a Actor, id uuid.UUID) (*RunView, error) {
	var cancelled []uuid.UUID
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		run, err := q.GetScriptRun(ctx, dbq.GetScriptRunParams{ID: id, OrgID: a.Org})
		if err != nil {
			return ErrNotFound
		}
		n, err := q.SetScriptRunStatus(ctx, dbq.SetScriptRunStatusParams{ID: id, OrgID: a.Org, Status: "cancelled"})
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("%w: the run is %s", ErrConflict, strings.ReplaceAll(run.Status, "_", " "))
		}
		now := s.now()
		rows, err := q.CancelJobsOfScriptRun(ctx, dbq.CancelJobsOfScriptRunParams{ScriptRunID: &id, FinishedAt: &now})
		if err != nil {
			return err
		}
		for _, r := range rows {
			if err := q.MarkCancelPending(ctx, r.ID); err != nil {
				return err
			}
			if err := q.InsertJobEvent(ctx, dbq.InsertJobEventParams{JobID: r.ID, Kind: "cancelled", Message: "the run was cancelled"}); err != nil {
				return err
			}
			cancelled = append(cancelled, r.ID)
		}
		return s.audit(ctx, tx, a, "script.run_cancel", "script_run", id, map[string]any{"script": run.ScriptName, "jobs_cancelled": len(rows)})
	})
	if err != nil {
		return nil, err
	}
	s.Deploy.OfferCancels(ctx, a.Org, cancelled)
	return s.GetRun(ctx, a.Org, id)
}

func ptr[T any](v T) *T { return &v }

func (s *Service) runView(ctx context.Context, q *dbq.Queries, r dbq.ScriptRun) RunView {
	v := RunView{ID: r.ID, ScriptID: r.ScriptID, ScriptName: r.ScriptName, Version: r.Version, SHA256: hex.EncodeToString(r.Sha256), Reason: r.Reason, Status: r.Status,
		Devices: r.Devices, TimeoutS: r.TimeoutS, RequestedAt: r.RequestedAt, RequestedByID: r.RequestedBy, DecidedAt: r.DecidedAt, Note: r.DecisionNote, NeedsApproval: r.Status == "pending_approval"}
	if r.Status == "pending_approval" && s.now().Sub(r.RequestedAt) > ApprovalValidity {
		v.Status, v.NeedsApproval = "expired", false
	}
	if r.RequestedBy != nil {
		if u, err := q.GetUserInOrg(ctx, dbq.GetUserInOrgParams{ID: *r.RequestedBy, OrgID: r.OrgID}); err == nil {
			v.RequestedBy = u.DisplayName
		}
	}
	if r.DecidedBy != nil {
		if u, err := q.GetUserInOrg(ctx, dbq.GetUserInOrgParams{ID: *r.DecidedBy, OrgID: r.OrgID}); err == nil {
			v.DecidedBy = u.DisplayName
		}
	}
	return v
}

// GetRun returns one run.
func (s *Service) GetRun(ctx context.Context, org, id uuid.UUID) (*RunView, error) {
	q := dbq.New(s.Pool)
	r, err := q.GetScriptRun(ctx, dbq.GetScriptRunParams{ID: id, OrgID: org})
	if err != nil {
		return nil, ErrNotFound
	}
	v := s.runView(ctx, q, r)
	jobs, _ := q.ListScriptRunJobs(ctx, &id)
	for _, j := range jobs {
		switch j.Status {
		case "succeeded":
			v.Succeeded++
		case "failed", "expired", "rejected":
			v.Failed++
		}
	}
	return &v, nil
}

// ListRuns returns the newest runs.
func (s *Service) ListRuns(ctx context.Context, org uuid.UUID, limit int32) ([]RunView, error) {
	rows, err := dbq.New(s.Pool).ListScriptRuns(ctx, dbq.ListScriptRunsParams{OrgID: org, Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]RunView, 0, len(rows))
	for _, r := range rows {
		v := RunView{ID: r.ID, ScriptID: r.ScriptID, ScriptName: r.ScriptName, Version: r.Version, Reason: r.Reason, Status: r.Status, Devices: r.Devices,
			RequestedAt: r.RequestedAt, RequestedByID: r.RequestedBy, DecidedAt: r.DecidedAt, RequestedBy: r.RequestedByName, DecidedBy: r.DecidedByName, Succeeded: r.Succeeded, Failed: r.Failed,
			NeedsApproval: r.Status == "pending_approval"}
		if r.Status == "pending_approval" && s.now().Sub(r.RequestedAt) > ApprovalValidity {
			v.Status, v.NeedsApproval = "expired", false
		}
		out = append(out, v)
	}
	return out, nil
}

// RunJob is one device of a run.
type RunJob struct {
	JobID      uuid.UUID  `json:"job_id"`
	DeviceID   uuid.UUID  `json:"device_id"`
	Hostname   string     `json:"hostname"`
	Status     string     `json:"status"`
	Reason     string     `json:"status_reason"`
	ExitCode   *int32     `json:"exit_code"`
	FinishedAt *time.Time `json:"finished_at"`
	HasOutput  bool       `json:"has_output"`
}

// RunDetail is a run, its content and its devices.
type RunDetail struct {
	RunView
	Content string   `json:"content"`
	Jobs    []RunJob `json:"jobs"`
}

// RunDetail returns a run with the exact content that was (or will be) sent and one row per device.
func (s *Service) RunDetail(ctx context.Context, org, id uuid.UUID) (*RunDetail, error) {
	q := dbq.New(s.Pool)
	r, err := q.GetScriptRun(ctx, dbq.GetScriptRunParams{ID: id, OrgID: org})
	if err != nil {
		return nil, ErrNotFound
	}
	v, _ := s.GetRun(ctx, org, id)
	d := &RunDetail{RunView: *v, Content: r.Content, Jobs: []RunJob{}}
	jobs, err := q.ListScriptRunJobs(ctx, &id)
	if err != nil {
		return nil, err
	}
	for _, j := range jobs {
		d.Jobs = append(d.Jobs, RunJob{JobID: j.ID, DeviceID: j.DeviceID, Hostname: j.Hostname, Status: j.Status, Reason: j.StatusReason, ExitCode: j.ExitCode, FinishedAt: j.FinishedAt, HasOutput: j.HasOutput})
	}
	return d, nil
}

// Output is what a script printed on one device.
type Output struct {
	JobID     uuid.UUID `json:"job_id"`
	ExitCode  int32     `json:"exit_code"`
	Output    string    `json:"output"`
	CreatedAt time.Time `json:"created_at"`
}

// GetOutput returns the output of one job of a run.
func (s *Service) GetOutput(ctx context.Context, org, run, job uuid.UUID) (*Output, error) {
	o, err := dbq.New(s.Pool).GetScriptOutput(ctx, dbq.GetScriptOutputParams{JobID: job, RunID: run, OrgID: org})
	if err != nil {
		return nil, ErrNotFound
	}
	return &Output{JobID: o.JobID, ExitCode: o.ExitCode, Output: o.Output, CreatedAt: o.CreatedAt}, nil
}

// OtherApprovers is how many other active administrators there are: with none, a run that needs approval can never be approved.
func (s *Service) OtherApprovers(ctx context.Context, org, user uuid.UUID) int64 {
	n, _ := dbq.New(s.Pool).CountApprovers(ctx, dbq.CountApproversParams{OrgID: org, ID: user})
	return n
}
