// Package agentrel manages agent self-update on the server: it stores vendor-signed agent
// releases, remembers which release devices should converge on and how (pilot group, soak time,
// success threshold, maintenance window), and creates the signed AGENT_UPDATE jobs.
//
// The server is deliberately not the root of trust here. It verifies a release when an
// administrator uploads it (to reject junk early) but the agents verify it again against the
// vendor key compiled into them, so a compromised server can only schedule releases the vendor
// published (docs/SECURITY.md §9d).
package agentrel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/catalog"
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/events"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/shared/ptr"
	"github.com/auzring1/librepatch/internal/shared/release"
	"github.com/auzring1/librepatch/internal/shared/text"
	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

// Errors the API maps to HTTP statuses.
var (
	ErrInvalid  = errors.New("agentrel: invalid request")
	ErrNotFound = errors.New("agentrel: not found")
	ErrConflict = errors.New("agentrel: conflict")
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Limits.
const (
	maxFailures  = 3
	retryAfter   = 24 * time.Hour
	jobLifetime  = 24 * time.Hour
	recentUpdate = 15 * time.Minute // an attempt that succeeded this recently may just not have reconnected yet
)

// Actor is who asked for something (for audit).
type Actor struct {
	Org  uuid.UUID
	User uuid.UUID
	IP   string
}

// Service owns releases and rollouts.
type Service struct {
	Pool    *pgxpool.Pool
	Deploy  *deploy.Service
	Content *catalog.Store
	Events  *events.Broker
	Log     *slog.Logger
	Now     func() time.Time
	// Keys are the vendor release public keys the server accepts for uploads
	// (default: the keys compiled into this build).
	Keys []ed25519.PublicKey
	// BundledDir holds the agent release that came with the server image (D149); empty turns that off.
	BundledDir string
	bd         bundledState
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) keys() []ed25519.PublicKey {
	if s.Keys != nil {
		return s.Keys
	}
	return release.TrustedKeys()
}

func (s *Service) publish(org uuid.UUID, device uuid.UUID) {
	if s.Events != nil {
		s.Events.Publish(org, events.Event{Type: events.UpdatesUpdated, DeviceID: device})
	}
}

// Release is one stored agent release.
type Release struct {
	ID         uuid.UUID `json:"id"`
	Version    string    `json:"version"`
	OS         string    `json:"os"`
	Arch       string    `json:"arch"`
	SHA256     string    `json:"sha256"`
	Size       int64     `json:"size"`
	KeyID      string    `json:"key_id"`
	Notes      string    `json:"notes"`
	Subject    string    `json:"authenticode_subject"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	DevicesOn  int64     `json:"devices_on"`
	IsTarget   bool      `json:"is_target"`
	MinVersion string    `json:"min_version,omitempty"`
}

func view(r dbq.AgentRelease) Release {
	v := Release{ID: r.ID, Version: r.Version, OS: r.Os, Arch: r.Arch, SHA256: hex.EncodeToString(r.Sha256), Size: r.Size, KeyID: r.KeyID,
		Notes: r.Notes, Status: r.Status, CreatedAt: r.CreatedAt}
	if m, err := release.ParseUnverified(r.Manifest); err == nil {
		v.Subject, v.MinVersion = m.AuthenticodeSubject, m.MinVersion
	}
	return v
}

// MaxBinary is the largest agent binary the server accepts.
const MaxBinary = release.MaxBinaryBytes

// AddRelease verifies a vendor bundle, stores the binary content-addressed and registers the release.
func (s *Service) AddRelease(ctx context.Context, a Actor, bundleJSON []byte, binary io.Reader) (Release, error) {
	if s.Content == nil {
		return Release{}, invalid("storage is not configured (LIBREPATCH_CONTENT_DIR)")
	}
	b, err := release.DecodeBundle(bundleJSON)
	if err != nil {
		return Release{}, invalid("%v", err)
	}
	m, err := release.Verify(s.keys(), b.Manifest, b.Signature, b.KeyID)
	if err != nil {
		return Release{}, invalid("%v", err)
	}
	limit := int64(m.Size) + 1 // #nosec G115 -- Verify bounds Size to release.MaxBinaryBytes
	sha, size, err := s.Content.Put(a.Org, io.LimitReader(binary, limit), limit)
	if err != nil {
		return Release{}, invalid("the upload failed: %v", err)
	}
	if !bytes.Equal(sha, m.SHA256Bytes()) || uint64(size) != m.Size { // #nosec G115 -- non-negative
		s.dropBlobIfUnused(ctx, a.Org, sha) // do not leave a mismatching blob behind
		return Release{}, invalid("the uploaded file does not match the signed manifest")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Release{}, err
	}
	name := "librepatch-agent-" + m.Version + ".exe"
	now := s.now()
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		// The same binary may already be stored (another release, or a custom package): the insert then only refreshes the row.
		// The release shipped inside the server image has no person behind it (a.User is the zero value): it is recorded as the system.
		var by *uuid.UUID
		actorType, actorID := audit.ActorSystem, bundledActorID
		if a.User != uuid.Nil {
			by, actorType, actorID = &a.User, audit.ActorUser, a.User.String()
		}
		if err := q.InsertContentBlob(ctx, dbq.InsertContentBlobParams{OrgID: a.Org, Sha256: sha, Size: size, FileName: name, UploadedBy: by}); err != nil {
			return err
		}
		if err := q.InsertAgentRelease(ctx, dbq.InsertAgentReleaseParams{ID: id, OrgID: a.Org, Version: m.Version, Os: m.OS, Arch: m.Arch, Sha256: sha, Size: size,
			Manifest: b.Manifest, Signature: b.Signature, KeyID: b.KeyID, Notes: m.Notes, UploadedBy: by}); err != nil {
			return err
		}
		_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &a.Org, ActorType: actorType, ActorID: actorID, ActorIP: a.IP, Action: "agent.release_add",
			TargetType: "agent_release", TargetIDs: []string{id.String()}, Outcome: audit.Success,
			Details: map[string]any{"version": m.Version, "os": m.OS, "arch": m.Arch, "sha256": m.SHA256, "key_id": b.KeyID}}, now)
		return err
	})
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == pgUniqueViolation && strings.Contains(pe.ConstraintName, "agent_releases") {
		return Release{}, fmt.Errorf("%w: version %s for %s/%s is already uploaded", ErrConflict, m.Version, m.OS, m.Arch)
	}
	if err != nil {
		return Release{}, err
	}
	r, err := dbq.New(s.Pool).GetAgentRelease(ctx, dbq.GetAgentReleaseParams{OrgID: a.Org, ID: id})
	if err != nil {
		return Release{}, err
	}
	return view(r), nil
}

const pgUniqueViolation = "23505"

// dropBlobIfUnused removes a stored file that no release and no custom package refers to. It is best effort: a file left
// behind costs disk space, never correctness.
func (s *Service) dropBlobIfUnused(ctx context.Context, org uuid.UUID, sha []byte) {
	if s.Content == nil {
		return
	}
	if n, err := dbq.New(s.Pool).CountReleaseBlobUses(ctx, dbq.CountReleaseBlobUsesParams{OrgID: org, Sha256: sha}); err == nil && n == 0 {
		_ = s.Content.Delete(org, sha)
	}
}

// Rollout is how devices converge on a release.
type Rollout struct {
	ReleaseID        *uuid.UUID     `json:"release_id"`
	PilotGroupIDs    []uuid.UUID    `json:"pilot_group_ids"`
	SoakHours        int32          `json:"soak_hours"`
	SuccessThreshold int32          `json:"success_threshold"`
	BatchPerTick     int32          `json:"batch_per_tick"`
	Window           *deploy.Window `json:"window"`
	Paused           bool           `json:"paused"`
	PausedReason     string         `json:"paused_reason"`
	StartedAt        *time.Time     `json:"started_at"`
	UpdatedAt        *time.Time     `json:"updated_at"`
	// AutoNewRelease makes a newer release that came with the server image the target by itself (D149).
	AutoNewRelease bool `json:"auto_new_release"`
}

func defaultRollout() Rollout {
	return Rollout{PilotGroupIDs: []uuid.UUID{}, SoakHours: 24, SuccessThreshold: 90, BatchPerTick: 100}
}

func rolloutView(r dbq.AgentRollout) Rollout {
	v := Rollout{ReleaseID: r.ReleaseID, PilotGroupIDs: r.PilotGroupIds, SoakHours: r.SoakHours, SuccessThreshold: r.SuccessThreshold,
		BatchPerTick: r.BatchPerTick, Paused: r.Paused, PausedReason: r.PausedReason, StartedAt: r.StartedAt, UpdatedAt: &r.UpdatedAt, AutoNewRelease: r.AutoNewRelease}
	if v.PilotGroupIDs == nil {
		v.PilotGroupIDs = []uuid.UUID{}
	}
	if len(r.MaintWindow) > 0 {
		var w deploy.Window
		if json.Unmarshal(r.MaintWindow, &w) == nil {
			v.Window = &w
		}
	}
	return v
}

// List returns the stored releases and the rollout setting.
func (s *Service) List(ctx context.Context, org uuid.UUID) ([]Release, Rollout, error) {
	q := dbq.New(s.Pool)
	rows, err := q.ListAgentReleases(ctx, org)
	if err != nil {
		return nil, Rollout{}, err
	}
	ro := defaultRollout()
	if r, err := q.GetAgentRollout(ctx, org); err == nil {
		ro = rolloutView(r)
	}
	out := make([]Release, 0, len(rows))
	for _, r := range rows {
		v := view(dbq.AgentRelease{ID: r.ID, OrgID: r.OrgID, Version: r.Version, Os: r.Os, Arch: r.Arch, Sha256: r.Sha256, Size: r.Size, Manifest: r.Manifest,
			Signature: r.Signature, KeyID: r.KeyID, Notes: r.Notes, Status: r.Status, UploadedBy: r.UploadedBy, CreatedAt: r.CreatedAt})
		v.DevicesOn = r.DevicesOn
		v.IsTarget = ro.ReleaseID != nil && *ro.ReleaseID == r.ID
		out = append(out, v)
	}
	return out, ro, nil
}

// SetStatus withdraws a release (never offered again) or makes it available again.
func (s *Service) SetStatus(ctx context.Context, a Actor, id uuid.UUID, status string) error {
	if status != "available" && status != "withdrawn" {
		return invalid("status must be available or withdrawn")
	}
	return s.audited(ctx, a, "agent.release_"+status, id, func(q *dbq.Queries) error {
		n, err := q.SetAgentReleaseStatus(ctx, dbq.SetAgentReleaseStatusParams{OrgID: a.Org, ID: id, Status: status})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		if status == "withdrawn" {
			// A withdrawn target stops the rollout.
			if ro, err := q.GetAgentRollout(ctx, a.Org); err == nil && ro.ReleaseID != nil && *ro.ReleaseID == id {
				return q.PauseAgentRollout(ctx, dbq.PauseAgentRolloutParams{OrgID: a.Org, PausedReason: "the target release was withdrawn"})
			}
		}
		return nil
	})
}

// Delete removes a release that is not the rollout target.
func (s *Service) Delete(ctx context.Context, a Actor, id uuid.UUID) error {
	var sha []byte
	err := s.audited(ctx, a, "agent.release_delete", id, func(q *dbq.Queries) error {
		r, err := q.GetAgentRelease(ctx, dbq.GetAgentReleaseParams{OrgID: a.Org, ID: id})
		if err != nil {
			return ErrNotFound
		}
		n, err := q.DeleteAgentRelease(ctx, dbq.DeleteAgentReleaseParams{OrgID: a.Org, ID: id})
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("%w: this release is the rollout target", ErrConflict)
		}
		sha = r.Sha256
		return nil
	})
	if err != nil {
		return err
	}
	// Only once the deletion is committed: a rolled-back transaction must not leave a release without its file.
	s.dropBlobIfUnused(ctx, a.Org, sha)
	return nil
}

func (s *Service) audited(ctx context.Context, a Actor, action string, target uuid.UUID, fn func(q *dbq.Queries) error) error {
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := fn(q); err != nil {
			return err
		}
		_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &a.Org, ActorType: audit.ActorUser, ActorID: a.User.String(), ActorIP: a.IP, Action: action,
			TargetType: "agent_release", TargetIDs: []string{target.String()}, Outcome: audit.Success}, s.now())
		return err
	})
}

// SetRollout chooses the target release and how to get there. ReleaseID nil stops updating.
func (s *Service) SetRollout(ctx context.Context, a Actor, in Rollout) error {
	if in.SoakHours < 0 || in.SoakHours > 720 || in.SuccessThreshold < 1 || in.SuccessThreshold > 100 || in.BatchPerTick < 1 || in.BatchPerTick > 1000 {
		return invalid("soak, threshold or batch size out of range")
	}
	if len(in.PilotGroupIDs) > 50 {
		return invalid("too many pilot groups")
	}
	win, err := deploy.WindowProto(in.Window)
	if err != nil {
		return invalid("%v", err)
	}
	_ = win
	var winJSON []byte
	if in.Window != nil {
		winJSON, _ = json.Marshal(in.Window)
	}
	now := s.now()
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		var started *time.Time
		prev, perr := q.GetAgentRollout(ctx, a.Org)
		if in.ReleaseID != nil {
			r, err := q.GetAgentRelease(ctx, dbq.GetAgentReleaseParams{OrgID: a.Org, ID: *in.ReleaseID})
			if err != nil {
				return invalid("unknown release")
			}
			if r.Status != "available" {
				return invalid("that release is withdrawn")
			}
			if perr == nil && prev.ReleaseID != nil && *prev.ReleaseID == *in.ReleaseID {
				started = prev.StartedAt // same target: keep the pilot's clock
			} else {
				started = &now
			}
		}
		reason := ""
		if in.Paused {
			reason = "paused by an administrator"
		}
		pilots := in.PilotGroupIDs
		if pilots == nil {
			pilots = []uuid.UUID{}
		}
		if err := q.UpsertAgentRollout(ctx, dbq.UpsertAgentRolloutParams{OrgID: a.Org, ReleaseID: in.ReleaseID, PilotGroupIds: pilots, SoakHours: in.SoakHours,
			SuccessThreshold: in.SuccessThreshold, BatchPerTick: in.BatchPerTick, MaintWindow: winJSON, Paused: in.Paused, PausedReason: reason, StartedAt: started, UpdatedBy: &a.User, AutoNewRelease: in.AutoNewRelease}); err != nil {
			return err
		}
		det := map[string]any{"paused": in.Paused, "pilot_groups": len(pilots), "soak_hours": in.SoakHours, "threshold": in.SuccessThreshold, "auto_new_release": in.AutoNewRelease}
		if in.ReleaseID != nil {
			det["release"] = in.ReleaseID.String()
		}
		_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &a.Org, ActorType: audit.ActorUser, ActorID: a.User.String(), ActorIP: a.IP, Action: "agent.rollout_set",
			TargetType: "organization", TargetIDs: []string{a.Org.String()}, Outcome: audit.Success, Details: det}, now)
		return err
	})
}

// Status is the rollout's progress for the console.
type Status struct {
	Versions     []VersionCount `json:"versions"`
	Updated      int64          `json:"updated"`
	Failed       int64          `json:"failed"`
	Queued       int64          `json:"queued"`
	PilotDevices int            `json:"pilot_devices"`
	PilotUpdated int64          `json:"pilot_updated"`
	PilotFailed  int64          `json:"pilot_failed"`
	// Waiting says why devices outside the pilot are not being updated yet ("" = they are).
	Waiting string `json:"waiting"`
}

// VersionCount is how many active devices run a version.
type VersionCount struct {
	Version string `json:"version"`
	Devices int64  `json:"devices"`
	Online  int64  `json:"online"`
}

// Status reports progress.
func (s *Service) Status(ctx context.Context, org uuid.UUID) (Status, error) {
	q := dbq.New(s.Pool)
	st := Status{Versions: []VersionCount{}}
	rows, err := q.CountDevicesByAgentVersion(ctx, org)
	if err != nil {
		return st, err
	}
	for _, r := range rows {
		v := r.AgentVersion
		if v == "" {
			v = "(unknown)"
		}
		st.Versions = append(st.Versions, VersionCount{Version: v, Devices: r.Devices, Online: r.Online})
	}
	ro, err := q.GetAgentRollout(ctx, org)
	if err != nil || ro.ReleaseID == nil {
		return st, nil
	}
	if p, err := q.AgentRolloutProgress(ctx, *ro.ReleaseID); err == nil {
		st.Updated, st.Failed, st.Queued = p.Updated, p.Failed, p.Queued
	}
	if len(ro.PilotGroupIds) > 0 {
		pilots, _ := s.pilotSet(ctx, org, ro.PilotGroupIds)
		st.PilotDevices = len(pilots)
		if ps, err := q.AgentPilotStats(ctx, *ro.ReleaseID); err == nil {
			st.PilotUpdated, st.PilotFailed = ps.Updated, ps.Failed
			_, st.Waiting = s.gate(ro, len(pilots), ps)
		}
	}
	return st, nil
}

func (s *Service) pilotSet(ctx context.Context, org uuid.UUID, groups []uuid.UUID) (map[uuid.UUID]bool, error) {
	devs, err := s.Deploy.ResolveTargets(ctx, org, groups, nil)
	if err != nil {
		return nil, err
	}
	m := make(map[uuid.UUID]bool, len(devs))
	for _, d := range devs {
		m[d.ID] = true
	}
	return m, nil
}

// gate decides whether devices outside the pilot may be updated. It returns (true, "") or
// (false, reason). hold=true cases (failure rate too high) are handled by the caller.
func (s *Service) gate(ro dbq.AgentRollout, pilotN int, ps dbq.AgentPilotStatsRow) (bool, string) {
	if pilotN == 0 {
		return false, "the pilot groups have no active devices"
	}
	if ps.Queued > 0 {
		return false, "pilot devices are still updating"
	}
	need := (int64(pilotN)*int64(ro.SuccessThreshold) + 99) / 100
	if ps.Updated < need {
		return false, fmt.Sprintf("%d of %d pilot devices updated, %d%% needed", ps.Updated, pilotN, ro.SuccessThreshold)
	}
	if ps.LastUpdatedUnix > 0 {
		if until := time.Unix(ps.LastUpdatedUnix, 0).Add(time.Duration(ro.SoakHours) * time.Hour); s.now().Before(until) {
			return false, "the pilot is soaking until " + until.Format(time.RFC3339)
		}
	}
	return true, ""
}

// Tick plans update jobs for every organization with an active rollout.
func (s *Service) Tick(ctx context.Context) {
	q := dbq.New(s.Pool)
	ros, err := q.ListActiveRollouts(ctx)
	if err != nil {
		s.log().Error("agent rollouts", "err", err)
		return
	}
	for _, ro := range ros {
		if ctx.Err() != nil {
			return
		}
		if err := s.tickOrg(ctx, ro); err != nil {
			s.log().Error("agent rollout", "org", ro.OrgID, "err", err)
		}
	}
}

func (s *Service) tickOrg(ctx context.Context, ro dbq.AgentRollout) error {
	q := dbq.New(s.Pool)
	rel, err := q.GetAgentRelease(ctx, dbq.GetAgentReleaseParams{OrgID: ro.OrgID, ID: *ro.ReleaseID})
	if err != nil || rel.Status != "available" {
		return nil
	}
	m, err := release.ParseUnverified(rel.Manifest)
	if err != nil {
		return err
	}
	cands, err := q.ListAgentUpdateCandidates(ctx, dbq.ListAgentUpdateCandidatesParams{OrgID: ro.OrgID, ReleaseID: rel.ID, Version: rel.Version})
	if err != nil {
		return err
	}
	now := s.now()
	var todo []dbq.ListAgentUpdateCandidatesRow
	for _, c := range cands {
		if c.AgentVersion == "" || vercmp.Key(c.AgentVersion) == nil {
			continue
		}
		if m.CheckApplicable(c.AgentVersion, m.OS, m.Arch) != nil {
			continue
		}
		if c.AttemptState != nil {
			fin := time.Time{}
			if c.AttemptFinished != nil {
				fin = *c.AttemptFinished
			}
			switch *c.AttemptState {
			case "failed":
				if (c.AttemptFailures != nil && *c.AttemptFailures >= maxFailures) || now.Sub(fin) < retryAfter {
					continue
				}
			case "updated":
				if now.Sub(fin) < recentUpdate {
					continue
				}
			}
		}
		todo = append(todo, c)
	}
	if len(todo) == 0 {
		return nil
	}
	pilot := map[uuid.UUID]bool{}
	allowOthers := true
	if len(ro.PilotGroupIds) > 0 {
		if pilot, err = s.pilotSet(ctx, ro.OrgID, ro.PilotGroupIds); err != nil {
			return err
		}
		ps, err := q.AgentPilotStats(ctx, rel.ID)
		if err != nil {
			return err
		}
		allowed := int64(len(pilot)) * int64(100-ro.SuccessThreshold) / 100
		if ps.Failed > allowed {
			reason := fmt.Sprintf("the pilot failed: %d of %d devices could not update (at most %d allowed)", ps.Failed, len(pilot), allowed)
			if err := q.PauseAgentRollout(ctx, dbq.PauseAgentRolloutParams{OrgID: ro.OrgID, PausedReason: reason}); err != nil {
				return err
			}
			_ = audit.Log(ctx, s.Pool, audit.Entry{OrgID: &ro.OrgID, ActorType: audit.ActorSystem, Action: "agent.rollout_hold", TargetType: "agent_release",
				TargetIDs: []string{rel.ID.String()}, Outcome: audit.Error, Details: map[string]any{"reason": reason, "version": rel.Version}})
			s.log().Warn("agent rollout paused", "org", ro.OrgID, "reason", reason)
			return nil
		}
		allowOthers, _ = s.gate(ro, len(pilot), ps)
	}
	var win *agentv1.MaintenanceWindow
	if len(ro.MaintWindow) > 0 {
		var w deploy.Window
		if json.Unmarshal(ro.MaintWindow, &w) == nil {
			win, _ = deploy.WindowProto(&w)
		}
	}
	keyID, _ := hex.DecodeString(rel.KeyID)
	body := func() *agentv1.AgentUpdateBody {
		return &agentv1.AgentUpdateBody{Manifest: rel.Manifest, Signature: rel.Signature, KeyId: keyID, TimeoutS: 1800}
	}
	// Pilot devices first, then (when the gate is open) everyone else, online devices before offline ones.
	var ordered []dbq.ListAgentUpdateCandidatesRow
	for _, c := range todo {
		if pilot[c.ID] {
			ordered = append(ordered, c)
		}
	}
	if allowOthers {
		for _, c := range todo {
			if !pilot[c.ID] {
				ordered = append(ordered, c)
			}
		}
	}
	if len(ordered) > int(ro.BatchPerTick) {
		ordered = ordered[:ro.BatchPerTick]
	}
	for _, c := range ordered {
		job, err := s.Deploy.NewJob(ro.OrgID, c.ID, deploy.JobSpec{Type: agentv1.JobType_JOB_TYPE_AGENT_UPDATE, DBType: "agent_update",
			Title: "Update the " + brand.Name + " agent to " + rel.Version, Body: body(), NotBefore: now, Expires: now.Add(jobLifetime), Window: win})
		if err != nil {
			return err
		}
		err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
			if err := q.InsertJob(ctx, job); err != nil {
				return err
			}
			return q.UpsertAgentAttemptQueued(ctx, dbq.UpsertAgentAttemptQueuedParams{DeviceID: c.ID, ReleaseID: rel.ID, OrgID: ro.OrgID, JobID: &job.ID, Pilot: pilot[c.ID], CreatedAt: now})
		})
		if err != nil {
			return err
		}
		s.Deploy.Publish(ro.OrgID, "job.updated", c.ID, job.ID, uuid.Nil)
		s.Deploy.DispatchAsync(c.ID)
	}
	return nil
}

// AfterJob records the outcome of an agent update job (hooked into deploy.Service).
func (s *Service) AfterJob(ctx context.Context, j dbq.Job, status string, u *agentv1.JobUpdate) {
	if j.Type != "agent_update" {
		return
	}
	q := dbq.New(s.Pool)
	switch status {
	case "expired", "cancelled":
		if err := q.DeleteQueuedAgentAttemptOfJob(ctx, &j.ID); err != nil {
			s.log().Error("release agent attempt", "job", j.ID, "err", err)
		}
		return
	}
	at, err := q.GetAgentAttemptByJob(ctx, &j.ID)
	if err != nil {
		return
	}
	state, msg := "failed", ""
	if status == "succeeded" {
		state = "updated"
	}
	if u != nil && u.Result != nil {
		msg = u.Result.Message
	}
	if err := q.FinishAgentAttempt(ctx, dbq.FinishAgentAttemptParams{State: state, LastError: text.Truncate(msg, 512), At: ptr.Of(s.now()), DeviceID: at.DeviceID, ReleaseID: at.ReleaseID}); err != nil {
		s.log().Error("record agent update result", "job", j.ID, "err", err)
	}
	s.publish(j.OrgID, j.DeviceID)
}
