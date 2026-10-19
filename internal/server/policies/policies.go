// Package policies runs software policies: "keep this package at its newest version on these
// groups" and "install this package on newly enrolled devices of these groups". A policy never
// reaches around the deployment engine: each run creates an ordinary deployment (so the same
// signing, verification, windows, results and audit apply) for the devices that need it.
package policies

import (
	"context"
	"encoding/json"
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
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/store"
)

// Errors the API maps to HTTP statuses.
var (
	ErrInvalid  = errors.New("policies: invalid request")
	ErrNotFound = errors.New("policies: not found")
	ErrConflict = errors.New("policies: conflict")
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Limits.
const (
	maxDevicesPerRun = 200
	maxFailures      = 3
	retryAfter       = 24 * time.Hour
	inventoryLag     = 2 * time.Hour // a finished job needs a while to show up in the inventory
	deployLifetime   = 72 * time.Hour
)

// Actor is who asked for something (for audit).
type Actor struct {
	Org  uuid.UUID
	User uuid.UUID
	IP   string
}

// Service owns software policies.
type Service struct {
	Pool   *pgxpool.Pool
	Deploy *deploy.Service
	Log    *slog.Logger
	Now    func() time.Time
	// OnHold is called when a ring misses its success threshold for a software version (hooked to a notification).
	OnHold func(ctx context.Context, org uuid.UUID, title, ring, reason string)
	// OnApprovalNeeded is called when a version waits for an administrator's decision (a notification; it de-duplicates).
	OnApprovalNeeded func(ctx context.Context, org uuid.UUID, pkg, version string)

	ringc ringCaches
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

// Policy is the console's view of a software policy.
type Policy struct {
	ID                  uuid.UUID      `json:"id"`
	Name                string         `json:"name"`
	Kind                string         `json:"kind"`
	PackageID           uuid.UUID      `json:"package_id"`
	PackageName         string         `json:"package_name"`
	PackageIdentifier   string         `json:"package_identifier"`
	GroupIDs            []uuid.UUID    `json:"group_ids"`
	DelayDays           int32          `json:"delay_days"`
	OnlyNewDevices      bool           `json:"only_new_devices"`
	UnverifiedConfirmed bool           `json:"unverified_confirmed"`
	Window              *deploy.Window `json:"window"`
	Enabled             bool           `json:"enabled"`
	UseRings            bool           `json:"use_rings"`
	RequireApproval     bool           `json:"require_approval"`
	CreatedAt           time.Time      `json:"created_at"`
	Devices             int64          `json:"devices_attempted"`
	// Rollout is the state of the newest version for a policy that uses rings or approval; null otherwise.
	Rollout *RolloutView `json:"rollout"`
}

// Input is what an administrator submits.
type Input struct {
	Name                string         `json:"name"`
	Kind                string         `json:"kind"`
	PackageID           uuid.UUID      `json:"package_id"`
	GroupIDs            []uuid.UUID    `json:"group_ids"`
	DelayDays           int32          `json:"delay_days"`
	OnlyNewDevices      bool           `json:"only_new_devices"`
	UnverifiedConfirmed bool           `json:"unverified_confirmed"`
	Window              *deploy.Window `json:"window"`
	Enabled             bool           `json:"enabled"`
	UseRings            bool           `json:"use_rings"`
	RequireApproval     bool           `json:"require_approval"`
}

func (s *Service) validate(ctx context.Context, org uuid.UUID, in *Input) ([]byte, error) {
	in.Name = strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(in.Name); n < 1 || n > 200 {
		return nil, invalid("the name must be 1 to 200 characters")
	}
	if in.Kind != "keep_updated" && in.Kind != "baseline" {
		return nil, invalid("kind must be keep_updated or baseline")
	}
	if len(in.GroupIDs) == 0 || len(in.GroupIDs) > 50 {
		return nil, invalid("choose 1 to 50 groups")
	}
	if in.UseRings && in.Kind != "keep_updated" {
		return nil, invalid("rings apply to keep-updated policies; a baseline installs on new devices only")
	}
	if in.DelayDays < 0 || in.DelayDays > 365 {
		return nil, invalid("the delay must be 0 to 365 days")
	}
	q := dbq.New(s.Pool)
	pkg, err := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: in.PackageID, OrgID: org})
	if err != nil {
		return nil, invalid("unknown package")
	}
	if pkg.Source == "winget" && !pkg.Verified && !in.UnverifiedConfirmed {
		return nil, invalid("this winget package has not been verified on test machines; confirm that you accept that before automating it")
	}
	for _, g := range in.GroupIDs {
		if _, err := q.GetGroup(ctx, dbq.GetGroupParams{ID: g, OrgID: org}); err != nil {
			return nil, invalid("unknown group")
		}
	}
	if _, err := deploy.WindowProto(in.Window); err != nil {
		return nil, invalid("%v", err)
	}
	var win []byte
	if in.Window != nil {
		win, _ = json.Marshal(in.Window)
	}
	return win, nil
}

func isUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// Create stores a policy.
func (s *Service) Create(ctx context.Context, a Actor, in Input) (uuid.UUID, error) {
	win, err := s.validate(ctx, a.Org, &in)
	if err != nil {
		return uuid.Nil, err
	}
	id := uuid.New()
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.InsertSoftwarePolicy(ctx, dbq.InsertSoftwarePolicyParams{ID: id, OrgID: a.Org, Name: in.Name, Kind: in.Kind, PackageID: in.PackageID, GroupIds: in.GroupIDs,
			DelayDays: in.DelayDays, OnlyNewDevices: in.OnlyNewDevices, UnverifiedConfirmed: in.UnverifiedConfirmed, MaintWindow: win, Enabled: in.Enabled, CreatedBy: &a.User, UseRings: in.UseRings, RequireApproval: in.RequireApproval}); err != nil {
			return err
		}
		return s.audit(ctx, tx, a, "policy.create", id, map[string]any{"name": in.Name, "kind": in.Kind, "package": in.PackageID.String(), "groups": len(in.GroupIDs), "rings": in.UseRings, "approval": in.RequireApproval})
	})
	if isUnique(err) {
		return uuid.Nil, fmt.Errorf("%w: a policy with that name already exists", ErrConflict)
	}
	return id, err
}

// Update replaces a policy.
func (s *Service) Update(ctx context.Context, a Actor, id uuid.UUID, in Input) error {
	win, err := s.validate(ctx, a.Org, &in)
	if err != nil {
		return err
	}
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		n, err := q.UpdateSoftwarePolicy(ctx, dbq.UpdateSoftwarePolicyParams{ID: id, OrgID: a.Org, Name: in.Name, Kind: in.Kind, PackageID: in.PackageID, GroupIds: in.GroupIDs,
			DelayDays: in.DelayDays, OnlyNewDevices: in.OnlyNewDevices, UnverifiedConfirmed: in.UnverifiedConfirmed, MaintWindow: win, Enabled: in.Enabled, UseRings: in.UseRings, RequireApproval: in.RequireApproval})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		return s.audit(ctx, tx, a, "policy.update", id, map[string]any{"name": in.Name, "enabled": in.Enabled, "rings": in.UseRings, "approval": in.RequireApproval})
	})
	if isUnique(err) {
		return fmt.Errorf("%w: a policy with that name already exists", ErrConflict)
	}
	return err
}

// Delete removes a policy (deployments it already created keep running).
func (s *Service) Delete(ctx context.Context, a Actor, id uuid.UUID) error {
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		n, err := q.DeleteSoftwarePolicy(ctx, dbq.DeleteSoftwarePolicyParams{ID: id, OrgID: a.Org})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		return s.audit(ctx, tx, a, "policy.delete", id, nil)
	})
}

func (s *Service) audit(ctx context.Context, tx pgx.Tx, a Actor, action string, id uuid.UUID, details map[string]any) error {
	_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &a.Org, ActorType: audit.ActorUser, ActorID: a.User.String(), ActorIP: a.IP, Action: action,
		TargetType: "policy", TargetIDs: []string{id.String()}, Outcome: audit.Success, Details: details}, s.now())
	return err
}

// List returns the policies of an organization.
func (s *Service) List(ctx context.Context, org uuid.UUID) ([]Policy, error) {
	q := dbq.New(s.Pool)
	rows, err := q.ListSoftwarePolicies(ctx, org)
	if err != nil {
		return nil, err
	}
	out := make([]Policy, 0, len(rows))
	for _, r := range rows {
		p := Policy{ID: r.ID, Name: r.Name, Kind: r.Kind, PackageID: r.PackageID, PackageName: r.PackageName, PackageIdentifier: r.PackageIdentifier, GroupIDs: r.GroupIds,
			DelayDays: r.DelayDays, OnlyNewDevices: r.OnlyNewDevices, UnverifiedConfirmed: r.UnverifiedConfirmed, Enabled: r.Enabled, UseRings: r.UseRings, RequireApproval: r.RequireApproval, CreatedAt: r.CreatedAt}
		if len(r.MaintWindow) > 0 {
			var w deploy.Window
			if json.Unmarshal(r.MaintWindow, &w) == nil {
				p.Window = &w
			}
		}
		if st, err := q.PolicyAttemptStats(ctx, r.ID); err == nil {
			p.Devices = st.Devices
		}
		if r.Enabled && (r.UseRings || r.RequireApproval) {
			if ro, err := s.plan(ctx, policyRow(r), s.now()); err == nil {
				p.Rollout = ro.view()
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// Tick runs every enabled policy once.
func (s *Service) Tick(ctx context.Context) {
	ps, err := dbq.New(s.Pool).ListEnabledSoftwarePolicies(ctx)
	if err != nil {
		s.log().Error("software policies", "err", err)
		return
	}
	for _, p := range ps {
		if ctx.Err() != nil {
			return
		}
		if err := s.run(ctx, p); err != nil {
			s.log().Error("software policy", "policy", p.ID, "name", p.Name, "err", err)
		}
	}
}

func (s *Service) run(ctx context.Context, p dbq.SoftwarePolicy) error {
	now := s.now()
	ro, err := s.plan(ctx, p, now)
	if err != nil || ro == nil || ro.ver == nil {
		return err
	}
	// A ring that missed its threshold holds the version back from the later rings.
	for _, st := range ro.stages {
		if st.ring != nil && st.holdReason != "" {
			s.raiseHold(ctx, ro, st, now)
		}
	}
	if ro.blocked != "" {
		if ro.blocked == blockPending && len(ro.all) > 0 && s.OnApprovalNeeded != nil {
			s.OnApprovalNeeded(ctx, p.OrgID, ro.pkg.Name, ro.ver.Version)
		}
		return nil
	}
	if p.CreatedBy == nil {
		return nil // the person who made the policy was deleted; deployments need an owner on record
	}
	q := dbq.New(s.Pool)
	budget := maxDevicesPerRun
	for _, st := range ro.stages {
		if !st.eligible || len(st.cands) == 0 || budget <= 0 {
			continue
		}
		eligible, fails, err := s.filterAttempts(ctx, p, ro.ver.Version, st.cands, now)
		if err != nil {
			return err
		}
		if len(eligible) > budget {
			eligible = eligible[:budget]
		}
		if len(eligible) == 0 {
			continue
		}
		budget -= len(eligible)
		name := fmt.Sprintf("Policy %s: %s %s", p.Name, ro.pkg.Name, ro.ver.Version)
		if st.ring != nil {
			name += " (" + st.ring.Name + ")"
		}
		plan, err := s.Deploy.Create(ctx, p.OrgID, deploy.Request{Name: name, Action: ro.action, PackageID: ro.pkg.ID,
			Version: ro.ver.Version, Scope: "machine", DeviceIDs: eligible, ExpiresIn: deployLifetime, Window: windowOf(p, st), UnverifiedConfirmed: p.UnverifiedConfirmed,
			Policy: p.ID.String(), UserID: *p.CreatedBy})
		if err != nil {
			return err
		}
		s.log().Debug("policy deployment created", "policy", p.Name, "stage", st.name, "devices", len(eligible), "jobs", plan.Jobs, "skipped", plan.Skipped)
		for _, d := range eligible {
			if err := q.UpsertPolicyAttempt(ctx, dbq.UpsertPolicyAttemptParams{PolicyID: p.ID, DeviceID: d, Version: ro.ver.Version, DeploymentID: &plan.DeploymentID, Failures: fails[d], CreatedAt: now}); err != nil {
				return err
			}
		}
	}
	return nil
}

// filterAttempts drops devices a policy already handled for this version: a job still running, one
// that just finished (the inventory needs time), and devices that failed three times; failed ones
// are retried no sooner than a day after the last try.
func (s *Service) filterAttempts(ctx context.Context, p dbq.SoftwarePolicy, version string, cands []uuid.UUID, now time.Time) ([]uuid.UUID, map[uuid.UUID]int32, error) {
	q := dbq.New(s.Pool)
	atts, err := q.ListPolicyAttempts(ctx, dbq.ListPolicyAttemptsParams{PolicyID: p.ID, Column2: cands})
	if err != nil {
		return nil, nil, err
	}
	by := map[uuid.UUID]dbq.PolicyAttempt{}
	var deps []uuid.UUID
	for _, a := range atts {
		by[a.DeviceID] = a
		if a.DeploymentID != nil {
			deps = append(deps, *a.DeploymentID)
		}
	}
	type key struct{ dep, dev uuid.UUID }
	open := map[key]bool{}
	if len(deps) > 0 {
		states, err := q.PolicyJobStates(ctx, deps)
		if err != nil {
			return nil, nil, err
		}
		for _, st := range states {
			if st.DeploymentID != nil {
				open[key{*st.DeploymentID, st.DeviceID}] = st.IsOpen
			}
		}
	}
	fails := map[uuid.UUID]int32{}
	var out []uuid.UUID
	for _, c := range cands {
		a, ok := by[c]
		if !ok || a.Version != version {
			out = append(out, c) // first time for this version
			continue
		}
		if a.DeploymentID != nil && open[key{*a.DeploymentID, c}] {
			continue
		}
		if now.Sub(a.CreatedAt) < inventoryLag || a.Failures >= maxFailures || now.Sub(a.CreatedAt) < retryAfter {
			continue
		}
		fails[c] = a.Failures + 1
		out = append(out, c)
	}
	return out, fails, nil
}
