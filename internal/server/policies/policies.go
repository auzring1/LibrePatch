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
	"sort"
	"strings"
	"sync"
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
	// Import adds an app from the public winget index to the catalog and returns its package id (an all-apps policy
	// that includes apps not in the catalog yet, D132). nil = no import.
	Import func(ctx context.Context, org, user uuid.UUID, wingetID string) (uuid.UUID, error)

	ringc ringCaches
	fleet fleetCache
}

// fleetCache keeps the fleet's available updates for the length of one Tick: every policy of the tick reads the same list,
// so a few hundred policies cost one query, not one each. Outside a tick (the console listing policies) nothing is kept.
type fleetCache struct {
	mu     sync.Mutex
	active bool
	byOrg  map[uuid.UUID][]deploy.FleetUpdate
}

func (s *Service) fleetUpdates(ctx context.Context, org uuid.UUID) ([]deploy.FleetUpdate, error) {
	s.fleet.mu.Lock()
	if ups, ok := s.fleet.byOrg[org]; ok && s.fleet.active {
		s.fleet.mu.Unlock()
		return ups, nil
	}
	s.fleet.mu.Unlock()
	ups, err := s.Deploy.FleetUpdates(ctx, org)
	if err != nil {
		return nil, err
	}
	s.fleet.mu.Lock()
	if s.fleet.active {
		s.fleet.byOrg[org] = ups
	}
	s.fleet.mu.Unlock()
	return ups, nil
}

func (s *Service) fleetBegin() {
	s.fleet.mu.Lock()
	s.fleet.active, s.fleet.byOrg = true, map[uuid.UUID][]deploy.FleetUpdate{}
	s.fleet.mu.Unlock()
}

func (s *Service) fleetEnd() {
	s.fleet.mu.Lock()
	s.fleet.active, s.fleet.byOrg = false, nil
	s.fleet.mu.Unlock()
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
	PackageID           *uuid.UUID     `json:"package_id"` // null for an all-apps policy
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
	// Prompts are the optional messages to the signed-in user (D124); null = silent.
	Prompts   *deploy.Prompts `json:"prompts"`
	CreatedAt time.Time       `json:"created_at"`
	Devices   int64           `json:"devices_attempted"`
	// Rollout is the state of the newest version for a policy that uses rings or approval; null otherwise.
	Rollout *RolloutView `json:"rollout"`
	// What the last check found (D132). State is one of the State* codes; StateText says it in words.
	State            string     `json:"state"`
	StateText        string     `json:"state_text"`
	LastCheckAt      *time.Time `json:"last_check_at"`
	NextCheckAt      *time.Time `json:"next_check_at"`
	LastRunAt        *time.Time `json:"last_run_at"`
	LastDeploymentID *uuid.UUID `json:"last_deployment_id"`
	// Auto is true for an all-apps policy: it has no package of its own, Apps counts the apps it handles now and
	// AppStates counts them by state. Filter says which apps it handles.
	Auto      bool             `json:"auto"`
	Filter    *AutoFilter      `json:"filter,omitempty"`
	Apps      int64            `json:"apps"`
	AppStates map[string]int64 `json:"app_states,omitempty"`
}

// statusFields fills in the status of a policy from what its last check recorded.
func (p *Policy) statusFields(checked *time.Time, state, detail string, enabled bool) {
	p.LastCheckAt = checked
	if checked != nil {
		n := checked.Add(CheckEvery)
		p.NextCheckAt = &n
	}
	switch {
	case !enabled:
		p.State, p.StateText, p.NextCheckAt = StateOff, "The policy is switched off.", nil
	case state == "":
		p.State, p.StateText = StateNew, "Not checked yet. The server checks every policy every five minutes."
	default:
		p.State, p.StateText = state, detail
	}
}

// Input is what an administrator submits.
type Input struct {
	Name                string          `json:"name"`
	Kind                string          `json:"kind"`
	PackageID           uuid.UUID       `json:"package_id"`
	GroupIDs            []uuid.UUID     `json:"group_ids"`
	DelayDays           int32           `json:"delay_days"`
	OnlyNewDevices      bool            `json:"only_new_devices"`
	UnverifiedConfirmed bool            `json:"unverified_confirmed"`
	Window              *deploy.Window  `json:"window"`
	Enabled             bool            `json:"enabled"`
	UseRings            bool            `json:"use_rings"`
	RequireApproval     bool            `json:"require_approval"`
	Prompts             *deploy.Prompts `json:"prompts"`
	// Filter is for an all-apps policy (kind keep_all), which has no package of its own.
	Filter *AutoFilter `json:"filter,omitempty"`
}

func (s *Service) validate(ctx context.Context, org uuid.UUID, in *Input) ([]byte, error) {
	in.Name = strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(in.Name); n < 1 || n > 200 {
		return nil, invalid("the name must be 1 to 200 characters")
	}
	if in.Kind != "keep_updated" && in.Kind != "baseline" && in.Kind != KindAll {
		return nil, invalid("kind must be keep_updated, keep_all or baseline")
	}
	if len(in.GroupIDs) == 0 || len(in.GroupIDs) > 50 {
		return nil, invalid("choose 1 to 50 groups")
	}
	if in.UseRings && in.Kind == "baseline" {
		return nil, invalid("rings apply to keep-updated policies; a baseline installs on new devices only")
	}
	if in.DelayDays < 0 || in.DelayDays > 365 {
		return nil, invalid("the delay must be 0 to 365 days")
	}
	q := dbq.New(s.Pool)
	var pkg dbq.CatalogPackage
	if in.Kind == KindAll {
		if err := validateAuto(in); err != nil {
			return nil, err
		}
	} else {
		var err error
		if pkg, err = q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: in.PackageID, OrgID: org}); err != nil {
			return nil, invalid("unknown package")
		}
	}
	if pkg.Source == "winget" && !pkg.Verified && !in.UnverifiedConfirmed {
		return nil, invalid("this winget package has not been verified on test machines; confirm that you accept that before automating it")
	}
	pr, err := in.Prompts.Validate()
	if err != nil {
		return nil, invalid("%v", strings.TrimPrefix(err.Error(), deploy.ErrInvalid.Error()+": "))
	}
	in.Prompts = pr
	if in.Kind != KindAll { // an all-apps policy adapts the choice to each app it adds
		if err := s.Deploy.CheckPrograms(ctx, org, pkg, pr); err != nil {
			return nil, invalid("%v", strings.TrimPrefix(err.Error(), deploy.ErrInvalid.Error()+": "))
		}
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
	if in.Kind == KindAll {
		return s.createAuto(ctx, a, in, win)
	}
	id := uuid.New()
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.InsertSoftwarePolicy(ctx, dbq.InsertSoftwarePolicyParams{ID: id, OrgID: a.Org, Name: in.Name, Kind: in.Kind, PackageID: in.PackageID, GroupIds: in.GroupIDs,
			DelayDays: in.DelayDays, OnlyNewDevices: in.OnlyNewDevices, UnverifiedConfirmed: in.UnverifiedConfirmed, MaintWindow: win, Enabled: in.Enabled, CreatedBy: &a.User, UseRings: in.UseRings, RequireApproval: in.RequireApproval, Prompts: deploy.MarshalPrompts(in.Prompts)}); err != nil {
			return err
		}
		return s.audit(ctx, tx, a, "policy.create", id, map[string]any{"name": in.Name, "kind": in.Kind, "package": in.PackageID.String(), "groups": len(in.GroupIDs), "rings": in.UseRings, "approval": in.RequireApproval, "prompts": !in.Prompts.Silent()})
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
	if in.Kind == KindAll {
		return s.updateAuto(ctx, a, id, in, win)
	}
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		n, err := q.UpdateSoftwarePolicy(ctx, dbq.UpdateSoftwarePolicyParams{ID: id, OrgID: a.Org, Name: in.Name, Kind: in.Kind, PackageID: in.PackageID, GroupIds: in.GroupIDs,
			DelayDays: in.DelayDays, OnlyNewDevices: in.OnlyNewDevices, UnverifiedConfirmed: in.UnverifiedConfirmed, MaintWindow: win, Enabled: in.Enabled, UseRings: in.UseRings, RequireApproval: in.RequireApproval, Prompts: deploy.MarshalPrompts(in.Prompts)})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		return s.audit(ctx, tx, a, "policy.update", id, map[string]any{"name": in.Name, "enabled": in.Enabled, "rings": in.UseRings, "approval": in.RequireApproval, "prompts": !in.Prompts.Silent()})
	})
	if isUnique(err) {
		return fmt.Errorf("%w: a policy with that name already exists", ErrConflict)
	}
	return err
}

// Delete removes a policy (deployments it already created keep running).
func (s *Service) Delete(ctx context.Context, a Actor, id uuid.UUID) error {
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		n, err := q.DeleteSoftwarePolicy(ctx, dbq.DeleteSoftwarePolicyParams{ID: id, OrgID: a.Org})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		return s.audit(ctx, tx, a, "policy.delete", id, nil)
	})
	if errors.Is(err, ErrNotFound) {
		if found, aerr := s.deleteAuto(ctx, a, id); aerr != nil {
			return aerr
		} else if found {
			return nil
		}
	}
	return err
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
		p := Policy{ID: r.ID, Name: r.Name, Kind: r.Kind, PackageID: &r.PackageID, PackageName: r.PackageName, PackageIdentifier: r.PackageIdentifier, GroupIDs: r.GroupIds,
			DelayDays: r.DelayDays, OnlyNewDevices: r.OnlyNewDevices, UnverifiedConfirmed: r.UnverifiedConfirmed, Enabled: r.Enabled, UseRings: r.UseRings, RequireApproval: r.RequireApproval, Prompts: deploy.ParsePrompts(r.Prompts), CreatedAt: r.CreatedAt,
			LastRunAt: r.LastRunAt, LastDeploymentID: r.LastDeploymentID}
		p.statusFields(r.LastCheckAt, r.LastState, r.LastDetail, r.Enabled)
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
	autos, err := s.listAuto(ctx, org)
	if err != nil {
		return nil, err
	}
	out = append(out, autos...)
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

// Tick runs every enabled policy once. All-apps policies first add the apps that newly need handling.
func (s *Service) Tick(ctx context.Context) {
	s.fleetBegin()
	defer s.fleetEnd()
	s.syncAll(ctx)
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

// runOutcome is what a check did, for the status the console shows.
type runOutcome struct {
	created int
	dep     *uuid.UUID
	wait    attemptStat
}

// run checks one policy: it works out what is needed, creates the deployments the rings and the approval allow, and
// records what it found (D132) so the console can say so.
func (s *Service) run(ctx context.Context, p dbq.SoftwarePolicy) error {
	now := s.now()
	ro, err := s.plan(ctx, p, now)
	if err != nil {
		return err
	}
	var out runOutcome
	err = s.act(ctx, p, ro, now, &out)
	state, detail := statusOf(ro, out.created, out.wait)
	if err != nil {
		state, detail = StateError, "The last check failed: "+err.Error()
	}
	s.setStatus(ctx, p.ID, now, state, detail, out.created, out.dep)
	return err
}

func (s *Service) act(ctx context.Context, p dbq.SoftwarePolicy, ro *rollout, now time.Time, out *runOutcome) error {
	if ro == nil || ro.ver == nil {
		return nil
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
		eligible, fails, wait, err := s.filterAttempts(ctx, p, ro.ver.Version, st.cands, now)
		if err != nil {
			return err
		}
		out.wait.add(wait)
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
		// Copies installed for the whole PC and copies installed for one person are updated by separate deployments, as on the
		// Software updates page (D143). A device with both gets both.
		first := map[uuid.UUID]*uuid.UUID{}
		failed := map[uuid.UUID]bool{}
		for _, g := range scopeGroups(eligible, ro.scopes) {
			plan, err := s.Deploy.Create(ctx, p.OrgID, deploy.Request{Name: name, Action: ro.action, PackageID: ro.pkg.ID,
				Version: ro.ver.Version, Scope: g.scope, DeviceIDs: g.ids, ExpiresIn: deployLifetime, Window: windowOf(p, st), UnverifiedConfirmed: p.UnverifiedConfirmed,
				AllowSelfUpdating: ro.allowSelf, Policy: p.ID.String(), UserID: *p.CreatedBy, Prompts: deploy.ParsePrompts(p.Prompts)})
			if err != nil {
				if g.scope == "machine" {
					return err
				}
				// A copy installed for one person may have no installer the policy can use; that must not stop the PCs' own updates.
				s.log().Warn("policy per-user deployment", "policy", p.Name, "devices", len(g.ids), "err", err)
				for _, d := range g.ids {
					if first[d] == nil {
						failed[d] = true
					}
				}
				continue
			}
			dep := plan.DeploymentID
			out.dep = &dep
			for _, d := range g.ids {
				if first[d] == nil {
					id := plan.DeploymentID
					first[d] = &id
					delete(failed, d)
				}
			}
			s.log().Debug("policy deployment created", "policy", p.Name, "stage", st.name, "scope", g.scope, "devices", len(g.ids), "jobs", plan.Jobs, "skipped", plan.Skipped)
		}
		for _, d := range eligible {
			if first[d] == nil && !failed[d] {
				continue
			}
			n := fails[d]
			if first[d] == nil {
				n++ // nothing could be queued for this device: that counts as a failed try
			} else {
				out.created++
			}
			if err := q.UpsertPolicyAttempt(ctx, dbq.UpsertPolicyAttemptParams{PolicyID: p.ID, DeviceID: d, Version: ro.ver.Version, DeploymentID: first[d], Failures: n, CreatedAt: now}); err != nil {
				return err
			}
		}
	}
	return nil
}

// scopeGroup is the devices of one deployment of a policy run.
type scopeGroup struct {
	scope string
	ids   []uuid.UUID
}

// scopeGroups splits devices by the kind of copy that is out of date: machine-wide first, then per-user. A device with no
// recorded scope (a baseline install) is machine-wide.
func scopeGroups(devs []uuid.UUID, scopes map[uuid.UUID]map[string]bool) []scopeGroup {
	var machine, user []uuid.UUID
	for _, d := range devs {
		sc := scopes[d]
		if len(sc) == 0 || sc["machine"] {
			machine = append(machine, d)
		}
		if sc["user"] {
			user = append(user, d)
		}
	}
	var out []scopeGroup
	if len(machine) > 0 {
		out = append(out, scopeGroup{"machine", machine})
	}
	if len(user) > 0 {
		out = append(out, scopeGroup{"user", user})
	}
	return out
}

// filterAttempts drops devices a policy already handled for this version: a job still running, one
// that just finished (the inventory needs time), and devices that failed three times; failed ones
// are retried no sooner than a day after the last try.
func (s *Service) filterAttempts(ctx context.Context, p dbq.SoftwarePolicy, version string, cands []uuid.UUID, now time.Time) ([]uuid.UUID, map[uuid.UUID]int32, attemptStat, error) {
	var wait attemptStat
	q := dbq.New(s.Pool)
	atts, err := q.ListPolicyAttempts(ctx, dbq.ListPolicyAttemptsParams{PolicyID: p.ID, Column2: cands})
	if err != nil {
		return nil, nil, wait, err
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
			return nil, nil, wait, err
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
			wait.open++
			continue
		}
		if a.Failures >= maxFailures {
			wait.gaveUp++
			continue
		}
		if now.Sub(a.CreatedAt) < inventoryLag || now.Sub(a.CreatedAt) < retryAfter {
			wait.waiting++
			continue
		}
		fails[c] = a.Failures + 1
		out = append(out, c)
	}
	return out, fails, wait, nil
}
