package policies

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/catalog"
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/inventory"
	"github.com/auzring1/librepatch/internal/server/rings"
	"github.com/auzring1/librepatch/internal/server/store"
)

// Why a policy is not rolling a version out right now.
const (
	blockExcluded   = "excluded"         // the package is excluded in the catalog
	blockSelfUpdate = "self_updating"    // left to the vendor's updater (D50)
	blockNoVersion  = "no_version"       // nothing to roll out
	blockDelay      = "delay"            // the version is younger than the policy's delay
	blockPending    = "pending_approval" // waiting for an administrator
	blockDeclined   = "declined"         // an administrator declined this version
	ringCacheTTL    = 5 * time.Minute
	restStageName   = "Devices in no ring"
	allDevicesName  = "All devices"
)

// Approval states of a version for a policy.
const (
	ApprovalNotRequired = "not_required"
	ApprovalPending     = "pending"
	ApprovalApproved    = "approved"
	ApprovalDeclined    = "declined"
)

type ringCacheEntry struct {
	at      time.Time
	version time.Time
	members map[uuid.UUID]bool
}

type ringCaches struct {
	mu sync.Mutex
	m  map[uuid.UUID]ringCacheEntry
}

// stage is one step of a rollout: a ring, or (ring nil) the devices that are in no ring.
type stage struct {
	ring    *dbq.WuRing
	name    string
	members []uuid.UUID // every targeted device in this stage
	cands   []uuid.UUID // those that still need the version
	stats   rings.Stats
	hold    rings.HoldState
	holdID  *uuid.UUID
	// eligible: the version may be installed here now. passed: it has proven itself here, so the next stage may open.
	eligible   bool
	passed     bool
	holdReason string // non-empty: raise a hold now
}

// rollout is everything a run, and the console, needs to know about one policy and the version it is rolling out.
type rollout struct {
	policy     dbq.SoftwarePolicy
	pkg        dbq.CatalogPackage
	ver        *dbq.CatalogVersion
	action     string
	approval   string
	approvedAt time.Time
	available  time.Time // the earliest moment the first stage may install
	blocked    string
	stages     []*stage
	all        []uuid.UUID // the union of the stages' candidates
}

func (s *Service) ringMembers(ctx context.Context, org uuid.UUID, r dbq.WuRing) (map[uuid.UUID]bool, error) {
	s.ringc.mu.Lock()
	if s.ringc.m == nil {
		s.ringc.m = map[uuid.UUID]ringCacheEntry{}
	}
	if c, ok := s.ringc.m[r.ID]; ok && c.version.Equal(r.UpdatedAt) && s.now().Sub(c.at) < ringCacheTTL {
		s.ringc.mu.Unlock()
		return c.members, nil
	}
	s.ringc.mu.Unlock()
	devs, err := s.Deploy.ResolveTargets(ctx, org, r.GroupIds, nil)
	if err != nil {
		return nil, err
	}
	m := make(map[uuid.UUID]bool, len(devs))
	for _, d := range devs {
		m[d.ID] = true
	}
	s.ringc.mu.Lock()
	s.ringc.m[r.ID] = ringCacheEntry{at: s.now(), version: r.UpdatedAt, members: m}
	s.ringc.mu.Unlock()
	return m, nil
}

// plan works out what a policy would do now, without doing it: which version, whether it is approved, which devices
// still need it, how each ring has fared and which rings may install. run acts on the plan; the console shows it.
func (s *Service) plan(ctx context.Context, p dbq.SoftwarePolicy, now time.Time) (*rollout, error) {
	q := dbq.New(s.Pool)
	pkg, err := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: p.PackageID, OrgID: p.OrgID})
	if err != nil {
		return nil, nil
	}
	ro := &rollout{policy: p, pkg: pkg, approval: ApprovalNotRequired, action: "update"}
	if p.Kind == "baseline" {
		ro.action = "install"
	}
	pin, enforce := "", false
	if ov, err := q.GetPackageOverride(ctx, dbq.GetPackageOverrideParams{OrgID: p.OrgID, PackageID: pkg.ID}); err == nil {
		if ov.Excluded {
			ro.blocked = blockExcluded
			return ro, nil
		}
		pin, enforce = ov.Pin, ov.SelfUpdatePolicy == "enforce"
	}
	if p.Kind == "keep_updated" && pkg.SelfUpdating && !enforce {
		ro.blocked = blockSelfUpdate // left to the vendor's updater (D50)
		return ro, nil
	}
	vs, err := q.ListPackageVersions(ctx, pkg.ID)
	if err != nil {
		return nil, err
	}
	ver, err := catalog.ChooseVersion(vs, "", pin)
	if err != nil || ver == nil || ver.VersionKey == nil {
		ro.blocked = blockNoVersion
		return ro, nil
	}
	ro.ver = ver
	ro.available = ver.ImportedAt.Add(time.Duration(p.DelayDays) * 24 * time.Hour)
	if p.RequireApproval {
		ro.approval = ApprovalPending
		if a, err := q.GetSoftwareApproval(ctx, dbq.GetSoftwareApprovalParams{OrgID: p.OrgID, PackageID: pkg.ID, Version: ver.Version}); err == nil {
			ro.approval, ro.approvedAt = a.Decision, a.DecidedAt
			if ro.approval == ApprovalApproved && ro.approvedAt.After(ro.available) {
				ro.available = ro.approvedAt
			}
		}
	}
	switch {
	case ro.approval == ApprovalDeclined:
		ro.blocked = blockDeclined
	case ro.approval == ApprovalPending:
		ro.blocked = blockPending
	case now.Before(ro.available):
		ro.blocked = blockDelay
	}

	devs, err := s.Deploy.ResolveTargets(ctx, p.OrgID, p.GroupIds, nil)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, len(devs))
	for i, d := range devs {
		ids[i] = d.ID
	}
	cands, err := s.candidates(ctx, p, pkg, ver, ids)
	if err != nil {
		return nil, err
	}
	ro.stages, err = s.stages(ctx, p, ids, cands)
	if err != nil {
		return nil, err
	}
	seen := map[uuid.UUID]bool{}
	for _, st := range ro.stages {
		for _, c := range st.cands {
			if !seen[c] {
				seen[c] = true
				ro.all = append(ro.all, c)
			}
		}
	}
	if err := s.gateStages(ctx, ro, ids, now); err != nil {
		return nil, err
	}
	return ro, nil
}

// candidates are the targeted devices that need the version: outdated copies for a keep-updated policy, devices without
// the software for a baseline.
func (s *Service) candidates(ctx context.Context, p dbq.SoftwarePolicy, pkg dbq.CatalogPackage, ver *dbq.CatalogVersion, ids []uuid.UUID) ([]uuid.UUID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	q := dbq.New(s.Pool)
	norm := inventory.NormalizeName(pkg.Name, "")
	var cands []uuid.UUID
	switch p.Kind {
	case "keep_updated":
		rows, err := q.ListOutdatedForPackage(ctx, dbq.ListOutdatedForPackageParams{DeviceIds: ids, NormalizedName: norm, VersionKey: ver.VersionKey})
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			cands = append(cands, r.DeviceID)
		}
	case "baseline":
		have, err := q.ListDevicesWithPackage(ctx, dbq.ListDevicesWithPackageParams{DeviceIds: ids, NormalizedName: norm})
		if err != nil {
			return nil, err
		}
		has := map[uuid.UUID]bool{}
		for _, d := range have {
			has[d] = true
		}
		enrolled := map[uuid.UUID]time.Time{}
		if p.OnlyNewDevices {
			ts, err := q.ListDeviceEnrollTimes(ctx, ids)
			if err != nil {
				return nil, err
			}
			for _, t := range ts {
				enrolled[t.ID] = t.EnrolledAt
			}
		}
		for _, id := range ids {
			if has[id] || (p.OnlyNewDevices && !enrolled[id].After(p.CreatedAt)) {
				continue
			}
			cands = append(cands, id)
		}
	}
	return cands, nil
}

// stages splits the targeted devices into the rollout's stages. Without rings there is one stage. With rings, a device
// belongs to the first enabled ring (by order) that lists it; devices in no ring form a last stage, so adopting rings
// never leaves a device of the policy without its update (unlike Windows updates, D60, where the rings are the scope).
func (s *Service) stages(ctx context.Context, p dbq.SoftwarePolicy, ids, cands []uuid.UUID) ([]*stage, error) {
	if !p.UseRings || p.Kind != "keep_updated" {
		return []*stage{{name: allDevicesName, members: ids, cands: cands}}, nil
	}
	all, err := dbq.New(s.Pool).ListRings(ctx, p.OrgID)
	if err != nil {
		return nil, err
	}
	var rs []dbq.WuRing
	for _, r := range all {
		if r.Enabled {
			rs = append(rs, r)
		}
	}
	if len(rs) == 0 {
		return []*stage{{name: allDevicesName, members: ids, cands: cands}}, nil
	}
	target := map[uuid.UUID]bool{}
	for _, id := range ids {
		target[id] = true
	}
	stageOf := map[uuid.UUID]int{}
	out := make([]*stage, 0, len(rs)+1)
	for i := range rs {
		r := rs[i]
		members, err := s.ringMembers(ctx, p.OrgID, r)
		if err != nil {
			return nil, err
		}
		st := &stage{ring: &r, name: r.Name}
		for d := range members {
			if _, done := stageOf[d]; !done && target[d] {
				stageOf[d] = i
				st.members = append(st.members, d)
			}
		}
		out = append(out, st)
	}
	rest := &stage{name: restStageName}
	for _, id := range ids {
		if _, ok := stageOf[id]; !ok {
			stageOf[id] = len(rs)
			rest.members = append(rest.members, id)
		}
	}
	out = append(out, rest)
	for _, c := range cands {
		st := out[stageOf[c]]
		st.cands = append(st.cands, c)
	}
	// A stage with nobody in it takes no part (it neither delays nor holds the next one).
	kept := out[:0]
	for _, st := range out {
		if len(st.members) > 0 {
			kept = append(kept, st)
		}
	}
	return kept, nil
}

// gateStages fills in each stage's results and decides which stages may install: the first always (once the version is
// available), each later one only when the one before it has proven itself.
func (s *Service) gateStages(ctx context.Context, ro *rollout, ids []uuid.UUID, now time.Time) error {
	if ro.ver == nil {
		return nil
	}
	q := dbq.New(s.Pool)
	p := ro.policy
	// Who was given this version, and how it went.
	atts, err := q.ListPolicyAttemptsForVersion(ctx, dbq.ListPolicyAttemptsForVersionParams{PolicyID: p.ID, Version: ro.ver.Version})
	if err != nil {
		return err
	}
	var deps []uuid.UUID
	for _, a := range atts {
		if a.DeploymentID != nil {
			deps = append(deps, *a.DeploymentID)
		}
	}
	type key struct{ dep, dev uuid.UUID }
	type jobState struct{ open, failed, ok bool }
	states := map[key]jobState{}
	if len(deps) > 0 {
		rows, err := q.PolicyJobStates(ctx, deps)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.DeploymentID != nil {
				states[key{*r.DeploymentID, r.DeviceID}] = jobState{r.IsOpen, r.Failed, r.Ok}
			}
		}
	}
	stageOf := map[uuid.UUID]*stage{}
	for _, st := range ro.stages {
		for _, d := range st.members {
			stageOf[d] = st
		}
	}
	for _, a := range atts {
		st := stageOf[a.DeviceID]
		if st == nil || a.DeploymentID == nil {
			continue
		}
		js, ok := states[key{*a.DeploymentID, a.DeviceID}]
		if !ok {
			continue // the deployment planned no job for this device: nothing to learn from it
		}
		st.stats.Total++
		switch {
		case js.ok:
			st.stats.Installed++
		case js.failed && !js.open:
			st.stats.Failed++
		}
		if st.stats.First.IsZero() || a.CreatedAt.Before(st.stats.First) {
			st.stats.First = a.CreatedAt
		}
	}
	holds, err := q.ListSoftwareHoldsForVersion(ctx, dbq.ListSoftwareHoldsForVersionParams{PolicyID: p.ID, Version: ro.ver.Version})
	if err != nil {
		return err
	}
	for _, h := range holds {
		for _, st := range ro.stages {
			if st.ring == nil || st.ring.ID != h.RingID {
				continue
			}
			if h.ReleasedAt == nil {
				st.hold.Open = true
				id := h.ID
				st.holdID = &id
			} else {
				st.hold.Released = true
			}
		}
	}
	passed := ro.blocked == ""
	for _, st := range ro.stages {
		delay := time.Duration(0)
		r := rings.Ring{Name: st.name, SuccessThreshold: 90}
		if st.ring != nil {
			delay = time.Duration(st.ring.DelayDays) * 24 * time.Hour
			r = rings.Ring{Name: st.ring.Name, SoakHours: st.ring.SoakHours, SuccessThreshold: st.ring.SuccessThreshold}
		}
		st.eligible = passed && !now.Before(ro.available.Add(delay))
		passed = false
		if !st.eligible {
			continue
		}
		st.passed, st.holdReason = rings.Gate(st.stats, r, st.hold, now, len(st.cands) > 0)
		if st.ring == nil {
			st.holdReason = "" // the last stage has no later ring to hold back, so there is nothing to raise
		}
		passed = st.passed
	}
	return nil
}

// windowOf is the maintenance window for a stage: the ring's own if it has one, else the policy's.
func windowOf(p dbq.SoftwarePolicy, st *stage) *deploy.Window {
	raw := p.MaintWindow
	if st != nil && st.ring != nil && len(st.ring.MaintWindow) > 0 {
		raw = st.ring.MaintWindow
	}
	if len(raw) == 0 {
		return nil
	}
	var w deploy.Window
	if json.Unmarshal(raw, &w) != nil {
		return nil
	}
	return &w
}

// raiseHold records that a ring missed its success threshold for a version, which stops the version from reaching later
// rings until an administrator releases the hold.
func (s *Service) raiseHold(ctx context.Context, ro *rollout, st *stage, now time.Time) {
	raised := false
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		n, err := q.InsertSoftwareHold(ctx, dbq.InsertSoftwareHoldParams{ID: uuid.New(), OrgID: ro.policy.OrgID, PolicyID: ro.policy.ID, Version: ro.ver.Version, RingID: st.ring.ID, Reason: st.holdReason})
		if err != nil || n == 0 {
			return err
		}
		raised = true
		_, err = audit.Write(ctx, tx, audit.Entry{OrgID: &ro.policy.OrgID, ActorType: audit.ActorSystem, ActorID: "software-rings", Action: "software.hold",
			TargetType: "policy", TargetIDs: []string{ro.policy.ID.String()}, Outcome: audit.Success,
			Details: map[string]any{"package": ro.pkg.Name, "version": ro.ver.Version, "ring": st.ring.Name, "reason": st.holdReason}}, now)
		return err
	})
	if err != nil {
		s.log().Error("raise software hold", "policy", ro.policy.ID, "err", err)
		return
	}
	if raised && s.OnHold != nil {
		s.OnHold(ctx, ro.policy.OrgID, ro.pkg.Name+" "+ro.ver.Version, st.ring.Name, st.holdReason)
	}
}

// ---- what the console shows ----

// StageView is one stage of a rollout as the console shows it.
type StageView struct {
	Name      string     `json:"name"`
	Ring      bool       `json:"ring"` // false: the devices that are in no ring
	Devices   int        `json:"devices"`
	Waiting   int        `json:"waiting"` // devices that still need the version
	Installed int        `json:"installed"`
	Failed    int        `json:"failed"`
	State     string     `json:"state"` // waiting, running, passed, done, held
	HoldID    *uuid.UUID `json:"hold_id,omitempty"`
	Reason    string     `json:"reason,omitempty"`
}

// RolloutView is the console's account of a policy's current version.
type RolloutView struct {
	Version     string      `json:"version"`
	ImportedAt  time.Time   `json:"imported_at"`
	Approval    string      `json:"approval"`
	ApprovedAt  *time.Time  `json:"approved_at,omitempty"`
	Blocked     string      `json:"blocked,omitempty"`
	AvailableAt *time.Time  `json:"available_at,omitempty"`
	Waiting     int         `json:"waiting"` // devices that still need the version, in all stages
	Stages      []StageView `json:"stages"`
}

func (ro *rollout) view() *RolloutView {
	if ro == nil || ro.ver == nil {
		return nil
	}
	v := &RolloutView{Version: ro.ver.Version, ImportedAt: ro.ver.ImportedAt, Approval: ro.approval, Blocked: ro.blocked, Waiting: len(ro.all), Stages: []StageView{}}
	if !ro.approvedAt.IsZero() {
		t := ro.approvedAt
		v.ApprovedAt = &t
	}
	if !ro.available.IsZero() {
		t := ro.available
		v.AvailableAt = &t
	}
	for _, st := range ro.stages {
		sv := StageView{Name: st.name, Ring: st.ring != nil, Devices: len(st.members), Waiting: len(st.cands), Installed: st.stats.Installed, Failed: st.stats.Failed, HoldID: st.holdID}
		switch {
		case st.hold.Open || st.holdReason != "":
			sv.State, sv.Reason = "held", st.holdReason
		case !st.eligible:
			sv.State = "waiting"
		case len(st.cands) == 0:
			sv.State = "done"
		case st.passed:
			sv.State = "passed"
		default:
			sv.State = "running"
		}
		v.Stages = append(v.Stages, sv)
	}
	return v
}

// ---- approvals ----

// ApprovalItem is a version waiting for, or recently given, a decision.
type ApprovalItem struct {
	PackageID   uuid.UUID  `json:"package_id"`
	PackageName string     `json:"package_name"`
	Version     string     `json:"version"`
	Decision    string     `json:"decision"` // pending, approved, declined
	Note        string     `json:"note"`
	ImportedAt  *time.Time `json:"imported_at,omitempty"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	DecidedBy   string     `json:"decided_by"`
	Policies    []string   `json:"policies"`
	Devices     int        `json:"devices"`
}

// HoldItem is an open hold.
type HoldItem struct {
	ID          uuid.UUID `json:"id"`
	PolicyID    uuid.UUID `json:"policy_id"`
	Policy      string    `json:"policy"`
	PackageName string    `json:"package_name"`
	Version     string    `json:"version"`
	Ring        string    `json:"ring"`
	Reason      string    `json:"reason"`
	CreatedAt   time.Time `json:"created_at"`
}

// Approvals is the approval queue: versions waiting for a decision, recent decisions, and open holds.
type Approvals struct {
	Pending []ApprovalItem `json:"pending"`
	Recent  []ApprovalItem `json:"recent"`
	Holds   []HoldItem     `json:"holds"`
}

// Queue lists what needs an administrator's attention.
func (s *Service) Queue(ctx context.Context, org uuid.UUID) (*Approvals, error) {
	q := dbq.New(s.Pool)
	ps, err := q.ListSoftwarePolicies(ctx, org)
	if err != nil {
		return nil, err
	}
	now := s.now()
	type key struct {
		pkg uuid.UUID
		ver string
	}
	byKey := map[key]*ApprovalItem{}
	devs := map[key]map[uuid.UUID]bool{}
	out := &Approvals{Pending: []ApprovalItem{}, Recent: []ApprovalItem{}, Holds: []HoldItem{}}
	for _, r := range ps {
		if !r.Enabled || !r.RequireApproval {
			continue
		}
		ro, err := s.plan(ctx, policyRow(r), now)
		if err != nil || ro == nil || ro.ver == nil || ro.approval != ApprovalPending {
			continue
		}
		k := key{ro.pkg.ID, ro.ver.Version}
		it := byKey[k]
		if it == nil {
			imp := ro.ver.ImportedAt
			it = &ApprovalItem{PackageID: ro.pkg.ID, PackageName: ro.pkg.Name, Version: ro.ver.Version, Decision: ApprovalPending, ImportedAt: &imp, Policies: []string{}}
			byKey[k] = it
			devs[k] = map[uuid.UUID]bool{}
		}
		it.Policies = append(it.Policies, r.Name)
		for _, d := range ro.all {
			devs[k][d] = true
		}
	}
	for k, it := range byKey {
		// A version nobody needs (every device already has it) asks for no decision.
		if it.Devices = len(devs[k]); it.Devices > 0 {
			out.Pending = append(out.Pending, *it)
		}
	}
	sort.Slice(out.Pending, func(i, j int) bool {
		if a, b := out.Pending[i].PackageName, out.Pending[j].PackageName; a != b {
			return a < b
		}
		return out.Pending[i].Version < out.Pending[j].Version
	})
	recent, err := q.ListRecentSoftwareApprovals(ctx, dbq.ListRecentSoftwareApprovalsParams{OrgID: org, DecidedAt: now.Add(-30 * 24 * time.Hour)})
	if err != nil {
		return nil, err
	}
	for _, r := range recent {
		t := r.DecidedAt
		out.Recent = append(out.Recent, ApprovalItem{PackageID: r.PackageID, PackageName: r.PackageName, Version: r.Version, Decision: r.Decision, Note: r.Note, DecidedAt: &t, DecidedBy: r.DecidedByName, Policies: []string{}})
	}
	holds, err := q.ListOpenSoftwareHolds(ctx, org)
	if err != nil {
		return nil, err
	}
	for _, h := range holds {
		out.Holds = append(out.Holds, HoldItem{ID: h.ID, PolicyID: h.PolicyID, Policy: h.PolicyName, PackageName: h.PackageName, Version: h.Version, Ring: h.RingName, Reason: h.Reason, CreatedAt: h.CreatedAt})
	}
	return out, nil
}

// policyRow turns the list query's row into the plain policy row plan works with.
func policyRow(r dbq.ListSoftwarePoliciesRow) dbq.SoftwarePolicy {
	return dbq.SoftwarePolicy{ID: r.ID, OrgID: r.OrgID, Name: r.Name, Kind: r.Kind, PackageID: r.PackageID, GroupIds: r.GroupIds, DelayDays: r.DelayDays,
		OnlyNewDevices: r.OnlyNewDevices, UnverifiedConfirmed: r.UnverifiedConfirmed, MaintWindow: r.MaintWindow, Enabled: r.Enabled, CreatedBy: r.CreatedBy,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, UseRings: r.UseRings, RequireApproval: r.RequireApproval, Prompts: r.Prompts}
}

// Decide records an administrator's decision about one version of a package: "approved", "declined", or "reset" (back
// to waiting).
func (s *Service) Decide(ctx context.Context, a Actor, pkg uuid.UUID, version, decision, note string) error {
	if decision != "approved" && decision != "declined" && decision != "reset" {
		return invalid("decision must be approved, declined or reset")
	}
	if len(note) > 1000 {
		return invalid("the note is at most 1000 characters")
	}
	q := dbq.New(s.Pool)
	p, err := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: pkg, OrgID: a.Org})
	if err != nil {
		return ErrNotFound
	}
	vs, err := q.ListPackageVersions(ctx, pkg)
	if err != nil {
		return err
	}
	found := false
	for _, v := range vs {
		found = found || v.Version == version
	}
	if !found {
		return invalid("that version is not in the catalog")
	}
	action := map[string]string{"approved": "software.approve", "declined": "software.decline", "reset": "software.approval_reset"}[decision]
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if decision == "reset" {
			if _, err := q.DeleteSoftwareApproval(ctx, dbq.DeleteSoftwareApprovalParams{OrgID: a.Org, PackageID: pkg, Version: version}); err != nil {
				return err
			}
		} else if err := q.UpsertSoftwareApproval(ctx, dbq.UpsertSoftwareApprovalParams{OrgID: a.Org, PackageID: pkg, Version: version, Decision: decision, Note: note, DecidedBy: &a.User, DecidedAt: s.now()}); err != nil {
			return err
		}
		_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &a.Org, ActorType: audit.ActorUser, ActorID: a.User.String(), ActorIP: a.IP, Action: action,
			TargetType: "package", TargetIDs: []string{pkg.String()}, Outcome: audit.Success,
			Details: map[string]any{"package": p.Name, "version": version, "note": note}}, s.now())
		return err
	})
}

// ReleaseHold lets a held version move on to the next ring (releasing counts as a pass, as for Windows updates, D60).
func (s *Service) ReleaseHold(ctx context.Context, a Actor, id uuid.UUID) error {
	h, err := dbq.New(s.Pool).GetSoftwareHold(ctx, dbq.GetSoftwareHoldParams{ID: id, OrgID: a.Org})
	if err != nil {
		return ErrNotFound
	}
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		n, err := q.ReleaseSoftwareHold(ctx, dbq.ReleaseSoftwareHoldParams{ID: id, OrgID: a.Org, ReleasedBy: &a.User})
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("%w: the hold was already released", ErrConflict)
		}
		_, err = audit.Write(ctx, tx, audit.Entry{OrgID: &a.Org, ActorType: audit.ActorUser, ActorID: a.User.String(), ActorIP: a.IP, Action: "software.hold_release",
			TargetType: "policy", TargetIDs: []string{h.PolicyID.String()}, Outcome: audit.Success,
			Details: map[string]any{"policy": h.PolicyName, "version": h.Version}}, s.now())
		return err
	})
}
