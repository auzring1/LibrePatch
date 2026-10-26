package policies

// All-apps policies (D132). One policy that keeps every app with an update current, instead of one policy per package.
//
// An all-apps policy is a parent row (software_auto_policies). Each app it handles is an ordinary one-package policy, a
// child (software_policies.auto_policy_id set), that the server creates when it sees an update for that app on a device
// in the policy's groups. Because a child is an ordinary policy, rings, approval, holds, delays, windows, attempts and the
// run status all work exactly as they do for a policy made by hand; the parent only decides which apps get a child.
// Children are hidden from the policy list, cannot be edited on their own, and go away with the parent.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/store"
)

// KindAll is the kind of an all-apps policy.
const KindAll = "keep_all"

// Limits of an all-apps policy.
const (
	maxAutoApps    = 300 // children per all-apps policy
	maxAutoExclude = 200
	importsPerSync = 3 // winget apps imported into the catalog per policy and check
	maxPreviewRows = 500
	autoActorID    = "software-policies"
)

// Why an all-apps policy leaves an app alone (AppMatch.Reason).
const (
	reasonVendor      = "vendor"
	reasonExcluded    = "excluded"
	reasonUnverified  = "unverified"
	reasonUnlisted    = "unlisted"
	reasonOtherPolicy = "other_policy"
	reasonCatalogOff  = "catalog_excluded"
	reasonLimit       = "limit"
)

// AutoFilter says which apps an all-apps policy handles.
type AutoFilter struct {
	// VerifiedOnly handles only apps that were verified on test machines (the default, and the safe choice).
	VerifiedOnly bool `json:"verified_only"`
	// IncludeUnlisted also handles apps that are not in the catalog yet: the server adds them from the public winget
	// index when an update shows up. They are never verified, so this needs VerifiedOnly to be off.
	IncludeUnlisted bool `json:"include_unlisted"`
	// Exclude lists apps to leave alone: package identifiers such as "Mozilla.Firefox" (not case-sensitive).
	Exclude []string `json:"exclude"`
	// IncludeSelfUpdating also keeps apps current that normally update themselves (Chrome, Edge, Zoom). When such an app is
	// still out of date on a PC its own updater is not doing its job there (switched off, blocked, or never installed), so
	// the policy installs the newest version itself (D148). On unless the policy says otherwise.
	IncludeSelfUpdating bool `json:"include_self_updating"`
}

func parseFilter(raw []byte) AutoFilter {
	f := AutoFilter{VerifiedOnly: true, IncludeSelfUpdating: true}
	var in struct {
		VerifiedOnly        *bool    `json:"verified_only"`
		IncludeUnlisted     bool     `json:"include_unlisted"`
		Exclude             []string `json:"exclude"`
		IncludeSelfUpdating *bool    `json:"include_self_updating"`
	}
	if len(raw) > 0 && json.Unmarshal(raw, &in) == nil {
		if in.VerifiedOnly != nil {
			f.VerifiedOnly = *in.VerifiedOnly
		}
		if in.IncludeSelfUpdating != nil {
			f.IncludeSelfUpdating = *in.IncludeSelfUpdating
		}
		f.IncludeUnlisted, f.Exclude = in.IncludeUnlisted, in.Exclude
	}
	return f
}

// clean checks and normalizes a filter an administrator submitted.
func (f *AutoFilter) clean() error {
	if f.IncludeUnlisted && f.VerifiedOnly {
		return invalid("apps added from the winget index are not verified, so \"only verified apps\" must be switched off to include them")
	}
	if len(f.Exclude) > maxAutoExclude {
		return invalid("exclude at most %d apps", maxAutoExclude)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(f.Exclude))
	for _, e := range f.Exclude {
		e = strings.TrimSpace(e)
		if e == "" || seen[strings.ToLower(e)] {
			continue
		}
		if utf8.RuneCountInString(e) > 200 {
			return invalid("an excluded app name is at most 200 characters")
		}
		seen[strings.ToLower(e)] = true
		out = append(out, e)
	}
	f.Exclude = out
	return nil
}

func (f AutoFilter) excludes(ids ...string) bool {
	for _, e := range f.Exclude {
		for _, id := range ids {
			if id != "" && strings.EqualFold(e, id) {
				return true
			}
		}
	}
	return false
}

// AppMatch is one app that has an update on a device in an all-apps policy's groups, and what the policy does about it.
type AppMatch struct {
	PackageID     *uuid.UUID `json:"package_id"` // null while the app is not in the catalog
	Name          string     `json:"name"`
	Identifier    string     `json:"identifier"`
	LatestVersion string     `json:"latest_version"`
	Devices       int        `json:"devices"`
	// Handled is true when the policy keeps this app current. Otherwise Reason is a code and ReasonText says why not.
	Handled    bool   `json:"handled"`
	Reason     string `json:"reason,omitempty"`
	ReasonText string `json:"reason_text,omitempty"`

	fu       deploy.FleetUpdate
	existing bool // the app already has a child
}

var reasonText = map[string]string{
	reasonVendor:      "The app updates itself, so it is left to its vendor (switch on \"also update apps that update themselves\" to handle it).",
	reasonExcluded:    "You excluded this app.",
	reasonUnverified:  "Not verified on test machines yet (the policy handles verified apps only).",
	reasonUnlisted:    "Not in your catalog yet (switch on \"add apps from winget\" to handle apps like this).",
	reasonOtherPolicy: "Another policy already keeps this app updated.",
	reasonCatalogOff:  "This app is excluded in the catalog.",
	reasonLimit:       fmt.Sprintf("The policy already handles %d apps, which is the most it keeps.", maxAutoApps),
}

// matchApps decides, for every app with an update on a device in the groups, whether an all-apps policy with this
// filter handles it. It changes nothing. self is the all-apps policy being previewed or synchronized (zero for a new
// one): its own children do not count as "another policy".
func (s *Service) matchApps(ctx context.Context, org uuid.UUID, groupIDs []uuid.UUID, f AutoFilter, self uuid.UUID, updates []deploy.FleetUpdate) ([]AppMatch, error) {
	targets, err := s.Deploy.ResolveTargets(ctx, org, groupIDs, nil)
	if err != nil {
		return nil, err
	}
	in := map[uuid.UUID]bool{}
	for _, t := range targets {
		in[t.ID] = true
	}
	q := dbq.New(s.Pool)
	var existing map[uuid.UUID]bool
	if self != uuid.Nil {
		existing = map[uuid.UUID]bool{}
		kids, err := q.ListAutoChildren(ctx, &self)
		if err != nil {
			return nil, err
		}
		for _, k := range kids {
			existing[k.PackageID] = true
		}
	}
	var selfPtr *uuid.UUID
	if self != uuid.Nil {
		selfPtr = &self
	}
	var out []AppMatch
	handled := len(existing)
	for _, u := range updates {
		n := 0
		for _, d := range u.Devices {
			if in[d.DeviceID] {
				n++
			}
		}
		if n == 0 {
			continue
		}
		m := AppMatch{Name: u.PackageName, Identifier: u.Identifier, LatestVersion: u.LatestVersion, Devices: n, fu: u}
		if u.InCatalog {
			id := u.PackageID
			m.PackageID = &id
		} else if u.WingetID != "" {
			m.Identifier = u.WingetID
		}
		skip := func(code string) {
			m.Reason, m.ReasonText = code, reasonText[code]
		}
		switch {
		case (!u.Deployable || u.SelfUpdating) && !f.IncludeSelfUpdating:
			skip(reasonVendor)
		case f.excludes(u.Identifier, u.WingetID):
			skip(reasonExcluded)
		case !u.InCatalog:
			if !f.IncludeUnlisted {
				skip(reasonUnlisted)
			} else {
				m.Handled = true
			}
		default:
			pkg, err := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: u.PackageID, OrgID: org})
			if err != nil {
				continue // removed meanwhile
			}
			ov, _ := q.GetPackageOverride(ctx, dbq.GetPackageOverrideParams{OrgID: org, PackageID: pkg.ID})
			owned, _ := q.PackageHasOtherPolicy(ctx, dbq.PackageHasOtherPolicyParams{OrgID: org, PackageID: pkg.ID, AutoPolicyID: selfPtr})
			switch {
			case ov.Excluded:
				skip(reasonCatalogOff)
			case f.VerifiedOnly && needsConfirm(pkg):
				skip(reasonUnverified)
			case owned:
				skip(reasonOtherPolicy)
			default:
				m.Handled = true
			}
		}
		if m.Handled {
			m.existing = m.PackageID != nil && existing[*m.PackageID]
			if !m.existing {
				if handled >= maxAutoApps {
					m.Handled = false
					skip(reasonLimit)
				} else {
					handled++
				}
			}
		}
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Handled != out[j].Handled {
			return out[i].Handled
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

// needsConfirm is true for a winget package nobody has verified: using it in a policy needs the administrator's yes.
func needsConfirm(p dbq.CatalogPackage) bool { return p.Source == "winget" && !p.Verified }

// PreviewResult is what an all-apps policy would handle, for the console's "these apps will be kept updated" list.
type PreviewResult struct {
	Items   []AppMatch `json:"items"`
	Handled int        `json:"handled"`
	Skipped int        `json:"skipped"`
	// Truncated is true when only the first rows are listed.
	Truncated bool `json:"truncated"`
}

// Preview lists the apps an all-apps policy with these groups and this filter handles now, and the ones it skips and why.
// id is the policy being edited (zero for a new one).
func (s *Service) Preview(ctx context.Context, org uuid.UUID, id uuid.UUID, groupIDs []uuid.UUID, f AutoFilter) (*PreviewResult, error) {
	if len(groupIDs) == 0 || len(groupIDs) > 50 {
		return nil, invalid("choose 1 to 50 groups")
	}
	q := dbq.New(s.Pool)
	for _, g := range groupIDs {
		if _, err := q.GetGroup(ctx, dbq.GetGroupParams{ID: g, OrgID: org}); err != nil {
			return nil, invalid("unknown group")
		}
	}
	if err := f.clean(); err != nil {
		return nil, err
	}
	ups, err := s.Deploy.FleetUpdates(ctx, org)
	if err != nil {
		return nil, err
	}
	items, err := s.matchApps(ctx, org, groupIDs, f, id, ups)
	if err != nil {
		return nil, err
	}
	r := &PreviewResult{Items: items}
	for _, m := range items {
		if m.Handled {
			r.Handled++
		} else {
			r.Skipped++
		}
	}
	if len(items) > maxPreviewRows {
		r.Items, r.Truncated = items[:maxPreviewRows], true
	}
	if r.Items == nil {
		r.Items = []AppMatch{}
	}
	return r, nil
}

// ---- keeping the children in step ----

// syncAll adds a child for every app an enabled all-apps policy newly handles, and drops the ones it no longer does. It
// runs at the start of every Tick, before the children themselves are checked.
func (s *Service) syncAll(ctx context.Context) {
	parents, err := dbq.New(s.Pool).ListEnabledAutoPolicies(ctx)
	if err != nil {
		s.log().Error("all-apps policies", "err", err)
		return
	}
	updates := map[uuid.UUID][]deploy.FleetUpdate{}
	for _, p := range parents {
		if ctx.Err() != nil {
			return
		}
		ups, ok := updates[p.OrgID]
		if !ok {
			if ups, err = s.fleetUpdates(ctx, p.OrgID); err != nil {
				s.log().Error("all-apps policy: reading updates", "policy", p.ID, "err", err)
				s.setAutoStatus(ctx, p.ID, StateError, "The last check failed: "+err.Error())
				continue
			}
			updates[p.OrgID] = ups
		}
		note, err := s.syncOne(ctx, p, ups, true)
		if err != nil {
			s.log().Error("all-apps policy", "policy", p.ID, "name", p.Name, "err", err)
			s.setAutoStatus(ctx, p.ID, StateError, "The last check failed: "+err.Error())
			continue
		}
		s.setAutoStatus(ctx, p.ID, "", note)
	}
}

func (s *Service) setAutoStatus(ctx context.Context, id uuid.UUID, state, detail string) {
	now := s.now()
	if len(detail) > 500 {
		detail = detail[:500]
	}
	if err := dbq.New(s.Pool).SetAutoPolicyStatus(ctx, dbq.SetAutoPolicyStatusParams{ID: id, CheckedAt: &now, State: state, Detail: detail}); err != nil {
		s.log().Warn("record all-apps policy status", "policy", id, "err", err)
	}
}

// syncOne brings the children of one all-apps policy in step with what is out of date now. imports says whether it may
// add apps from the winget index to the catalog (slow, so not while an administrator waits for a save).
//
// It returns a sentence about the apps that have an update but are left alone (and why), so the policy's status can say so
// instead of claiming there is nothing to do.
func (s *Service) syncOne(ctx context.Context, p dbq.SoftwareAutoPolicy, updates []deploy.FleetUpdate, imports bool) (string, error) {
	f := parseFilter(p.Filter)
	q := dbq.New(s.Pool)
	kids, err := q.ListAutoChildren(ctx, &p.ID)
	if err != nil {
		return "", err
	}
	// Drop what the policy no longer handles: an app that is now excluded, unverified, or taken over by a policy someone
	// made by hand. (An app that merely has no update right now stays: it will need one again.)
	for _, k := range kids {
		why := ""
		switch {
		case f.excludes(k.PackageIdentifier):
			why = "you excluded it"
		case f.VerifiedOnly && k.PackageSource == "winget" && !k.PackageVerified:
			why = "it is not verified"
		default:
			if owned, _ := q.PackageHasManualPolicy(ctx, dbq.PackageHasManualPolicyParams{OrgID: p.OrgID, PackageID: k.PackageID}); owned {
				why = "another policy now keeps it updated"
			}
		}
		if why == "" {
			continue
		}
		if err := s.dropChild(ctx, p, k.ID, k.PackageName, why); err != nil {
			return "", err
		}
	}
	if p.CreatedBy == nil {
		return "", nil // deployments need an owner on record; the person who made the policy was deleted
	}
	items, err := s.matchApps(ctx, p.OrgID, p.GroupIds, f, p.ID, updates)
	if err != nil {
		return "", err
	}
	budget := importsPerSync
	for _, m := range items {
		if !m.Handled || m.existing {
			continue
		}
		var pkgID uuid.UUID
		if m.PackageID != nil {
			pkgID = *m.PackageID
		} else {
			if !imports || budget <= 0 || s.Import == nil {
				continue
			}
			budget--
			id, err := s.Import(ctx, p.OrgID, *p.CreatedBy, m.fu.WingetID)
			if err != nil {
				s.log().Warn("all-apps policy: importing from winget", "policy", p.ID, "app", m.fu.WingetID, "err", err)
				continue
			}
			pkgID = id
			s.auditSystem(ctx, p.OrgID, "catalog.import", "package", pkgID, map[string]any{"identifier": m.fu.WingetID, "by": "all-apps policy", "policy": p.Name})
		}
		if err := s.addChild(ctx, p, f, pkgID); err != nil {
			s.log().Warn("all-apps policy: adding an app", "policy", p.ID, "package", pkgID, "err", err)
		}
	}
	return leftAloneNote(items), nil
}

// leftAloneNote names up to three apps that have an update the policy does not handle, with the reason. Apps the
// administrator excluded are not mentioned: that was their choice.
func leftAloneNote(items []AppMatch) string {
	var parts []string
	n := 0
	for _, m := range items {
		if m.Handled || m.Reason == "" || m.Reason == reasonExcluded || m.Reason == reasonCatalogOff {
			continue
		}
		n++
		if len(parts) < 3 {
			why := map[string]string{reasonVendor: "updates itself", reasonUnverified: "not verified yet", reasonUnlisted: "not in the catalog",
				reasonOtherPolicy: "has a policy of its own", reasonLimit: "over the limit"}[m.Reason]
			parts = append(parts, m.Name+" ("+why+")")
		}
	}
	if n == 0 {
		return ""
	}
	s := "Has an update but is left alone: " + strings.Join(parts, ", ")
	if n > len(parts) {
		s += fmt.Sprintf(" and %d more", n-len(parts))
	}
	return s + ". Open the policy to see why."
}

func (s *Service) dropChild(ctx context.Context, p dbq.SoftwareAutoPolicy, child uuid.UUID, pkgName, why string) error {
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.DeleteAutoChild(ctx, child); err != nil {
			return err
		}
		_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorSystem, ActorID: autoActorID, Action: "policy.auto_remove_app",
			TargetType: "policy", TargetIDs: []string{p.ID.String()}, Outcome: audit.Success,
			Details: map[string]any{"policy": p.Name, "app": pkgName, "reason": why}}, s.now())
		return err
	})
	return err
}

func (s *Service) addChild(ctx context.Context, p dbq.SoftwareAutoPolicy, f AutoFilter, pkgID uuid.UUID) error {
	q := dbq.New(s.Pool)
	pkg, err := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: pkgID, OrgID: p.OrgID})
	if err != nil {
		return err
	}
	// An imported app is never verified: the filter must allow that.
	if f.VerifiedOnly && needsConfirm(pkg) {
		return nil
	}
	prompts := s.childPrompts(ctx, p.OrgID, pkg, deploy.ParsePrompts(p.Prompts))
	base := childName(p.Name, pkg.Name)
	names := []string{base, childName(p.Name, pkg.Name+" ("+pkg.Identifier+")"), childName(p.Name, pkg.Name+" ("+uuid.NewString()[:8]+")")}
	for _, name := range names {
		id := uuid.New()
		err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
			if err := q.InsertAutoChild(ctx, dbq.InsertAutoChildParams{ID: id, OrgID: p.OrgID, Name: name, PackageID: pkg.ID, GroupIds: p.GroupIds, DelayDays: p.DelayDays,
				UnverifiedConfirmed: !f.VerifiedOnly, MaintWindow: p.MaintWindow, Enabled: p.Enabled, CreatedBy: p.CreatedBy, UseRings: p.UseRings, RequireApproval: p.RequireApproval,
				Prompts: deploy.MarshalPrompts(prompts), AutoPolicyID: &p.ID}); err != nil {
				return err
			}
			_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorSystem, ActorID: autoActorID, Action: "policy.auto_add_app",
				TargetType: "policy", TargetIDs: []string{p.ID.String()}, Outcome: audit.Success,
				Details: map[string]any{"policy": p.Name, "app": pkg.Name, "identifier": pkg.Identifier, "child": id.String()}}, s.now())
			return err
		})
		if !isUnique(err) {
			return err
		}
	}
	return nil // another check added it first, or the name could not be made unique
}

func childName(parent, app string) string {
	n := parent + " · " + app
	if utf8.RuneCountInString(n) > 200 {
		n = string([]rune(n)[:200])
	}
	return n
}

// childPrompts adapts the all-apps policy's messages to one app: choices that need the app's program names (wait for it
// to be closed, ask, close it) cannot be used for an app whose programs are not known, so that part is left out.
func (s *Service) childPrompts(ctx context.Context, org uuid.UUID, pkg dbq.CatalogPackage, p *deploy.Prompts) *deploy.Prompts {
	if p == nil {
		return nil
	}
	if s.Deploy.CheckPrograms(ctx, org, pkg, p) == nil {
		return p
	}
	c := *p
	c.InUse, c.AskTimeoutS, c.DeferMinutes = "", 0, 0
	r, err := c.Validate()
	if err != nil {
		return nil
	}
	return r
}

func (s *Service) auditSystem(ctx context.Context, org uuid.UUID, action, targetType string, target uuid.UUID, details map[string]any) {
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &org, ActorType: audit.ActorSystem, ActorID: autoActorID, Action: action,
			TargetType: targetType, TargetIDs: []string{target.String()}, Outcome: audit.Success, Details: details}, s.now())
		return err
	})
	if err != nil {
		s.log().Warn("audit", "action", action, "err", err)
	}
}

// propagate gives every child the settings of its all-apps policy.
func (s *Service) propagate(ctx context.Context, q *dbq.Queries, p dbq.SoftwareAutoPolicy, f AutoFilter) error {
	kids, err := q.ListAutoChildren(ctx, &p.ID)
	if err != nil {
		return err
	}
	base := deploy.ParsePrompts(p.Prompts)
	for _, k := range kids {
		pkg, err := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: k.PackageID, OrgID: p.OrgID})
		if err != nil {
			continue
		}
		if err := q.PropagateAutoPolicy(ctx, dbq.PropagateAutoPolicyParams{ID: k.ID, GroupIds: p.GroupIds, DelayDays: p.DelayDays, MaintWindow: p.MaintWindow, Enabled: p.Enabled,
			UseRings: p.UseRings, RequireApproval: p.RequireApproval, Prompts: deploy.MarshalPrompts(s.childPrompts(ctx, p.OrgID, pkg, base)), UnverifiedConfirmed: !f.VerifiedOnly}); err != nil {
			return err
		}
	}
	return nil
}

// ---- create, update, delete ----

// validateAuto checks what is specific to an all-apps policy and fills in the filter.
func validateAuto(in *Input) error {
	f := AutoFilter{VerifiedOnly: true}
	if in.Filter != nil {
		f = *in.Filter
	}
	if err := f.clean(); err != nil {
		return err
	}
	in.Filter = &f
	if in.OnlyNewDevices {
		return invalid("an all-apps policy keeps apps updated; it does not install apps on new devices")
	}
	return nil
}

func (s *Service) createAuto(ctx context.Context, a Actor, in Input, win []byte) (uuid.UUID, error) {
	id := uuid.New()
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		raw, _ := json.Marshal(in.Filter)
		if err := q.InsertAutoPolicy(ctx, dbq.InsertAutoPolicyParams{ID: id, OrgID: a.Org, Name: in.Name, GroupIds: in.GroupIDs, DelayDays: in.DelayDays, MaintWindow: win, Enabled: in.Enabled,
			UseRings: in.UseRings, RequireApproval: in.RequireApproval, Prompts: deploy.MarshalPrompts(in.Prompts), Filter: raw, CreatedBy: &a.User}); err != nil {
			return err
		}
		return s.audit(ctx, tx, a, "policy.create", id, map[string]any{"name": in.Name, "kind": KindAll, "groups": len(in.GroupIDs), "rings": in.UseRings, "approval": in.RequireApproval,
			"prompts": !in.Prompts.Silent(), "verified_only": in.Filter.VerifiedOnly, "include_unlisted": in.Filter.IncludeUnlisted, "include_self_updating": in.Filter.IncludeSelfUpdating, "excluded": len(in.Filter.Exclude)})
	})
	if isUnique(err) {
		return uuid.Nil, fmt.Errorf("%w: a policy with that name already exists", ErrConflict)
	}
	if err != nil {
		return uuid.Nil, err
	}
	s.syncNow(ctx, a.Org, id)
	return id, nil
}

func (s *Service) updateAuto(ctx context.Context, a Actor, id uuid.UUID, in Input, win []byte) error {
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		raw, _ := json.Marshal(in.Filter)
		n, err := q.UpdateAutoPolicy(ctx, dbq.UpdateAutoPolicyParams{ID: id, OrgID: a.Org, Name: in.Name, GroupIds: in.GroupIDs, DelayDays: in.DelayDays, MaintWindow: win, Enabled: in.Enabled,
			UseRings: in.UseRings, RequireApproval: in.RequireApproval, Prompts: deploy.MarshalPrompts(in.Prompts), Filter: raw})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		p, err := q.GetAutoPolicy(ctx, dbq.GetAutoPolicyParams{ID: id, OrgID: a.Org})
		if err != nil {
			return err
		}
		if err := s.propagate(ctx, q, p, *in.Filter); err != nil {
			return err
		}
		return s.audit(ctx, tx, a, "policy.update", id, map[string]any{"name": in.Name, "kind": KindAll, "enabled": in.Enabled, "rings": in.UseRings, "approval": in.RequireApproval,
			"prompts": !in.Prompts.Silent(), "verified_only": in.Filter.VerifiedOnly, "include_unlisted": in.Filter.IncludeUnlisted, "include_self_updating": in.Filter.IncludeSelfUpdating, "excluded": len(in.Filter.Exclude)})
	})
	if isUnique(err) {
		return fmt.Errorf("%w: a policy with that name already exists", ErrConflict)
	}
	if err != nil {
		return err
	}
	s.syncNow(ctx, a.Org, id)
	return nil
}

// syncNow looks at the apps right after a save so the administrator sees the result at once (without importing from the
// winget index; the next regular check does that).
func (s *Service) syncNow(ctx context.Context, org, id uuid.UUID) {
	p, err := dbq.New(s.Pool).GetAutoPolicy(ctx, dbq.GetAutoPolicyParams{ID: id, OrgID: org})
	if err != nil || !p.Enabled {
		return
	}
	note := ""
	ups, err := s.Deploy.FleetUpdates(ctx, org)
	if err == nil {
		note, err = s.syncOne(ctx, p, ups, false)
	}
	if err != nil {
		s.log().Warn("all-apps policy: first look", "policy", id, "err", err)
		return
	}
	s.setAutoStatus(ctx, id, "", note)
}

// deleteAuto removes an all-apps policy and, with it, its apps' policies. It reports whether id was one.
func (s *Service) deleteAuto(ctx context.Context, a Actor, id uuid.UUID) (bool, error) {
	found := false
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		n, err := q.DeleteAutoPolicy(ctx, dbq.DeleteAutoPolicyParams{ID: id, OrgID: a.Org})
		if err != nil || n == 0 {
			return err
		}
		found = true
		return s.audit(ctx, tx, a, "policy.delete", id, map[string]any{"kind": KindAll})
	})
	return found, err
}

// ---- what the console shows ----

// summarize turns the states of an all-apps policy's apps into one state and one sentence.
func summarize(states map[string]int64) (string, string) {
	var total, updating, waiting, attention, current int64
	for st, n := range states {
		total += n
		switch st {
		case StateUpdating:
			updating += n
		case StateWaitingApproval, StateWaitingRing, StateWaitingDelay, StateRetry:
			waiting += n
		case StateHeld, StateError, StateGaveUp, StateDeclined, StatePackageGone:
			attention += n
		case StateUpToDate:
			current += n
		}
	}
	apps := func(n int64) string { return fmt.Sprintf("%d %s", n, plural(int(n), "app", "apps")) }
	var parts []string
	if attention > 0 {
		parts = append(parts, apps(attention)+" need your attention")
	}
	if updating > 0 {
		parts = append(parts, apps(updating)+" being updated")
	}
	if waiting > 0 {
		parts = append(parts, apps(waiting)+" waiting (approval, a ring, a delay or a retry)")
	}
	if current > 0 {
		parts = append(parts, apps(current)+" up to date")
	}
	other := total - attention - updating - waiting - current
	if other > 0 {
		parts = append(parts, apps(other)+" not checked yet or left alone")
	}
	switch {
	case total == 0:
		return StateNoApps, "No app on these groups has an update to handle right now. When one does, it is added here."
	case attention > 0:
		return StateAppsNeedAttention, strings.Join(parts, ", ") + "."
	case updating > 0:
		return StateAppsUpdating, strings.Join(parts, ", ") + "."
	case waiting > 0:
		return StateAppsWaiting, strings.Join(parts, ", ") + "."
	case current == total:
		return StateAppsAllCurrent, fmt.Sprintf("All %s %s up to date.", apps(total), plural(int(total), "is", "are"))
	}
	return StateAppsWaiting, strings.Join(parts, ", ") + "."
}

// listAuto returns the all-apps policies of an organization for the policy list.
func (s *Service) listAuto(ctx context.Context, org uuid.UUID) ([]Policy, error) {
	q := dbq.New(s.Pool)
	ps, err := q.ListAutoPolicies(ctx, org)
	if err != nil {
		return nil, err
	}
	out := make([]Policy, 0, len(ps))
	for _, r := range ps {
		f := parseFilter(r.Filter)
		p := Policy{ID: r.ID, Name: r.Name, Kind: KindAll, GroupIDs: r.GroupIds, DelayDays: r.DelayDays, Enabled: r.Enabled, UseRings: r.UseRings,
			RequireApproval: r.RequireApproval, Prompts: deploy.ParsePrompts(r.Prompts), CreatedAt: r.CreatedAt, Auto: true, Filter: &f, AppStates: map[string]int64{}}
		if len(r.MaintWindow) > 0 {
			var w deploy.Window
			if json.Unmarshal(r.MaintWindow, &w) == nil {
				p.Window = &w
			}
		}
		kids, err := q.ListAutoChildren(ctx, &r.ID)
		if err != nil {
			return nil, err
		}
		p.Apps = int64(len(kids))
		var last *time.Time
		for _, k := range kids {
			st := k.LastState
			if st == "" {
				st = StateNew
			}
			p.AppStates[st]++
			if k.LastRunAt != nil && (last == nil || k.LastRunAt.After(*last)) {
				last, p.LastDeploymentID = k.LastRunAt, k.LastDeploymentID
			}
		}
		p.LastRunAt = last
		if st, err := q.AutoPolicyAttemptStats(ctx, &r.ID); err == nil {
			p.Devices = st
		}
		state, detail := summarize(p.AppStates)
		if r.LastState == StateError {
			state, detail = StateError, r.LastDetail
		} else if r.LastDetail != "" {
			detail += " " + r.LastDetail
		}
		if r.LastCheckAt == nil && p.Apps == 0 {
			state, detail = StateFirstCheckSoon, "Not checked yet. The server looks for apps to add every five minutes."
		}
		p.statusFields(r.LastCheckAt, state, detail, r.Enabled)
		out = append(out, p)
	}
	return out, nil
}

// AppRow is one app an all-apps policy handles, with where its update stands.
type AppRow struct {
	PolicyID         uuid.UUID  `json:"policy_id"`
	PackageID        uuid.UUID  `json:"package_id"`
	Name             string     `json:"name"`
	Identifier       string     `json:"identifier"`
	Verified         bool       `json:"verified"`
	State            string     `json:"state"`
	StateText        string     `json:"state_text"`
	LastCheckAt      *time.Time `json:"last_check_at"`
	LastRunAt        *time.Time `json:"last_run_at"`
	LastDeploymentID *uuid.UUID `json:"last_deployment_id"`
	AddedAt          time.Time  `json:"added_at"`
}

// Apps lists the apps an all-apps policy handles.
func (s *Service) Apps(ctx context.Context, org, id uuid.UUID) ([]AppRow, error) {
	q := dbq.New(s.Pool)
	if _, err := q.GetAutoPolicy(ctx, dbq.GetAutoPolicyParams{ID: id, OrgID: org}); err != nil {
		return nil, ErrNotFound
	}
	kids, err := q.ListAutoChildren(ctx, &id)
	if err != nil {
		return nil, err
	}
	out := make([]AppRow, 0, len(kids))
	for _, k := range kids {
		r := AppRow{PolicyID: k.ID, PackageID: k.PackageID, Name: k.PackageName, Identifier: k.PackageIdentifier, Verified: k.PackageVerified,
			LastCheckAt: k.LastCheckAt, LastRunAt: k.LastRunAt, LastDeploymentID: k.LastDeploymentID, AddedAt: k.CreatedAt}
		var sp Policy
		sp.statusFields(k.LastCheckAt, k.LastState, k.LastDetail, k.Enabled)
		r.State, r.StateText = sp.State, sp.StateText
		out = append(out, r)
	}
	return out, nil
}
