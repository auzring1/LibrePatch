package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/catalog"
	"github.com/auzring1/librepatch/internal/server/groups"
	"github.com/auzring1/librepatch/internal/server/inventory"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/server/wingetindex"
	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

// Window is a maintenance window (evaluated on the device).
type Window struct {
	Days            []int  `json:"days"`
	StartMinute     int    `json:"start_minute"`
	DurationMinutes int    `json:"duration_minutes"`
	TZ              string `json:"tz"`
}

// Request creates a deployment.
type Request struct {
	Name                string
	Action              string // install | update | uninstall
	PackageID           uuid.UUID
	Version             string // "" = newest allowed by the pin
	Scope               string // machine | user
	GroupIDs            []uuid.UUID
	DeviceIDs           []uuid.UUID
	StartsAt            time.Time // zero = now
	ExpiresIn           time.Duration
	Window              *Window
	UnverifiedConfirmed bool
	// Actor for audit.
	UserID uuid.UUID
	IP     string
	// Policy, when set, marks a deployment created by a software policy: it is audited as the system
	// acting for that policy rather than as the user who created the policy.
	Policy string
}

// Skip explains why a device got no job.
type Skip struct {
	Device string `json:"device"`
	Reason string `json:"reason"`
}

// Plan is what Create produced.
type Plan struct {
	DeploymentID uuid.UUID `json:"deployment_id"`
	Devices      int       `json:"devices"`
	Jobs         int       `json:"jobs"`
	UserJobs     int       `json:"user_jobs"`
	Skipped      []Skip    `json:"skipped"`
	// PerUserFound counts per-user copies found on target devices and what policy did with them.
	PerUserFound  int    `json:"per_user_found"`
	PerUserPolicy string `json:"per_user_policy"`
}

const (
	maxTargets  = 20000
	maxLifetime = 30 * 24 * time.Hour
)

func (s *Service) resolveTargets(ctx context.Context, q *dbq.Queries, org uuid.UUID, groupIDs, deviceIDs []uuid.UUID) ([]dbq.ListActiveDevicesByIDsRow, error) {
	ids := map[uuid.UUID]bool{}
	for _, d := range deviceIDs {
		ids[d] = true
	}
	if len(groupIDs) > 0 {
		static, err := q.ListStaticGroupDeviceIDs(ctx, dbq.ListStaticGroupDeviceIDsParams{OrgID: org, Column2: groupIDs})
		if err != nil {
			return nil, err
		}
		for _, d := range static {
			ids[d] = true
		}
		for _, gid := range groupIDs {
			g, err := q.GetGroup(ctx, dbq.GetGroupParams{ID: gid, OrgID: org})
			if err != nil {
				return nil, invalid("group %s not found", gid)
			}
			if g.Kind != "dynamic" {
				continue
			}
			f, err := groups.Parse(g.Filter)
			if err != nil {
				return nil, invalid("group %q has an invalid filter", g.Name)
			}
			for off := int32(0); ; off += 500 {
				ms, _, err := groups.Evaluate(ctx, s.Pool, org, f, 500, off)
				if err != nil {
					return nil, fmt.Errorf("evaluate group %q: %w", g.Name, err)
				}
				for _, m := range ms {
					ids[m.ID] = true
				}
				if len(ms) < 500 || len(ids) > maxTargets {
					break
				}
			}
		}
	}
	if len(ids) > maxTargets {
		return nil, invalid("the targets resolve to more than %d devices", maxTargets)
	}
	list := make([]uuid.UUID, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	return q.ListActiveDevicesByIDs(ctx, dbq.ListActiveDevicesByIDsParams{OrgID: org, Column2: list})
}

// Create plans a deployment and queues its jobs. Jobs for connected devices
// are dispatched immediately; the rest when their device next connects.
func (s *Service) Create(ctx context.Context, org uuid.UUID, r Request) (*Plan, error) {
	if n := strings.TrimSpace(r.Name); n == "" || len(n) > 200 {
		return nil, invalid("name must be 1 to 200 characters")
	}
	switch r.Action {
	case "install", "update", "uninstall":
	default:
		return nil, invalid("action must be install, update or uninstall")
	}
	if r.Scope != "machine" && r.Scope != "user" {
		return nil, invalid("scope must be machine or user")
	}
	if len(r.GroupIDs)+len(r.DeviceIDs) == 0 {
		return nil, invalid("choose at least one group or device")
	}
	now := s.now()
	starts := r.StartsAt
	if starts.IsZero() || starts.Before(now) {
		starts = now
	}
	life := r.ExpiresIn
	if life == 0 {
		life = 72 * time.Hour
	}
	if life < time.Hour || life > maxLifetime {
		return nil, invalid("expiry must be between 1 hour and 30 days")
	}
	expires := starts.Add(life)
	var win *agentv1.MaintenanceWindow
	if r.Window != nil {
		w := r.Window
		if w.StartMinute < 0 || w.StartMinute > 1439 || w.DurationMinutes < 1 || w.DurationMinutes > 1440 || len(w.Days) > 7 {
			return nil, invalid("maintenance window out of range")
		}
		win = &agentv1.MaintenanceWindow{StartMinute: uint32(w.StartMinute), DurationMinutes: uint32(w.DurationMinutes), Tz: w.TZ} // #nosec G115 -- bounded above
		for _, d := range w.Days {
			if d < 0 || d > 6 {
				return nil, invalid("maintenance window day out of range")
			}
			win.Days = append(win.Days, uint32(d)) // #nosec G115 -- bounded above
		}
		if w.TZ != "" {
			if _, err := time.LoadLocation(w.TZ); err != nil {
				return nil, invalid("unknown time zone")
			}
		}
	}

	q := dbq.New(s.Pool)
	pkg, err := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: r.PackageID, OrgID: org})
	if err != nil {
		return nil, invalid("package not found")
	}
	var ov *dbq.PackageOverride
	if o, err := q.GetPackageOverride(ctx, dbq.GetPackageOverrideParams{OrgID: org, PackageID: pkg.ID}); err == nil {
		ov = &o
	}
	if ov != nil && ov.Excluded {
		return nil, ErrExcluded
	}
	// What a signed overlay knows about the package (silent arguments, detection rules) sits under the administrator's own
	// override (D122).
	if o := s.overlay(); o != nil {
		if e, ok := o.EntryFor(org, pkg.Identifier); ok {
			ov = catalog.MergeOverride(ov, e)
		}
	}
	// A self-updating app (Chrome, Edge, Zoom, ...) is left to its vendor's updater unless an
	// administrator chose to enforce versions (docs/ARCHITECTURE.md §7.7).
	selfManaged := pkg.SelfUpdating && (ov == nil || ov.SelfUpdatePolicy != "enforce")
	if r.Action == "update" && selfManaged {
		return nil, ErrSelfUpdating
	}
	// Imported (winget) packages must have passed the VM matrix or be confirmed; an
	// administrator's own uploads are not subject to the matrix.
	if pkg.Source == "winget" && !pkg.Verified && !r.UnverifiedConfirmed {
		return nil, ErrUnverified
	}
	devs, err := s.resolveTargets(ctx, q, org, r.GroupIDs, r.DeviceIDs)
	if err != nil {
		return nil, err
	}
	if len(devs) == 0 {
		return nil, ErrNoTargets
	}

	pl := &planner{s: s, q: q, org: org, req: r, pkg: pkg, ov: ov, selfManaged: selfManaged, starts: starts, expires: expires, window: win, plan: &Plan{Devices: len(devs)}}
	if err := pl.prepare(ctx); err != nil {
		return nil, err
	}
	depID := uuid.New()
	pl.plan.DeploymentID = depID
	pl.depID = depID
	if err := pl.build(ctx, devs); err != nil {
		return nil, err
	}
	if len(pl.jobs) == 0 {
		return nil, invalid("no jobs could be planned: %s", firstReason(pl.plan.Skipped))
	}

	var winJSON []byte
	if r.Window != nil {
		winJSON, _ = json.Marshal(r.Window)
	}
	var verID *uuid.UUID
	if pl.version != nil {
		verID = &pl.version.ID
	}
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.InsertDeployment(ctx, dbq.InsertDeploymentParams{ID: depID, OrgID: org, Name: strings.TrimSpace(r.Name), Action: r.Action,
			PackageID: pkg.ID, VersionID: verID, Scope: r.Scope, TargetGroupIds: nzu(r.GroupIDs), TargetDeviceIds: nzu(r.DeviceIDs),
			StartsAt: starts, ExpiresAt: expires, MaintWindow: winJSON, UnverifiedConfirmed: r.UnverifiedConfirmed, CreatedBy: r.UserID}); err != nil {
			return err
		}
		for _, j := range pl.jobs {
			if err := q.InsertJob(ctx, j); err != nil {
				return err
			}
		}
		details := map[string]any{"name": r.Name, "action": r.Action, "package": pkg.Identifier, "scope": r.Scope,
			"devices": pl.plan.Devices, "jobs": pl.plan.Jobs, "skipped": len(pl.plan.Skipped)}
		if pl.version != nil {
			details["version"] = pl.version.Version
		}
		if pkg.Source == "winget" && !pkg.Verified {
			details["unverified_confirmed"] = true
		}
		actorType, actorID := audit.ActorUser, r.UserID.String()
		if r.Policy != "" {
			actorType, actorID = audit.ActorSystem, "policy:"+r.Policy
			details["policy"] = r.Policy
		}
		_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &org, ActorType: actorType, ActorID: actorID, ActorIP: r.IP,
			Action: "deployment.create", TargetType: "deployment", TargetIDs: []string{depID.String()}, Outcome: audit.Success, Details: details}, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	if pl.plan.Skipped == nil {
		pl.plan.Skipped = []Skip{} // JSON [] rather than null
	}
	s.publish(org, "deployment.updated", uuid.Nil, uuid.Nil, depID)
	// Hand jobs to connected devices without blocking the request.
	seen := map[uuid.UUID]bool{}
	var targets []uuid.UUID
	for _, j := range pl.jobs {
		if !seen[j.DeviceID] {
			seen[j.DeviceID] = true
			targets = append(targets, j.DeviceID)
		}
	}
	s.bg.Add(1)
	go func() { // #nosec G118 -- delivery to devices must outlive the HTTP request; Service.Wait tracks it
		defer s.bg.Done()
		bg := context.Background()
		for _, d := range targets {
			s.Dispatch(bg, d)
		}
	}()
	return pl.plan, nil
}

func nzu(u []uuid.UUID) []uuid.UUID {
	if u == nil {
		return []uuid.UUID{}
	}
	return u
}

func firstReason(s []Skip) string {
	if len(s) == 0 {
		return "nothing to do"
	}
	return s[0].Reason
}

// planner builds the job rows of one deployment.
type planner struct {
	s       *Service
	q       *dbq.Queries
	org     uuid.UUID
	req     Request
	pkg     dbq.CatalogPackage
	ov      *dbq.PackageOverride
	starts  time.Time
	expires time.Time
	window  *agentv1.MaintenanceWindow
	plan    *Plan
	depID   uuid.UUID

	version    *dbq.CatalogVersion
	installers []dbq.CatalogInstaller
	targetKey  []byte
	policy     string
	// selfManaged: the vendor updates this app; per-user in-place updates are not ours to do.
	selfManaged bool
	normName    string
	jobs        []dbq.InsertJobParams
	// indexed holds the installed copies the winget index recognised as this package although their display name
	// differs from the package's, by rowKey; the value is the architecture the copy's name or registry view shows
	// ("x64", "x86" or "" when it shows none).
	indexed map[string]string
}

func (p *planner) prepare(ctx context.Context) error {
	p.normName = inventory.NormalizeName(p.pkg.Name, "")
	if p.req.Action == "uninstall" {
		return nil
	}
	vs, err := p.q.ListPackageVersions(ctx, p.pkg.ID)
	if err != nil {
		return err
	}
	pin := ""
	if p.ov != nil {
		pin = p.ov.Pin
	}
	v, err := catalog.ChooseVersion(vs, p.req.Version, pin)
	if err != nil {
		return invalid("%v", err)
	}
	p.version = v
	p.targetKey = vercmp.Key(v.Version)
	if p.installers, err = p.q.ListVersionInstallers(ctx, v.ID); err != nil {
		return err
	}
	// per-user policy: package override, then the organization default
	p.policy = "report_only"
	if os, err := p.q.GetOrgSettings(ctx, p.org); err == nil {
		p.policy = os.UserScopePolicy
	}
	if p.ov != nil && p.ov.UserScopePolicy != "" {
		p.policy = p.ov.UserScopePolicy
	}
	p.plan.PerUserPolicy = p.policy
	return nil
}

func (p *planner) skip(host, reason string) {
	p.plan.Skipped = append(p.plan.Skipped, Skip{Device: host, Reason: reason})
}

func (p *planner) addJob(device uuid.UUID, sid string, typ agentv1.JobType, title string, body proto.Message, depends *uuid.UUID) (uuid.UUID, error) {
	return p.addJobWhen(device, sid, typ, title, body, depends, "")
}

// addJobWhen is addJob with an explicit dependency mode: "" or "success" waits for the parent to
// succeed, "finished" runs once the parent has ended in any way.
func (p *planner) addJobWhen(device uuid.UUID, sid string, typ agentv1.JobType, title string, body proto.Message, depends *uuid.UUID, when string) (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, err
	}
	env := &agentv1.JobEnvelope{Version: 1, JobId: id.String(), OrgId: p.org.String(), DeviceId: device.String(), TargetUserSid: sid,
		Type: typ, DeploymentId: p.depID.String(), Window: p.window, Attempt: 1, NotBefore: p.starts.Unix(), ExpiresAt: p.expires.Unix()}
	switch b := body.(type) {
	case *agentv1.InstallBody:
		env.Body = &agentv1.JobEnvelope_Install{Install: b}
	case *agentv1.UninstallBody:
		env.Body = &agentv1.JobEnvelope_Uninstall{Uninstall: b}
	default:
		return uuid.Nil, fmt.Errorf("unsupported body %T", body)
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(env)
	if err != nil {
		return uuid.Nil, err
	}
	jt := map[agentv1.JobType]string{agentv1.JobType_JOB_TYPE_SOFTWARE_INSTALL: "software_install",
		agentv1.JobType_JOB_TYPE_SOFTWARE_UPDATE: "software_update", agentv1.JobType_JOB_TYPE_SOFTWARE_UNINSTALL: "software_uninstall"}[typ]
	p.jobs = append(p.jobs, dbq.InsertJobParams{ID: id, OrgID: p.org, DeploymentID: &p.depID, DeviceID: device, UserSid: sid, Type: jt, Title: title,
		Body: raw, DependsOn: depends, DependsWhen: when, NotBefore: p.starts, ExpiresAt: p.expires, Attempt: 1})
	p.plan.Jobs++
	if sid != "" {
		p.plan.UserJobs++
	}
	return id, nil
}

func (p *planner) installBody(inst *dbq.CatalogInstaller, scope string, update bool) (*agentv1.InstallBody, error) {
	return catalog.BuildInstallBody(catalog.BuildInput{Pkg: p.pkg, Ver: *p.version, Inst: *inst, Override: p.ov, Scope: scope, Update: update})
}

func (p *planner) title(verb, who string) string {
	t := verb + " " + p.pkg.Name
	if p.version != nil {
		t += " " + p.version.Version
	}
	if who != "" {
		t += " (" + who + ")"
	}
	return t
}

func (p *planner) build(ctx context.Context, devs []dbq.ListActiveDevicesByIDsRow) error {
	ids := make([]uuid.UUID, len(devs))
	for i, d := range devs {
		ids[i] = d.ID
	}
	installs, err := p.q.ListPackageInstalls(ctx, dbq.ListPackageInstallsParams{OrgID: p.org, DeviceIds: ids, NormalizedName: p.normName})
	if err != nil {
		return err
	}
	if p.req.Action == "update" && p.pkg.Source == "winget" {
		extra, err := p.indexMatched(ctx, ids, installs)
		if err != nil {
			return err
		}
		installs = append(installs, extra...)
	}
	byDev := map[uuid.UUID][]dbq.ListPackageInstallsRow{}
	for _, r := range installs {
		byDev[r.DeviceID] = append(byDev[r.DeviceID], r)
	}
	var users map[uuid.UUID][]dbq.ListDeviceUsersForDevicesRow
	if p.req.Action == "install" && p.req.Scope == "user" {
		rows, err := p.q.ListDeviceUsersForDevices(ctx, ids)
		if err != nil {
			return err
		}
		users = map[uuid.UUID][]dbq.ListDeviceUsersForDevicesRow{}
		for _, u := range rows {
			users[u.DeviceID] = append(users[u.DeviceID], u)
		}
	}
	sort.SliceStable(devs, func(i, j int) bool { return strings.ToLower(devs[i].Hostname) < strings.ToLower(devs[j].Hostname) })
	for _, d := range devs {
		rows := byDev[d.ID]
		switch p.req.Action {
		case "uninstall":
			p.planUninstall(d, rows)
		case "install", "update":
			if err := p.planInstall(d, rows, users[d.ID]); err != nil {
				return err
			}
		}
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func rowKey(device uuid.UUID, source, scope, userSID, itemKey string) string {
	return device.String() + "|" + source + "|" + scope + "|" + userSID + "|" + itemKey
}

// installedArch is the architecture an installed copy shows: in its name ("(x86)") or in the registry view that lists it.
func installedArch(name, source string) string {
	if _, a := wingetindex.NormalizeName(name); a != "" {
		return strings.ToLower(a)
	}
	switch source {
	case "reg32", "hku32":
		return "x86"
	case "reg64":
		return "x64"
	}
	return ""
}

// indexMatched finds the installed copies of this winget package that the name lookup missed. The Software updates
// page recognises programs through the winget index (product codes and normalized names), so a program such as
// "Microsoft Windows Desktop Runtime (x64)" is offered an update to the package "Microsoft .NET Windows Desktop
// Runtime 10.0"; looking copies up by the package's own name, as ListPackageInstalls does, would find none of them and
// plan nothing. Copies already in found are not repeated.
func (p *planner) indexMatched(ctx context.Context, devices []uuid.UUID, found []dbq.ListPackageInstallsRow) ([]dbq.ListPackageInstallsRow, error) {
	m := p.s.Winget.Matcher()
	if m == nil {
		return nil, nil
	}
	have := map[string]bool{}
	for _, r := range found {
		have[rowKey(r.DeviceID, r.Source, r.Scope, r.UserSid, r.ItemKey)] = true
	}
	rows, err := p.q.ListInstallRowsForDevices(ctx, devices)
	if err != nil {
		return nil, err
	}
	var out []dbq.ListPackageInstallsRow
	for _, r := range rows {
		k := rowKey(r.DeviceID, r.Source, r.Scope, r.UserSid, r.ItemKey)
		if have[k] || r.VersionKey == nil {
			continue
		}
		fm, ok := m.Find(wingetindex.Installed{Name: r.Name, Publisher: r.Publisher, ItemKey: r.ItemKey, ProductCode: r.ProductCode, Source: r.Source})
		if !ok || !strings.EqualFold(fm.ID, p.pkg.Identifier) {
			continue
		}
		if p.indexed == nil {
			p.indexed = map[string]string{}
		}
		p.indexed[k] = installedArch(r.Name, r.Source)
		out = append(out, dbq.ListPackageInstallsRow{DeviceID: r.DeviceID, Source: r.Source, Scope: r.Scope, UserSid: r.UserSid, ItemKey: r.ItemKey,
			Version: r.Version, VersionKey: r.VersionKey, Name: r.Name})
	}
	return out, nil
}

func olderThanTarget(r dbq.ListPackageInstallsRow, key []byte) bool {
	if r.VersionKey == nil {
		return true // unknown version: let the installer decide
	}
	return string(r.VersionKey) < string(key)
}

func (p *planner) planInstall(d dbq.ListActiveDevicesByIDsRow, rows []dbq.ListPackageInstallsRow, devUsers []dbq.ListDeviceUsersForDevicesRow) error {
	update := p.req.Action == "update"
	var machineRows, userRows []dbq.ListPackageInstallsRow
	for _, r := range rows {
		if r.Scope == "machine" {
			machineRows = append(machineRows, r)
		} else {
			userRows = append(userRows, r)
		}
	}
	if p.req.Scope == "user" {
		inst := catalog.SelectInstaller(p.installers, d.Arch, "user")
		if inst == nil {
			p.skip(d.Hostname, "the package has no user-scope installer for this device")
			return nil
		}
		if update {
			n := 0
			for _, r := range userRows {
				if !olderThanTarget(r, p.targetKey) || r.UserSid == "" {
					continue
				}
				body, err := p.installBody(inst, "user", true)
				if err != nil {
					p.skip(d.Hostname, err.Error())
					return nil
				}
				if _, err := p.addJob(d.ID, r.UserSid, agentv1.JobType_JOB_TYPE_SOFTWARE_UPDATE, p.title("Update", r.UserSid), body, nil); err != nil {
					return err
				}
				n++
			}
			if n == 0 {
				p.skip(d.Hostname, "no per-user copy older than the target version")
			}
			return nil
		}
		if len(devUsers) == 0 {
			p.skip(d.Hostname, "no user profiles are known on this device yet")
			return nil
		}
		for _, u := range devUsers {
			body, err := p.installBody(inst, "user", false)
			if err != nil {
				p.skip(d.Hostname, err.Error())
				return nil
			}
			if _, err := p.addJob(d.ID, u.Sid, agentv1.JobType_JOB_TYPE_SOFTWARE_INSTALL, p.title("Install", u.Username), body, nil); err != nil {
				return err
			}
		}
		return nil
	}

	// machine scope
	if update {
		old := false
		for _, r := range machineRows {
			if olderThanTarget(r, p.targetKey) {
				old = true
			}
		}
		if len(machineRows) == 0 {
			p.skip(d.Hostname, "not installed machine-wide")
		} else if !old {
			p.skip(d.Hostname, "already at or above the target version")
		}
		if !old {
			return p.planUserExtras(d, userRows, nil)
		}
	}
	// Copies the winget index recognised (their name differs from the package's) are updated with an installer of
	// their own architecture, one job per architecture, and nothing is removed first: the installer upgrades them in
	// place, and removing, say, the x86 runtime because an x64 one was installed would break programs.
	var nameRows []dbq.ListPackageInstallsRow
	archOld := map[string]bool{}
	hasIndexed := false
	for _, r := range machineRows {
		if a, ok := p.indexed[rowKey(r.DeviceID, r.Source, r.Scope, r.UserSid, r.ItemKey)]; ok {
			hasIndexed = true
			if olderThanTarget(r, p.targetKey) {
				archOld[a] = true
			}
			continue
		}
		nameRows = append(nameRows, r)
	}
	var indexJobs []uuid.UUID
	for _, a := range []string{"", "x64", "x86"} {
		if !archOld[a] {
			continue
		}
		devArch := d.Arch
		switch a {
		case "x64":
			devArch = "amd64"
		case "x86":
			devArch = "x86"
		}
		inst := catalog.SelectInstaller(p.installers, devArch, "machine")
		if inst == nil {
			p.skip(d.Hostname, "the package has no machine-wide installer for the installed copy ("+firstNonEmpty(a, d.Arch)+")")
			continue
		}
		body, err := p.installBody(inst, "machine", true)
		if err != nil {
			p.skip(d.Hostname, err.Error())
			continue
		}
		title := p.title("Update", "")
		if a != "" {
			title = p.title("Update", a)
		}
		id, err := p.addJobWhen(d.ID, "", agentv1.JobType_JOB_TYPE_SOFTWARE_UPDATE, title, body, nil, "finished")
		if err != nil {
			return err
		}
		indexJobs = append(indexJobs, id)
	}
	nameOld := false
	for _, r := range nameRows {
		if olderThanTarget(r, p.targetKey) {
			nameOld = true
		}
	}
	if hasIndexed && !nameOld {
		var dep *uuid.UUID
		if len(indexJobs) > 0 {
			dep = &indexJobs[0]
		}
		return p.planUserExtras(d, userRows, dep)
	}
	machineRows = nameRows

	inst := catalog.SelectInstaller(p.installers, d.Arch, "machine")
	if inst == nil {
		p.skip(d.Hostname, "the package has no machine-wide installer for this device ("+d.Arch+")")
		return p.planUserExtras(d, userRows, nil)
	}
	body, err := p.installBody(inst, "machine", update)
	if err != nil {
		p.skip(d.Hostname, err.Error())
		return nil
	}
	typ, verb := agentv1.JobType_JOB_TYPE_SOFTWARE_INSTALL, "Install"
	if update {
		typ, verb = agentv1.JobType_JOB_TYPE_SOFTWARE_UPDATE, "Update"
	}
	// An update removes older copies that the new installer will not replace by itself (for example
	// a 25.01 EXE install when the update is an MSI): they are uninstalled first, one after another,
	// and the install runs after them whether or not each removal succeeded.
	var after *uuid.UUID
	if update {
		var err error
		if after, err = p.planCleanup(d, machineRows, body); err != nil {
			return err
		}
	}
	machineJob, err := p.addJobWhen(d.ID, "", typ, p.title(verb, ""), body, after, "finished")
	if err != nil {
		return err
	}
	return p.planUserExtras(d, userRows, &machineJob)
}

// planCleanup queues "remove the old copy" jobs for machine-wide rows that are older than the target
// and that the new installer will not upgrade in place. It returns the last job of the chain (nil if
// there is nothing to remove). Rows the new installer registers under the same key are left to it.
func (p *planner) planCleanup(d dbq.ListActiveDevicesByIDsRow, rows []dbq.ListPackageInstallsRow, newBody *agentv1.InstallBody) (*uuid.UUID, error) {
	var last *uuid.UUID
	for _, r := range rows {
		if !olderThanTarget(r, p.targetKey) || replacedInPlace(r.ItemKey, newBody) {
			continue
		}
		ub := uninstallBody(p.pkg, r, "machine")
		ub.RemoveOlderThan = p.version.Version
		id, err := p.addJobWhen(d.ID, "", agentv1.JobType_JOB_TYPE_SOFTWARE_UNINSTALL, "Remove old "+p.pkg.Name+" "+r.Version, ub, last, "finished")
		if err != nil {
			return nil, err
		}
		last = &id
	}
	return last, nil
}

// replacedInPlace reports whether the new installer registers under the given Uninstall key (its
// detection rules name that key), meaning it upgrades that copy itself.
func replacedInPlace(itemKey string, b *agentv1.InstallBody) bool {
	for _, r := range b.Detection {
		if (r.Kind == agentv1.DetectionKind_DETECTION_KIND_MSI_PRODUCT || r.Kind == agentv1.DetectionKind_DETECTION_KIND_REGISTRY) &&
			strings.EqualFold(r.Key, itemKey) {
			return true
		}
	}
	return false
}

// planUserExtras applies the per-user app policy to per-user copies found on a
// device that is getting a machine-wide deployment (docs/ARCHITECTURE.md §7.4).
func (p *planner) planUserExtras(d dbq.ListActiveDevicesByIDsRow, userRows []dbq.ListPackageInstallsRow, machineJob *uuid.UUID) error {
	if len(userRows) == 0 || p.req.Scope != "machine" {
		return nil
	}
	p.plan.PerUserFound += len(userRows)
	switch p.policy {
	case "update_in_place":
		if p.selfManaged {
			p.skip(d.Hostname, "per-user copy left to the app's own updater (self-updating); set the package's self-update policy to enforce to update it")
			break
		}
		inst := catalog.SelectInstaller(p.installers, d.Arch, "user")
		for _, r := range userRows {
			if r.UserSid == "" || !olderThanTarget(r, p.targetKey) {
				continue
			}
			if inst == nil {
				p.skip(d.Hostname, "per-user copy found but the package has no user-scope installer to update it")
				break
			}
			body, err := p.installBody(inst, "user", true)
			if err != nil {
				p.skip(d.Hostname, err.Error())
				break
			}
			if _, err := p.addJob(d.ID, r.UserSid, agentv1.JobType_JOB_TYPE_SOFTWARE_UPDATE, p.title("Update", r.UserSid), body, nil); err != nil {
				return err
			}
		}
	case "convert_to_machine", "remove":
		for _, r := range userRows {
			if r.UserSid == "" {
				continue
			}
			var dep *uuid.UUID
			if p.policy == "convert_to_machine" {
				if machineJob == nil {
					continue // without a machine job there is nothing to convert to
				}
				dep = machineJob
			}
			if _, err := p.addJob(d.ID, r.UserSid, agentv1.JobType_JOB_TYPE_SOFTWARE_UNINSTALL, "Remove per-user "+p.pkg.Name, uninstallBody(p.pkg, r, "user"), dep); err != nil {
				return err
			}
		}
	}
	return nil
}

func uninstallBody(pkg dbq.CatalogPackage, r dbq.ListPackageInstallsRow, scope string) *agentv1.UninstallBody {
	sc := agentv1.InstallScope_INSTALL_SCOPE_MACHINE
	if scope == "user" {
		sc = agentv1.InstallScope_INSTALL_SCOPE_USER
	}
	return &agentv1.UninstallBody{PackageId: pkg.Identifier, Name: pkg.Name, Scope: sc, ItemSource: r.Source, ItemKey: r.ItemKey,
		Method: agentv1.UninstallMethod_UNINSTALL_METHOD_AUTO, TimeoutS: 3600, MaxRetries: 1, RetryBackoffS: 120}
}

func (p *planner) planUninstall(d dbq.ListActiveDevicesByIDsRow, rows []dbq.ListPackageInstallsRow) {
	n := 0
	for _, r := range rows {
		if r.Scope != p.req.Scope {
			continue
		}
		sid := ""
		if r.Scope == "user" {
			sid = r.UserSid
		}
		_, _ = p.addJob(d.ID, sid, agentv1.JobType_JOB_TYPE_SOFTWARE_UNINSTALL, "Uninstall "+r.Name, uninstallBody(p.pkg, r, r.Scope), nil)
		n++
	}
	if n == 0 {
		p.skip(d.Hostname, "the software is not installed in this scope")
	}
}

// ResolveTargets returns the active devices behind groups and explicit device IDs.
func (s *Service) ResolveTargets(ctx context.Context, org uuid.UUID, groupIDs, deviceIDs []uuid.UUID) ([]dbq.ListActiveDevicesByIDsRow, error) {
	return s.resolveTargets(ctx, dbq.New(s.Pool), org, groupIDs, deviceIDs)
}
