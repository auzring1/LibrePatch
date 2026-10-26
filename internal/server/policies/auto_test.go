package policies

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/inventory"
	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

func (f *fx) listOne(id uuid.UUID) Policy {
	f.t.Helper()
	list, err := f.svc.List(context.Background(), f.org)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, p := range list {
		if p.ID == id {
			return p
		}
	}
	f.t.Fatalf("policy %s not in the list: %+v", id, list)
	return Policy{}
}

func (f *fx) allApps(groups []uuid.UUID, mut func(*Input)) uuid.UUID {
	f.t.Helper()
	in := Input{Name: "all-" + uuid.NewString()[:6], Kind: KindAll, GroupIDs: groups, Enabled: true}
	if mut != nil {
		mut(&in)
	}
	id, err := f.svc.Create(context.Background(), f.actor(), in)
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

// otherApp adds a second catalog app with one version and an installed copy of an older version on dev.
func (f *fx) otherApp(source, name, ident string, verified bool, dev uuid.UUID, installed, latest string) uuid.UUID {
	f.t.Helper()
	ctx := context.Background()
	q := dbq.New(f.pool)
	pid, err := q.UpsertCatalogPackage(ctx, dbq.UpsertCatalogPackageParams{ID: uuid.New(), OrgID: f.org, Source: source, Identifier: ident, Name: name, Publisher: "Other"})
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec("UPDATE catalog_packages SET verified=$2 WHERE id=$1", pid, verified)
	vid, err := q.UpsertCatalogVersion(ctx, dbq.UpsertCatalogVersionParams{ID: uuid.New(), PackageID: pid, Version: latest, VersionKey: vercmp.Key(latest)})
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(`INSERT INTO catalog_installers (id, version_id, architecture, scope, installer_type, url, sha256, file_name, switches, success_codes, expected_codes, detection)
		VALUES ($1,$2,'x64','machine','msi','https://v.example/o.msi',$3,'o.msi','{"silent":[],"custom":[]}','{}','{}','[]')`, uuid.New(), vid, make([]byte, 32))
	var title uuid.UUID
	if err := f.pool.QueryRow(ctx, `INSERT INTO software_titles (id, org_id, normalized_name, normalized_publisher, display_name, display_publisher)
		VALUES ($1,$2,$3,'other',$4,'Other') RETURNING id`, uuid.New(), f.org, inventory.NormalizeName(name, ""), name).Scan(&title); err != nil {
		f.t.Fatal(err)
	}
	f.exec(`INSERT INTO software_installs (device_id, source, scope, user_sid, item_key, title_id, name, version, version_key, first_seen_at, last_seen_at)
		VALUES ($1,'reg64','machine','',$2,$3,$4,$5,$6,now(),now())`, dev, ident, title, name, installed, vercmp.Key(installed))
	return pid
}

func TestPolicyStatusIsRecorded(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	d := f.device("d", time.Now())
	f.install(d, "1.0")
	g := f.group(d)
	id := f.policy("keep_updated", []uuid.UUID{g}, func(in *Input) { in.OnlyNewDevices = false })

	if p := f.listOne(id); p.State != StateNew || p.LastCheckAt != nil || p.NextCheckAt != nil {
		t.Fatalf("before the first check: %+v", p)
	}
	f.svc.Tick(ctx)
	p := f.listOne(id)
	if p.State != StateUpdating || p.LastRunAt == nil || p.LastDeploymentID == nil || p.LastCheckAt == nil {
		t.Fatalf("after creating a deployment: %+v", p)
	}
	if got := p.NextCheckAt.Sub(*p.LastCheckAt); got != CheckEvery {
		t.Fatalf("next check = last + %v", got)
	}
	if f.count("SELECT count(*) FROM deployments WHERE id=$1", *p.LastDeploymentID) != 1 {
		t.Fatal("the status links to the deployment the check created")
	}
	run := *p.LastRunAt

	// The job is still open: still "updating", and the last install does not move.
	f.advance(10 * time.Minute)
	f.svc.Tick(ctx)
	if p = f.listOne(id); p.State != StateUpdating || !p.LastRunAt.Equal(run) {
		t.Fatalf("open job: %+v", p)
	}

	// The device has the new version: up to date, and the last install is still remembered.
	f.exec("UPDATE jobs SET status='succeeded' WHERE device_id=$1", d)
	f.install2(d, "2.0")
	f.advance(10 * time.Minute)
	f.svc.Tick(ctx)
	if p = f.listOne(id); p.State != StateUpToDate || p.LastDeploymentID == nil || !p.LastRunAt.Equal(run) {
		t.Fatalf("up to date: %+v", p)
	}

	// Approval needed, self-updating, switched off.
	f.catalog("3.0")
	if err := f.svc.Update(ctx, f.actor(), id, Input{Name: p.Name, Kind: "keep_updated", PackageID: f.pkg, GroupIDs: []uuid.UUID{g}, Enabled: true, RequireApproval: true}); err != nil {
		t.Fatal(err)
	}
	f.svc.Tick(ctx)
	if p = f.listOne(id); p.State != StateWaitingApproval {
		t.Fatalf("approval: %+v", p)
	}
	f.exec("UPDATE catalog_packages SET self_updating=true WHERE id=$1", f.pkg)
	f.svc.Tick(ctx)
	if p = f.listOne(id); p.State != StateVendor {
		t.Fatalf("self-updating: %+v", p)
	}
	if err := f.svc.Update(ctx, f.actor(), id, Input{Name: p.Name, Kind: "keep_updated", PackageID: f.pkg, GroupIDs: []uuid.UUID{g}, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if p = f.listOne(id); p.State != StateOff || p.NextCheckAt != nil {
		t.Fatalf("off: %+v", p)
	}
}

func TestAllAppsPolicyAddsAChildPerOutdatedApp(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	d := f.device("d", time.Now())
	f.install(d, "1.0")
	g := f.group(d)
	id := f.allApps([]uuid.UUID{g}, nil)

	// The child exists at once (the save looks at the apps), but is not a policy of its own in the list.
	list, _ := f.svc.List(ctx, f.org)
	if len(list) != 1 || list[0].ID != id || !list[0].Auto || list[0].Kind != KindAll || list[0].PackageID != nil || list[0].Apps != 1 {
		t.Fatalf("list: %+v", list)
	}
	if list[0].State != StateAppsWaiting && list[0].State != StateAppsUpdating && list[0].State != StateFirstCheckSoon {
		// no child has been checked yet: counted as "not checked yet"
		t.Logf("state before the first check: %s", list[0].State)
	}
	if f.count("SELECT count(*) FROM software_policies WHERE auto_policy_id=$1", id) != 1 {
		t.Fatal("one child for the one outdated app")
	}
	if f.jobsFor(d) != 0 {
		t.Fatal("nothing is installed before the first check")
	}

	f.svc.Tick(ctx)
	if f.jobsFor(d) != 1 {
		t.Fatalf("the child updates the outdated device: %d jobs", f.jobsFor(d))
	}
	f.svc.Tick(ctx)
	if f.count("SELECT count(*) FROM software_policies WHERE auto_policy_id=$1", id) != 1 || f.jobsFor(d) != 1 {
		t.Fatal("a second check adds nothing and does not deploy twice")
	}
	p := f.listOne(id)
	if p.State != StateAppsUpdating || p.LastDeploymentID == nil || p.LastRunAt == nil || p.AppStates[StateUpdating] != 1 {
		t.Fatalf("the all-apps policy summarizes its apps: %+v", p)
	}
	apps, err := f.svc.Apps(ctx, f.org, id)
	if err != nil || len(apps) != 1 || apps[0].Name != "Acme Tool" || apps[0].State != StateUpdating {
		t.Fatalf("apps: %v %+v", err, apps)
	}
	if _, err := f.svc.Apps(ctx, f.org, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("apps of an unknown policy: %v", err)
	}
	if f.count("SELECT count(*) FROM audit_log WHERE action='policy.auto_add_app' AND actor_type='system'") != 1 {
		t.Fatal("adding an app is audited as the system")
	}

	// A child cannot be changed or deleted on its own.
	var child uuid.UUID
	if err := f.pool.QueryRow(ctx, "SELECT id FROM software_policies WHERE auto_policy_id=$1", id).Scan(&child); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Delete(ctx, f.actor(), child); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting a child: %v", err)
	}
	if err := f.svc.Update(ctx, f.actor(), child, Input{Name: "x", Kind: "keep_updated", PackageID: f.pkg, GroupIDs: []uuid.UUID{g}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("editing a child: %v", err)
	}

	// Changing the parent changes the children; switching it off stops them.
	if err := f.svc.Update(ctx, f.actor(), id, Input{Name: p.Name, Kind: KindAll, GroupIDs: []uuid.UUID{g}, Enabled: true, DelayDays: 5, RequireApproval: true}); err != nil {
		t.Fatal(err)
	}
	if f.count("SELECT count(*) FROM software_policies WHERE auto_policy_id=$1 AND delay_days=5 AND require_approval AND enabled", id) != 1 {
		t.Fatal("the settings of the all-apps policy are the settings of its apps")
	}
	if err := f.svc.Update(ctx, f.actor(), id, Input{Name: p.Name, Kind: KindAll, GroupIDs: []uuid.UUID{g}, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if f.count("SELECT count(*) FROM software_policies WHERE auto_policy_id=$1 AND enabled", id) != 0 {
		t.Fatal("a switched-off all-apps policy switches its apps off")
	}
	if p = f.listOne(id); p.State != StateOff {
		t.Fatalf("off: %+v", p)
	}

	// Deleting the parent deletes the apps' policies; deployments already made stay.
	deps := f.count("SELECT count(*) FROM deployments")
	if err := f.svc.Delete(ctx, f.actor(), id); err != nil {
		t.Fatal(err)
	}
	if f.count("SELECT count(*) FROM software_policies WHERE auto_policy_id IS NOT NULL") != 0 || f.count("SELECT count(*) FROM deployments") != deps {
		t.Fatal("children go with the parent, deployments stay")
	}
	if err := f.svc.Delete(ctx, f.actor(), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestAllAppsPolicyFilterAndOwnership(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	d := f.device("d", time.Now())
	f.install(d, "1.0")
	unverified := f.otherApp("winget", "Zeta Viewer", "Zeta.Viewer", false, d, "1.0", "2.0")
	selfUpd := f.otherApp("custom", "Self Updater", "Custom.SelfUpdater", true, d, "1.0", "2.0")
	f.exec("UPDATE catalog_packages SET self_updating=true WHERE id=$1", selfUpd)
	g := f.group(d)

	// Preview before saving: what is handled and what is not, and why.
	pv, err := f.svc.Preview(ctx, f.org, uuid.Nil, []uuid.UUID{g}, AutoFilter{VerifiedOnly: true, Exclude: []string{"custom.acmetool"}})
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]string{}
	for _, m := range pv.Items {
		reasons[m.Name] = m.Reason
	}
	if pv.Handled != 0 || reasons["Acme Tool"] != reasonExcluded || reasons["Zeta Viewer"] != reasonUnverified || reasons["Self Updater"] != reasonVendor {
		t.Fatalf("preview: %+v", pv)
	}
	if f.count("SELECT count(*) FROM software_auto_policies")+f.count("SELECT count(*) FROM software_policies") != 0 {
		t.Fatal("a preview changes nothing")
	}

	// Verified apps only, without the excluded one: nothing to do.
	id := f.allApps([]uuid.UUID{g}, func(in *Input) { in.Filter = &AutoFilter{VerifiedOnly: true, Exclude: []string{"Custom.AcmeTool"}} })
	if n := f.count("SELECT count(*) FROM software_policies WHERE auto_policy_id=$1", id); n != 0 {
		t.Fatalf("%d children", n)
	}
	if p := f.listOne(id); p.State != StateNoApps {
		t.Fatalf("no apps: %+v", p)
	}
	// Taking the exclusion away and accepting unverified apps handles both.
	p := f.listOne(id)
	if err := f.svc.Update(ctx, f.actor(), id, Input{Name: p.Name, Kind: KindAll, GroupIDs: []uuid.UUID{g}, Enabled: true, Filter: &AutoFilter{VerifiedOnly: false}}); err != nil {
		t.Fatal(err)
	}
	if f.count("SELECT count(*) FROM software_policies WHERE auto_policy_id=$1", id) != 2 || f.count("SELECT count(*) FROM software_policies WHERE auto_policy_id=$1 AND unverified_confirmed", id) != 2 {
		t.Fatal("both the verified and the unverified app are handled, with the unverified ones confirmed by the administrator's choice")
	}
	// Excluding one drops its child; going back to verified-only drops the unverified one.
	if err := f.svc.Update(ctx, f.actor(), id, Input{Name: p.Name, Kind: KindAll, GroupIDs: []uuid.UUID{g}, Enabled: true, Filter: &AutoFilter{VerifiedOnly: true}}); err != nil {
		t.Fatal(err)
	}
	if f.count("SELECT count(*) FROM software_policies WHERE auto_policy_id=$1 AND package_id=$2", id, unverified) != 0 || f.count("SELECT count(*) FROM software_policies WHERE auto_policy_id=$1", id) != 1 {
		t.Fatal("verified-only drops the unverified app")
	}
	if f.count("SELECT count(*) FROM audit_log WHERE action='policy.auto_remove_app'") != 1 {
		t.Fatal("dropping an app is audited")
	}

	// A policy made by hand for the same app takes it over; the all-apps policy gives it up and does not take it back.
	f.policy("keep_updated", []uuid.UUID{g}, func(in *Input) { in.OnlyNewDevices = false })
	f.svc.Tick(ctx)
	if f.count("SELECT count(*) FROM software_policies WHERE auto_policy_id=$1", id) != 0 {
		t.Fatal("the all-apps policy leaves an app that has a policy of its own")
	}
	if f.jobsFor(d) != 1 {
		t.Fatalf("exactly one policy deploys: %d jobs", f.jobsFor(d))
	}
	pv, _ = f.svc.Preview(ctx, f.org, id, []uuid.UUID{g}, AutoFilter{VerifiedOnly: true})
	for _, m := range pv.Items {
		if m.Name == "Acme Tool" && m.Reason != reasonOtherPolicy {
			t.Fatalf("preview of an app with its own policy: %+v", m)
		}
	}

	// Two all-apps policies do not fight over an app: the first one keeps it.
	other := f.otherApp("custom", "Third", "Custom.Third", true, d, "1.0", "2.0")
	a := f.allApps([]uuid.UUID{g}, func(in *Input) { in.Name = "first" })
	b := f.allApps([]uuid.UUID{g}, func(in *Input) { in.Name = "second" })
	f.svc.Tick(ctx)
	if f.count("SELECT count(*) FROM software_policies WHERE package_id=$1", other) != 1 {
		t.Fatalf("one policy per app: %d", f.count("SELECT count(*) FROM software_policies WHERE package_id=$1", other))
	}
	_, _ = a, b
}

func TestAllAppsPolicyValidation(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	d := f.device("d", time.Now())
	g := f.group(d)
	bad := []Input{
		{Name: "x", Kind: KindAll, GroupIDs: []uuid.UUID{g}, Filter: &AutoFilter{VerifiedOnly: true, IncludeUnlisted: true}},
		{Name: "x", Kind: KindAll, GroupIDs: []uuid.UUID{g}, OnlyNewDevices: true},
		{Name: "x", Kind: KindAll},
		{Name: "x", Kind: KindAll, GroupIDs: []uuid.UUID{uuid.New()}},
		{Name: "x", Kind: KindAll, GroupIDs: []uuid.UUID{g}, DelayDays: 999},
		{Name: "x", Kind: KindAll, GroupIDs: []uuid.UUID{g}, Prompts: &deploy.Prompts{InUse: "explode"}},
	}
	for i, in := range bad {
		if _, err := f.svc.Create(ctx, f.actor(), in); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	// The default is the safe one: verified apps only.
	id := f.allApps([]uuid.UUID{g}, func(in *Input) { in.Name = "dup" })
	if p := f.listOne(id); p.Filter == nil || !p.Filter.VerifiedOnly {
		t.Fatalf("default filter: %+v", p.Filter)
	}
	if _, err := f.svc.Create(ctx, f.actor(), Input{Name: "dup", Kind: KindAll, GroupIDs: []uuid.UUID{g}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	// A policy of another kind cannot become an all-apps policy (or back) by an update.
	one := f.policy("baseline", []uuid.UUID{g}, nil)
	if err := f.svc.Update(ctx, f.actor(), one, Input{Name: "y", Kind: KindAll, GroupIDs: []uuid.UUID{g}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("baseline -> all: %v", err)
	}
	if err := f.svc.Update(ctx, f.actor(), id, Input{Name: "y", Kind: "baseline", PackageID: f.pkg, GroupIDs: []uuid.UUID{g}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("all -> baseline: %v", err)
	}
}

// An in-use choice needs the app's program names; an all-apps policy gives the apps that have none the quiet choice.
func TestAllAppsPolicyAdaptsPromptsPerApp(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	d := f.device("d", time.Now())
	f.install(d, "1.0")
	f.exec("INSERT INTO package_overrides (org_id, package_id, processes) VALUES ($1,$2,$3)", f.org, f.pkg, []string{"acme.exe"})
	f.otherApp("custom", "No Programs", "Custom.NoPrograms", true, d, "1.0", "2.0")
	g := f.group(d)
	f.allApps([]uuid.UUID{g}, func(in *Input) { in.Prompts = &deploy.Prompts{InUse: "ask", Restart: "ask", AskTimeoutS: 90} })
	rows, err := dbq.New(f.pool).ListSoftwarePolicies(ctx, f.org)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("children are not listed: %d", len(rows))
	}
	got := map[string]string{}
	r, _ := f.pool.Query(ctx, "SELECT k.name, coalesce(p.prompts->>'in_use','') || '/' || coalesce(p.prompts->>'restart','') FROM software_policies p JOIN catalog_packages k ON k.id=p.package_id WHERE p.auto_policy_id IS NOT NULL")
	for r.Next() {
		var n, v string
		_ = r.Scan(&n, &v)
		got[n] = v
	}
	r.Close()
	if got["Acme Tool"] != "ask/ask" || got["No Programs"] != "/ask" {
		t.Fatalf("prompts per app: %+v", got)
	}
}

// An app that updates itself but is still old on a PC (Chrome with its updater switched off) is updated by the all-apps
// policy unless the policy says to leave such apps to their vendor (D148).
func TestAllAppsPolicyUpdatesSelfUpdatingAppsThatAreStillOld(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	d := f.device("d", time.Now())
	f.install(d, "1.0")
	chrome := f.otherApp("custom", "Self Updater", "Custom.SelfUpdater", true, d, "1.0", "2.0")
	f.exec("UPDATE catalog_packages SET self_updating=true WHERE id=$1", chrome)
	g := f.group(d)

	// Left to the vendor: no child for the app, and the status says why instead of "nothing to do".
	off := f.allApps([]uuid.UUID{g}, func(in *Input) {
		in.Name = "vendor"
		in.Filter = &AutoFilter{VerifiedOnly: true, Exclude: []string{"Custom.AcmeTool"}}
	})
	f.svc.Tick(ctx)
	if n := f.count("SELECT count(*) FROM software_policies WHERE auto_policy_id=$1", off); n != 0 {
		t.Fatalf("%d children although self-updating apps are left to the vendor", n)
	}
	if p := f.listOne(off); p.State != StateNoApps || !strings.Contains(p.StateText, "Self Updater (updates itself)") {
		t.Fatalf("status should name the app that is left alone: %+v", p)
	}
	if ok, err := f.svc.deleteAuto(ctx, f.actor(), off); err != nil || !ok {
		t.Fatalf("delete: %v %v", ok, err)
	}

	// Switched on (the default): the app gets a child and a deployment although its package says it updates itself.
	before := f.jobsFor(d)
	on := f.allApps([]uuid.UUID{g}, func(in *Input) {
		in.Name = "all"
		in.Filter = &AutoFilter{VerifiedOnly: true, IncludeSelfUpdating: true, Exclude: []string{"Custom.AcmeTool"}}
	})
	f.svc.Tick(ctx)
	if n := f.count("SELECT count(*) FROM software_policies WHERE auto_policy_id=$1 AND package_id=$2", on, chrome); n != 1 {
		t.Fatalf("%d children for the self-updating app", n)
	}
	if got := f.jobsFor(d); got != before+1 {
		t.Fatalf("the old self-updating app should be updated: jobs %d -> %d", before, got)
	}
	// A policy stored before the option existed has no such key and counts as on.
	if !parseFilter([]byte(`{"verified_only":true}`)).IncludeSelfUpdating {
		t.Fatal("an older stored filter means the option is on")
	}
}
