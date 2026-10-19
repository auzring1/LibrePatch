package deploy

import (
	"context"
	"crypto/sha256"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/catalog"
	"github.com/auzring1/librepatch/internal/server/inventory"
	"github.com/auzring1/librepatch/internal/server/wingetindex"
	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

// useIndex gives the fixture's service the small synthetic winget index.
func (f *fixture) useIndex() {
	f.t.Helper()
	b, err := os.ReadFile("../wingetindex/testdata/mini-source2.msix")
	if err != nil {
		f.t.Fatal(err)
	}
	snap, err := wingetindex.ParseMSIX(b)
	if err != nil {
		f.t.Fatal(err)
	}
	w := &wingetindex.Service{}
	w.Use(snap)
	f.svc.Winget = w
	f.svc.Overlay = catalog.LoadOverlay()
}

// program records an installed program with the details the matcher uses.
func (f *fixture) program(dev uuid.UUID, source, itemKey, name, publisher, productCode, version string) {
	f.t.Helper()
	ctx := context.Background()
	var title uuid.UUID
	norm := inventory.NormalizeName(name, version)
	err := f.pool.QueryRow(ctx, `INSERT INTO software_titles (id, org_id, normalized_name, normalized_publisher, display_name, display_publisher)
		VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (org_id, normalized_name, normalized_publisher) DO UPDATE SET display_name = EXCLUDED.display_name
		RETURNING id`, uuid.New(), f.org, norm, strings.ToLower(publisher), name, publisher).Scan(&title)
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(`INSERT INTO software_installs (device_id, source, scope, user_sid, item_key, title_id, name, version, version_key, publisher, product_code, first_seen_at, last_seen_at)
		VALUES ($1,$2,'machine','',$3,$4,$5,$6,$7,$8,$9,now(),now())`, dev, source, itemKey, title, name, version, vercmp.Key(version), publisher, productCode)
}

func TestUpdatesFromTheWingetIndexNeedNoCatalogEntry(t *testing.T) {
	f := newFixture(t)
	f.useIndex()
	ctx := context.Background()
	old, cur, other := f.device("old", "amd64"), f.device("cur", "amd64"), f.device("other", "amd64")
	f.program(old, "reg64", "7-Zip", "7-Zip 24.08 (x64 edition)", "Igor Pavlov", "", "24.08")
	f.program(old, "reg64", "Google Chrome", "Google Chrome", "Google LLC", "", "154.0.8037.98")
	f.program(old, "reg64", "HSC", "Hospital Scheduling Client", "Contoso Health", "", "1.0")
	f.program(cur, "reg64", "7-Zip", "7-Zip 26.04 (x64 edition)", "Igor Pavlov", "", "26.04")
	f.program(other, "reg64", "Google Chrome", "Google Chrome", "Google LLC", "", "154.0.8000.1")

	ups, err := f.svc.DeviceUpdates(ctx, f.org, old)
	if err != nil || len(ups) != 2 {
		t.Fatalf("%+v %v", ups, err)
	}
	by := map[string]AvailableUpdate{}
	for _, u := range ups {
		by[u.WingetID] = u
	}
	z, c := by["7zip.7zip"], by["Google.Chrome"]
	if z.InCatalog || z.PackageID != uuid.Nil || z.LatestVersion != "26.04" || z.InstalledVersion != "24.08" || !z.Deployable || z.MatchedBy != "product_code" {
		t.Fatalf("7-Zip: %+v", z)
	}
	// Chrome updates itself: listed, but left to the vendor unless an administrator decides otherwise.
	if c.InCatalog || c.LatestVersion != "155.0.8059.40" || c.Deployable || c.Reason == "" || !c.SelfUpdating || c.MatchedBy != "name" {
		t.Fatalf("Chrome: %+v", c)
	}
	if ups, _ := f.svc.DeviceUpdates(ctx, f.org, cur); len(ups) != 0 {
		t.Fatalf("a current install is not an update: %+v", ups)
	}

	fleet, err := f.svc.FleetUpdates(ctx, f.org)
	if err != nil || len(fleet) != 2 {
		t.Fatalf("%+v %v", fleet, err)
	}
	if fleet[0].WingetID != "Google.Chrome" || len(fleet[0].Devices) != 2 || fleet[0].InCatalog || fleet[1].WingetID != "7zip.7zip" || len(fleet[1].Devices) != 1 {
		t.Fatalf("fleet: %+v", fleet)
	}

	// Without an index nothing changes: only the catalog counts.
	f.svc.Winget = nil
	if ups, _ := f.svc.DeviceUpdates(ctx, f.org, old); len(ups) != 0 {
		t.Fatalf("no index, no catalog: %+v", ups)
	}
}

func TestACatalogEntryDecidesInsteadOfTheIndex(t *testing.T) {
	f := newFixture(t)
	f.useIndex()
	ctx := context.Background()
	d := f.device("pc", "amd64")
	f.program(d, "reg64", "7-Zip", "7-Zip 24.08 (x64 edition)", "Igor Pavlov", "", "24.08")

	// Imported under another name: the product code finds it, the catalog's newest allowed version is what counts.
	q := dbq.New(f.pool)
	pid, err := q.UpsertCatalogPackage(ctx, dbq.UpsertCatalogPackageParams{ID: uuid.New(), OrgID: f.org, Source: "winget", Identifier: "7zip.7zip", Name: "Archive Tool", Publisher: "Igor Pavlov"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.UpsertCatalogVersion(ctx, dbq.UpsertCatalogVersionParams{ID: uuid.New(), PackageID: pid, Version: "25.01", VersionKey: vercmp.Key("25.01")}); err != nil {
		t.Fatal(err)
	}
	ups, _ := f.svc.DeviceUpdates(ctx, f.org, d)
	if len(ups) != 1 || !ups[0].InCatalog || ups[0].PackageID != pid || ups[0].LatestVersion != "25.01" || ups[0].WingetID != "7zip.7zip" {
		t.Fatalf("%+v", ups)
	}
	// An administrator excluded the package: the index must not bring it back.
	f.exec("INSERT INTO package_overrides (org_id, package_id, excluded) VALUES ($1,$2,true)", f.org, pid)
	if ups, _ := f.svc.DeviceUpdates(ctx, f.org, d); len(ups) != 0 {
		t.Fatalf("excluded package listed: %+v", ups)
	}
	// A pin below the installed version: same.
	f.exec("UPDATE package_overrides SET excluded = false, pin = '< 24.0'")
	if ups, _ := f.svc.DeviceUpdates(ctx, f.org, d); len(ups) != 0 {
		t.Fatalf("pinned package listed: %+v", ups)
	}
}

// A program the winget index recognises under a different display name than the package's ("Microsoft Windows
// Desktop Runtime 10.0.12 (x64)" for "Microsoft .NET Windows Desktop Runtime 10.0") used to be listed as updatable and
// then refused with "not installed machine-wide", because the planner looked copies up by the package's own name.
func TestUpdateOfAProgramRecognisedUnderAnotherName(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	q := dbq.New(f.pool)
	snap := &wingetindex.Snapshot{Packages: []wingetindex.Package{{
		ID: "Microsoft.DotNet.DesktopRuntime.10", Name: "Microsoft .NET Windows Desktop Runtime 10.0", LatestVersion: "10.0.13",
		NormNames:      []string{"microsoftwindowsdesktopruntime(X64)", "microsoftwindowsdesktopruntime(X86)"},
		NormPublishers: []string{"microsoft"},
	}}}
	w := &wingetindex.Service{}
	w.Use(snap)
	f.svc.Winget = w

	pid, err := q.UpsertCatalogPackage(ctx, dbq.UpsertCatalogPackageParams{ID: uuid.New(), OrgID: f.org, Source: "winget", Identifier: "Microsoft.DotNet.DesktopRuntime.10",
		Name: "Microsoft .NET Windows Desktop Runtime 10.0", Publisher: "Microsoft Corporation"})
	if err != nil {
		t.Fatal(err)
	}
	vid, err := q.UpsertCatalogVersion(ctx, dbq.UpsertCatalogVersionParams{ID: uuid.New(), PackageID: pid, Version: "10.0.13", VersionKey: vercmp.Key("10.0.13")})
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"x64", "x86"} {
		sum := sha256.Sum256([]byte(arch))
		if err := q.InsertCatalogInstaller(ctx, dbq.InsertCatalogInstallerParams{ID: uuid.New(), VersionID: vid, Architecture: arch, Scope: "machine", InstallerType: "burn",
			Url: "https://v.example/dotnet-" + arch + ".exe", Sha256: sum[:], FileName: "dotnet-" + arch + ".exe", Switches: []byte(`{"silent":[],"custom":[]}`),
			SuccessCodes: []int32{}, ExpectedCodes: []int32{}, Detection: []byte(`[]`)}); err != nil {
			t.Fatal(err)
		}
	}
	f.pkg, _ = q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: pid, OrgID: f.org})
	f.exec("UPDATE catalog_packages SET verified = true WHERE id = $1", pid)

	pc := f.device("pc", "amd64")
	f.program(pc, "reg64", "{x64-bundle}", "Microsoft Windows Desktop Runtime - 10.0.12 (x64)", "Microsoft Corporation", "", "10.0.12.50000")
	f.program(pc, "reg32", "{x86-bundle}", "Microsoft Windows Desktop Runtime - 10.0.12 (x86)", "Microsoft Corporation", "", "10.0.12.50000")
	current := f.device("current", "amd64")
	f.program(current, "reg64", "{x64-new}", "Microsoft Windows Desktop Runtime - 10.0.13 (x64)", "Microsoft Corporation", "", "10.0.13.50000")
	none := f.device("none", "amd64")

	plan, err := f.create(Request{Action: "update", Scope: "machine", DeviceIDs: []uuid.UUID{pc, current, none}})
	if err != nil {
		t.Fatal(err)
	}
	// One update per installed architecture, none of them preceded by a removal, nothing for the current or empty PCs.
	if plan.Jobs != 2 || len(plan.Skipped) != 2 {
		t.Fatalf("plan: %+v", plan)
	}
	files := map[string]bool{}
	for _, j := range f.jobs(plan.DeploymentID) {
		if j.DeviceID != pc || j.Type != "software_update" {
			t.Fatalf("unexpected job: %s for %s", j.Type, j.DeviceID)
		}
		files[envOf(t, j).GetInstall().Installer.FileName] = true
	}
	if !files["dotnet-x64.exe"] || !files["dotnet-x86.exe"] {
		t.Fatalf("each architecture must get its own installer: %v", files)
	}
}

// Citrix Workspace's current and LTSR releases are two winget packages that share one uninstall key and one name.
// The installed program's name carries the release ("Citrix Workspace 2607"), which no catalog name matches, so it
// used to be recognised by nobody. The package the administrator imported is the one that counts.
func TestSharedKeyIsSettledByTheImportedPackage(t *testing.T) {
	f := newFixture(t)
	f.useIndex()
	ctx := context.Background()
	d := f.device("pc", "amd64")
	f.program(d, "reg32", "CitrixOnlinePluginPackWeb", "Citrix Workspace 2607", "Citrix Systems, Inc.", "", "26.7.0.269")

	// Not imported yet: two packages fit equally well, so nothing is offered, and the console says why.
	ups, checks, err := f.svc.DeviceUpdateReport(ctx, f.org, d)
	if err != nil || len(ups) != 0 || len(checks) != 1 || checks[0].Status != "unrecognised" || !strings.Contains(checks[0].Message, "Citrix.Workspace.LTSR") {
		t.Fatalf("%+v %+v %v", ups, checks, err)
	}

	q := dbq.New(f.pool)
	pid, err := q.UpsertCatalogPackage(ctx, dbq.UpsertCatalogPackageParams{ID: uuid.New(), OrgID: f.org, Source: "winget", Identifier: "Citrix.Workspace.LTSR", Name: "Citrix Workspace", Publisher: "Citrix Systems, Inc."})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.UpsertCatalogVersion(ctx, dbq.UpsertCatalogVersionParams{ID: uuid.New(), PackageID: pid, Version: "26.7.1.4", VersionKey: vercmp.Key("26.7.1.4")}); err != nil {
		t.Fatal(err)
	}
	ups, checks, err = f.svc.DeviceUpdateReport(ctx, f.org, d)
	if err != nil || len(ups) != 1 || len(checks) != 0 {
		t.Fatalf("%+v %+v %v", ups, checks, err)
	}
	if u := ups[0]; !u.InCatalog || u.PackageID != pid || u.LatestVersion != "26.7.1.4" || u.WingetID != "Citrix.Workspace.LTSR" || u.MatchedBy != "product_code" {
		t.Fatalf("%+v", u)
	}
}

func TestChecksExplainWhyThereIsNoUpdate(t *testing.T) {
	f := newFixture(t)
	f.useIndex()
	ctx := context.Background()
	d := f.device("pc", "amd64")
	f.program(d, "reg64", "7-Zip", "7-Zip 26.04 (x64 edition)", "Igor Pavlov", "", "26.04")
	f.program(d, "reg32", "MicroSIP", "MicroSIP", "", "", "3.22.18")
	f.program(d, "portable", "tool", "Some Portable Tool", "Contoso Health", "", "1.0")
	f.program(d, "reg64", "HSC", "Hospital Scheduling Client", "Contoso Health", "", "1.0")

	ups, checks, err := f.svc.DeviceUpdateReport(ctx, f.org, d)
	if err != nil || len(ups) != 0 {
		t.Fatalf("%+v %v", ups, err)
	}
	by := map[string]UpdateCheck{}
	for _, c := range checks {
		by[c.ItemKey] = c
	}
	if len(by) != 4 {
		t.Fatalf("%+v", checks)
	}
	for key, want := range map[string]struct{ status, text string }{
		"7-Zip":    {"current", "Up to date"},
		"MicroSIP": {"unrecognised", "no publisher"},
		"tool":     {"skipped", "Portable"},
		"HSC":      {"unrecognised", "Not in the winget list"},
	} {
		if got := by[key]; got.Status != want.status || !strings.Contains(got.Message, want.text) {
			t.Errorf("%s: %+v, want %s containing %q", key, got, want.status, want.text)
		}
	}
	if c := by["7-Zip"]; c.Source != "reg64" || c.Scope != "machine" {
		t.Fatalf("the row it belongs to: %+v", c)
	}

	// Without an index the check says so rather than staying silent.
	f.svc.Winget = nil
	_, checks, _ = f.svc.DeviceUpdateReport(ctx, f.org, d)
	for _, c := range checks {
		if c.Status != "skipped" || !strings.Contains(c.Message, "winget list is not loaded") {
			t.Fatalf("%+v", c)
		}
	}
}

// fleetUpdatesFull is the page as it was built before FleetUpdates read the device rows of only the products that have
// an update: every install row of every active device, checked one by one.
func (s *Service) fleetUpdatesFull(ctx context.Context, org uuid.UUID) ([]FleetUpdate, error) {
	all, err := dbq.New(s.Pool).ListFleetInstallRows(ctx, org)
	if err != nil {
		return nil, err
	}
	u, err := s.newUpdater(ctx, org)
	if err != nil {
		return nil, err
	}
	rows := make([]fleetRow, len(all))
	for i, r := range all {
		rows[i] = fleetRow{r.DeviceID, r.Hostname, r.Scope, installRow{name: r.Name, version: r.Version, publisher: r.Publisher, itemKey: r.ItemKey,
			productCode: r.ProductCode, source: r.Source, normalizedName: r.NormalizedName, versionKey: r.VersionKey}}
	}
	return groupFleetUpdates(rows, u), nil
}

// FleetUpdates must give exactly the page that checking every install row gives.
func TestFleetUpdatesEqualsCheckingEveryInstallRow(t *testing.T) {
	f := newFixture(t)
	f.useIndex()
	ctx := context.Background()
	var devs []uuid.UUID
	for _, h := range []string{"alpha", "bravo", "charlie", "delta", "echo", "Foxtrot"} {
		devs = append(devs, f.device(h, "amd64"))
	}
	for i, d := range devs {
		ver7z := []string{"24.08", "26.04", "23.01"}[i%3]
		f.program(d, "reg64", "7-Zip", "7-Zip "+ver7z+" (x64 edition)", "Igor Pavlov", "", ver7z)
		f.program(d, "reg64", "Google Chrome", "Google Chrome", "Google LLC", "", []string{"154.0.8037.98", "155.0.8059.40"}[i%2])
		f.program(d, "reg64", "HSC", "Hospital Scheduling Client", "Contoso Health", "", "1.0")
	}
	// The same program in another registry view, as a per-user install, and rows that are never updated by an installer.
	f.program(devs[0], "reg32", "7-Zip", "7-Zip 24.08 (x64 edition)", "Igor Pavlov", "", "24.08")
	f.exec(`INSERT INTO software_installs (device_id, source, scope, user_sid, item_key, title_id, name, version, version_key, publisher, product_code, first_seen_at, last_seen_at)
		SELECT device_id, 'hku', 'user', 'S-1-5-21-1', item_key, title_id, name, version, version_key, publisher, product_code, now(), now()
		FROM software_installs WHERE device_id = $1 AND source = 'reg64' AND name LIKE 'Google Chrome'`, devs[1])
	f.program(devs[2], "appx", "Microsoft.Foo", "Foo Store App", "Microsoft", "", "1.0")
	f.program(devs[3], "portable", "tool", "Tool", "Somebody", "", "1.0")
	f.exec(`UPDATE software_installs SET system_component = true WHERE device_id = $1 AND name LIKE '7-Zip%'`, devs[4])
	revoked := f.device("revoked-pc", "amd64")
	f.program(revoked, "reg64", "7-Zip", "7-Zip 20.00 (x64 edition)", "Igor Pavlov", "", "20.00")
	f.exec(`UPDATE devices SET status = 'revoked' WHERE id = $1`, revoked)

	want, err := f.svc.fleetUpdatesFull(ctx, f.org)
	if err != nil || len(want) != 2 {
		t.Fatalf("full read: %+v %v", want, err)
	}
	defer func(v float64) { fleetTargetedShare = v }(fleetTargetedShare)
	for _, share := range []float64{2, -1} { // read only the products with an update, then read everything
		fleetTargetedShare = share
		got, err := f.svc.FleetUpdates(ctx, f.org)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("FleetUpdates (share %v) differs from checking every row:\n got %+v\nwant %+v", share, got, want)
		}
	}
	total := 0
	for _, u := range want {
		total += len(u.Devices)
	}
	if total < 6 {
		t.Fatalf("the data should produce several update rows, got %d: %+v", total, want)
	}
}
