package deploy

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

// An MSIX/AppX package from the catalog is deployed to the whole computer through the agent's own script (D151): the job
// carries the package, its identity in a detection rule and no arguments.
func TestMSIXPackageIsDeployedMachineWide(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	q := dbq.New(f.pool)
	pid, err := q.UpsertCatalogPackage(ctx, dbq.UpsertCatalogPackageParams{ID: uuid.New(), OrgID: f.org, Source: "winget", Identifier: "Contoso.Terminal", Name: "Contoso Terminal", Publisher: "Contoso Health"})
	if err != nil {
		t.Fatal(err)
	}
	vid, err := q.UpsertCatalogVersion(ctx, dbq.UpsertCatalogVersionParams{ID: uuid.New(), PackageID: pid, Version: "1.25.2733.0", VersionKey: vercmp.Key("1.25.2733.0")})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("bundle"))
	if err := q.InsertCatalogInstaller(ctx, dbq.InsertCatalogInstallerParams{ID: uuid.New(), VersionID: vid, Architecture: "x64", Scope: "machine", InstallerType: "msix",
		Url: "https://v.example/Terminal.msixbundle", Sha256: sum[:], FileName: "Terminal.msixbundle", Switches: []byte(`{"silent":[],"custom":[]}`),
		SuccessCodes: []int32{}, ExpectedCodes: []int32{},
		Detection: []byte(`[{"kind":"appx","key":"Contoso.Terminal_","version":"1.25.2733.0","cmp":"ge"}]`)}); err != nil {
		t.Fatal(err)
	}
	f.pkg, _ = q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: pid, OrgID: f.org})
	dev := f.device("pc-1", "amd64")

	plan, err := f.create(Request{Action: "install", Scope: "machine", DeviceIDs: []uuid.UUID{dev}, UnverifiedConfirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Jobs != 1 || len(plan.Skipped) != 0 {
		t.Fatalf("%+v", plan)
	}
	env := envOf(t, f.jobs(plan.DeploymentID)[0])
	b := env.GetInstall()
	if b == nil || b.Installer.Type != agentv1.InstallerType_INSTALLER_TYPE_MSIX || b.Scope != agentv1.InstallScope_INSTALL_SCOPE_MACHINE || b.Installer.FileName != "Terminal.msixbundle" {
		t.Fatalf("install body: %+v", b)
	}
	if len(b.Installer.Args) != 0 || len(b.Detection) != 1 || b.Detection[0].Kind != agentv1.DetectionKind_DETECTION_KIND_APPX || b.Detection[0].Key != "Contoso.Terminal_" {
		t.Fatalf("args %v, detection %+v", b.Installer.Args, b.Detection)
	}
}

// The inventory lists MSIX/AppX apps; those installed for the whole computer can be removed from the device page.
func TestMSIXAppsCanBeRemovedFromTheInventory(t *testing.T) {
	f := newFixture(t)
	dev := f.device("pc-1", "amd64")
	full := "Contoso.Terminal_1.25.2733.0_x64__8wekyb3d8bbwe"
	f.install(dev, "machine", "", "appx", full, "1.25.2733.0")
	f.install(dev, "user", sidA, "appx", "Contoso.Other_1.0.0.0_x64__8wekyb3d8bbwe", "1.0.0.0")

	res, err := f.svc.UninstallSoftware(context.Background(), f.org, f.user, dev, "127.0.0.1", []SoftwareRef{
		{Source: "appx", Scope: "machine", ItemKey: full},
		{Source: "appx", Scope: "user", UserSID: sidA, ItemKey: "Contoso.Other_1.0.0.0_x64__8wekyb3d8bbwe"},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Wait()
	if len(res.JobIDs) != 1 || len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0].Reason, "one person only") {
		t.Fatalf("%+v", res)
	}
	j, err := dbq.New(f.pool).GetJob(context.Background(), dbq.GetJobParams{ID: res.JobIDs[0], OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	u := envOf(t, j).GetUninstall()
	if u == nil || u.ItemSource != "appx" || u.ItemKey != full || u.Scope != agentv1.InstallScope_INSTALL_SCOPE_MACHINE {
		t.Fatalf("uninstall body: %+v", u)
	}
}
