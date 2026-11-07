package api

import (
	"testing"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/vulns"
)

func TestAttachFixesTiesAHitToTheUpdateOfTheSameProgram(t *testing.T) {
	d1, d2 := uuid.New(), uuid.New()
	ff, notIn := uuid.New(), uuid.New()
	ups := []deploy.FleetUpdate{
		{PackageID: ff, PackageName: "Mozilla Firefox", LatestVersion: "125.0.2", InCatalog: true, Deployable: true, Verified: true, Devices: []deploy.FleetUpdateDevice{
			{DeviceID: d1, InstalledVersion: "120.0", Scope: "machine", NormalizedName: "mozilla firefox"},
			{DeviceID: d2, InstalledVersion: "120.0", Scope: "machine", NormalizedName: "mozilla firefox"},
		}},
		{PackageID: notIn, PackageName: "Old Tool", WingetID: "Vendor.OldTool", LatestVersion: "1.2", Deployable: true, Devices: []deploy.FleetUpdateDevice{
			{DeviceID: d1, InstalledVersion: "1.0", Scope: "user", NormalizedName: "old tool"},
		}},
	}
	hits := []vulns.DeviceHit{
		{DeviceID: d1, Product: "Mozilla Firefox", Installed: "120.0", FixedIn: "125.0.1", Title: "mozilla firefox"},         // the newest version is past the fix
		{DeviceID: d2, Product: "Mozilla Firefox", Installed: "120.0", FixedIn: "126.0", Title: "mozilla firefox"},           // the newest version is still affected
		{DeviceID: d1, Product: "Old Tool", Installed: "1.0", FixedIn: "", Title: "old tool"},                                // the advisory names no fixed version
		{DeviceID: d1, Product: "Mozilla Firefox", Installed: "119.0", FixedIn: "125.0.1", Title: "mozilla firefox"},         // another copy: no update known for that version
		{DeviceID: d2, Product: "Windows 11 24H2", Installed: "26100.1", FixedIn: "26100.9", Title: ""},                      // a Windows build has no program update
		{DeviceID: uuid.New(), Product: "Mozilla Firefox", Installed: "120.0", FixedIn: "125.0.1", Title: "mozilla firefox"}, // a device with no update row
	}
	got := attachFixes(hits, ups)
	if len(got) != len(hits) {
		t.Fatalf("every hit is kept: %d", len(got))
	}
	if f := got[0].Update; f == nil || f.Fixes != "yes" || f.PackageID == nil || *f.PackageID != ff || !f.Deployable || f.Scope != "machine" || f.LatestVersion != "125.0.2" {
		t.Fatalf("fixed by the newest version: %+v", f)
	}
	if f := got[1].Update; f == nil || f.Fixes != "no" {
		t.Fatalf("newest version still affected: %+v", f)
	}
	if f := got[2].Update; f == nil || f.Fixes != "unknown" || f.PackageID != nil || f.InCatalog || f.WingetID != "Vendor.OldTool" || f.Scope != "user" {
		t.Fatalf("no fixed version named, not in the catalog yet: %+v", f)
	}
	for i := 3; i < 6; i++ {
		if got[i].Update != nil {
			t.Fatalf("hit %d has no update: %+v", i, got[i].Update)
		}
	}
	if len(attachFixes(hits, nil)) != len(hits) || attachFixes(hits, nil)[0].Update != nil {
		t.Fatal("without the update list nothing is attached")
	}
}
