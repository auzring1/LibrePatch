package api

import (
	"testing"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/server/deploy"
)

func TestScope(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	org := &Principal{Access: auth.Access{Org: map[string]bool{auth.PermDevicesRead: true}}}
	if sc := scopeOf(org, auth.PermDevicesRead); !sc.ok || sc.sites != nil || !sc.has(a) {
		t.Fatalf("org-wide: %+v", sc)
	}
	site := &Principal{Access: auth.Access{Org: map[string]bool{}, Sites: map[uuid.UUID]map[string]bool{a: {auth.PermDevicesRead: true}}}}
	sc := scopeOf(site, auth.PermDevicesRead)
	if !sc.ok || !sc.has(a) || sc.has(b) {
		t.Fatalf("site-limited: %+v", sc)
	}
	if sc := scopeOf(site, auth.PermUpdatesRead); sc.ok || sc.has(a) {
		t.Fatalf("no permission: %+v", sc)
	}
}

func TestDashSoftwareFrom(t *testing.T) {
	d1, d2, d3, other := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	pa, pb, pc := uuid.New(), uuid.New(), uuid.New()
	dev := func(ids ...uuid.UUID) []deploy.FleetUpdateDevice {
		var out []deploy.FleetUpdateDevice
		for _, id := range ids {
			out = append(out, deploy.FleetUpdateDevice{DeviceID: id})
		}
		return out
	}
	ups := []deploy.FleetUpdate{
		{PackageID: pa, PackageName: "Alpha", LatestVersion: "2", InCatalog: true, Deployable: true, Devices: dev(d1, d2, d3)},
		{PackageID: pb, PackageName: "Beta", LatestVersion: "9", InCatalog: true, Deployable: true, Devices: dev(d1)},
		{PackageID: pc, PackageName: "Chrome", LatestVersion: "1", InCatalog: true, Deployable: false, Devices: dev(d2)}, // left to its vendor
		{PackageName: "Gamma", LatestVersion: "4", InCatalog: false, Deployable: true, Devices: dev(d3)},                 // not in the catalog yet
		{PackageID: uuid.New(), PackageName: "Elsewhere", InCatalog: true, Deployable: true, Devices: dev(other)},
	}
	all := func(uuid.UUID) bool { return true }
	s := dashSoftwareFrom(ups, all, map[uuid.UUID]bool{pa: true}, false)
	if s.Apps != 4 || s.Devices != 4 || s.Vendor != 1 || s.Auto != 1 || s.AllApps {
		t.Fatalf("numbers: %+v", s)
	}
	if s.Top[0].Name != "Alpha" || s.Top[0].Devices != 3 || !s.Top[0].Automated || s.Top[len(s.Top)-1].Name == "" {
		t.Fatalf("most devices first: %+v", s.Top)
	}
	var gamma *dashSoftwareApp
	for i := range s.Top {
		if s.Top[i].Name == "Gamma" {
			gamma = &s.Top[i]
		}
	}
	if gamma == nil || gamma.PackageID != nil || gamma.Automated {
		t.Fatalf("an app that is not in the catalog has no package and is not automated: %+v", gamma)
	}
	// The site switcher: only the devices of the site count.
	site := func(id uuid.UUID) bool { return id == d1 || id == d2 }
	s = dashSoftwareFrom(ups, site, nil, true)
	if s.Apps != 2 || s.Devices != 2 || s.Vendor != 1 || !s.AllApps {
		t.Fatalf("one site: %+v", s)
	}
	// Nothing out of date: an empty list, not null.
	if s = dashSoftwareFrom(nil, all, nil, false); s.Apps != 0 || s.Top == nil {
		t.Fatalf("empty: %+v", s)
	}
}
