package wingetindex

import "testing"

func matcher(t *testing.T) *Matcher {
	t.Helper()
	s, err := ParseMSIX(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	return NewMatcher(s)
}

func TestNormalizeName(t *testing.T) {
	for _, c := range []struct{ in, norm, arch string }{
		{"Google Chrome", "googlechrome", ""},
		{"Mozilla Firefox (x64 en-US)", "mozillafirefox", "X64"},
		{"7-Zip 24.08 (x64 edition)", "7zip", "X64"},
		{"Zoom Workplace (64-bit)", "zoomworkplace", "X64"},
		{"Notepad++ (32-bit x86)", "notepad", "X86"},
		{"Splashtop® Streamer", "splashtopstreamer", ""},
		{"Cloud Foundry CLI v8", "cloudfoundrycli", ""},
		{"ASAP Utilities (Home and Student edition)", "asaputilities", ""},
		{"Microsoft Edge", "microsoftedge", ""},
		{"Adobe Acrobat Reader DC - Deutsch", "adobeacrobatreaderdcdeutsch", ""},
	} {
		if n, a := NormalizeName(c.in); n != c.norm || a != c.arch {
			t.Errorf("NormalizeName(%q) = %q, %q; want %q, %q", c.in, n, a, c.norm, c.arch)
		}
	}
	for in, want := range map[string]string{"Google LLC": "google", "Microsoft Corporation": "microsoft", "Citrix Systems, Inc.": "citrixsystems", "Notepad++ Team": "notepadteam", "Zoom Video Communications, Inc.": "zoomvideocommunications"} {
		if got := NormalizePublisher(in); got != want {
			t.Errorf("NormalizePublisher(%q) = %q, want %q", in, got, want)
		}
	}
	if !publishersAgree("zoomvideocommunications", []string{"zoom"}) || publishersAgree("adobe", []string{"ado"}) || publishersAgree("", []string{"x"}) || publishersAgree("dell", []string{"microsoft"}) {
		t.Fatal("publisher agreement rules")
	}
}

func TestFindRecognisesInstalledPrograms(t *testing.T) {
	m := matcher(t)
	for _, c := range []struct {
		name string
		in   Installed
		id   string
		by   string
		none bool
	}{
		{name: "product code of an MSI install", in: Installed{Name: "Google Chrome", Publisher: "Google LLC", ItemKey: "{74BADAF7-9D73-386E-B2E4-2D4B3416A469}", Source: "msi"}, id: "Google.Chrome", by: "product_code"},
		{name: "exe install by name and publisher", in: Installed{Name: "Google Chrome", Publisher: "Google LLC", ItemKey: "Google Chrome", Source: "reg64"}, id: "Google.Chrome", by: "name"},
		{name: "uninstall key name", in: Installed{Name: "Notepad++ (64-bit x64)", Publisher: "Notepad++ Team", ItemKey: "Notepad++", Source: "reg64"}, id: "Notepad++.Notepad++", by: "product_code"},
		{name: "long legal publisher", in: Installed{Name: "Zoom Workplace (64-bit)", Publisher: "Zoom Video Communications, Inc.", ItemKey: "ZoomUMX", Source: "reg64"}, id: "Zoom.Zoom", by: "name"},
		{name: "shared key resolved by name (Firefox)", in: Installed{Name: "Mozilla Firefox (x64 en-US)", Publisher: "Mozilla", ItemKey: "Mozilla Firefox 157.0.1 (x64 en-US)", ProductCode: "mozilla firefox", Source: "reg64"}, id: "Mozilla.Firefox", by: "product_code"},
		{name: "shared key resolved by name (ESR)", in: Installed{Name: "Mozilla Firefox ESR (x64 en-US)", Publisher: "Mozilla", ProductCode: "mozilla firefox", Source: "reg64"}, id: "Mozilla.Firefox.ESR", by: "product_code"},
		{name: "shared key, name decides nothing", in: Installed{Name: "Some Other Browser", Publisher: "Mozilla", ProductCode: "mozilla firefox", Source: "reg64"}, none: true},
		{name: "name without a publisher is not enough", in: Installed{Name: "Google Chrome", ItemKey: "Google Chrome", Source: "reg64"}, none: true},
		{name: "name with another publisher", in: Installed{Name: "Google Chrome", Publisher: "Acme Corp", ItemKey: "x", Source: "reg64"}, none: true},
		{name: "unknown program", in: Installed{Name: "Hospital Scheduling Client", Publisher: "Contoso Health", ItemKey: "HSC", Source: "reg64"}, none: true},
		{name: "store apps are not matched", in: Installed{Name: "Google Chrome", Publisher: "Google LLC", Source: "appx"}, none: true},
	} {
		got, ok := m.Find(c.in)
		if c.none {
			if ok {
				t.Errorf("%s: matched %s", c.name, got.ID)
			}
			continue
		}
		if !ok || got.ID != c.id || got.By != c.by {
			t.Errorf("%s: got %+v ok=%v, want %s by %s", c.name, got, ok, c.id, c.by)
		}
	}
}

func TestMatchNewer(t *testing.T) {
	m := matcher(t)
	got, ok := m.Find(Installed{Name: "Google Chrome", Publisher: "Google LLC", ItemKey: "Google Chrome", Source: "reg64"})
	if !ok {
		t.Fatal("no match")
	}
	old, _ := vercmpKey("154.0.8037.98")
	cur, _ := vercmpKey("155.0.8059.40")
	newer, _ := vercmpKey("156.0.1.1")
	if !got.Newer(old) || got.Newer(cur) || got.Newer(newer) || got.Newer(nil) {
		t.Fatal("version comparison")
	}
}

func TestSearchRanksExactAndPrefixFirst(t *testing.T) {
	m := matcher(t)
	r := m.Search("firefox", 5)
	if len(r) != 2 || r[0].ID != "Mozilla.Firefox" {
		t.Fatalf("%+v", r)
	}
	if r := m.Search("chrome", 3); len(r) != 1 || r[0].ID != "Google.Chrome" {
		t.Fatalf("%+v", r)
	}
	if len(m.Search("", 5)) != 0 || len(m.Search("zzzznothing", 5)) != 0 {
		t.Fatal("empty and unknown queries")
	}
	if p, ok := m.Package("google.chrome"); !ok || p.ID != "Google.Chrome" {
		t.Fatal("package lookup is case-insensitive")
	}
}

func TestRecogniseExplainsWhyNot(t *testing.T) {
	m := matcher(t)
	for _, c := range []struct {
		name string
		in   Installed
		code string
		ids  []string
	}{
		{"store app", Installed{Name: "Google Chrome", Publisher: "Google LLC", Source: "appx"}, "store_app", nil},
		{"portable", Installed{Name: "MicroSIP", Publisher: "MicroSIP", Source: "portable"}, "portable", nil},
		{"name in the index, no publisher listed", Installed{Name: "MicroSIP", ItemKey: "MicroSIP", Source: "reg32"}, "no_publisher", []string{"MicroSIP.MicroSIP"}},
		{"name in the index, other publisher", Installed{Name: "MicroSIP", Publisher: "Contoso Health", ItemKey: "MicroSIP", Source: "reg32"}, "publisher_differs", []string{"MicroSIP.MicroSIP"}},
		{"two packages share the key", Installed{Name: "Citrix Workspace 2607", Publisher: "Citrix Systems, Inc.", ItemKey: "CitrixOnlinePluginPackWeb", Source: "reg32"}, "ambiguous", []string{"Citrix.Workspace", "Citrix.Workspace.LTSR"}},
		{"nothing fits", Installed{Name: "Hospital Scheduling Client", Publisher: "Contoso Health", ItemKey: "HSC", Source: "reg64"}, "unknown", nil},
	} {
		_, why := m.Recognise(c.in, nil)
		if why == nil || why.Code != c.code {
			t.Errorf("%s: reason %+v, want %s", c.name, why, c.code)
			continue
		}
		if len(why.IDs) != len(c.ids) {
			t.Errorf("%s: ids %v, want %v", c.name, why.IDs, c.ids)
			continue
		}
		for i := range c.ids {
			if why.IDs[i] != c.ids[i] {
				t.Errorf("%s: ids %v, want %v", c.name, why.IDs, c.ids)
			}
		}
	}
	if mt, why := m.Recognise(Installed{Name: "MicroSIP", Publisher: "MicroSIP", ItemKey: "MicroSIP", Source: "reg32"}, nil); why != nil || mt.ID != "MicroSIP.MicroSIP" {
		t.Fatalf("name and publisher agree: %+v %+v", mt, why)
	}
}

func TestRecognisePrefersThePackageAlreadyInTheCatalog(t *testing.T) {
	m := matcher(t)
	citrix := Installed{Name: "Citrix Workspace 2607", Publisher: "Citrix Systems, Inc.", ItemKey: "CitrixOnlinePluginPackWeb", Source: "reg32"}
	only := func(id string) func(string) bool { return func(x string) bool { return x == id } }
	if mt, why := m.Recognise(citrix, only("Citrix.Workspace.LTSR")); why != nil || mt.ID != "Citrix.Workspace.LTSR" || mt.By != "product_code" {
		t.Fatalf("the imported edition should win: %+v %+v", mt, why)
	}
	both := func(id string) bool { return id == "Citrix.Workspace" || id == "Citrix.Workspace.LTSR" }
	if _, why := m.Recognise(citrix, both); why == nil || why.Code != "ambiguous" {
		t.Fatalf("both imported: still ambiguous, got %+v", why)
	}
	if _, why := m.Recognise(citrix, only("Google.Chrome")); why == nil {
		t.Fatal("an unrelated catalog package decides nothing")
	}
	// A shared key with a publisher that does not agree is never settled by preference alone.
	other := Installed{Name: "Citrix Workspace 2607", Publisher: "Contoso Health", ItemKey: "CitrixOnlinePluginPackWeb", Source: "reg32"}
	if _, why := m.Recognise(other, only("Citrix.Workspace.LTSR")); why == nil {
		t.Fatal("publisher must still agree")
	}
	// Name and publisher path: the same preference applies.
	if mt, why := m.Recognise(Installed{Name: "Citrix Workspace", Publisher: "Citrix Systems, Inc.", ItemKey: "x", Source: "reg64"}, only("Citrix.Workspace")); why != nil || mt.ID != "Citrix.Workspace" || mt.By != "name" {
		t.Fatalf("name path: %+v %+v", mt, why)
	}
}

// Winget lists Chrome twice, as an MSI package and as an executable package, with the same name, publisher and version.
// Neither is "the" Chrome, so an old Chrome used to be unrecognised until someone imported it by hand.
func TestRecogniseTreatsInstallerFlavoursOfOneAppAsOne(t *testing.T) {
	pub := []string{"google"}
	m := NewMatcher(&Snapshot{Packages: []Package{
		{ID: "Google.Chrome.EXE", Name: "Google Chrome", LatestVersion: "156.0.8078.48", ProductCodes: []string{"google chrome"}, NormNames: []string{"googlechrome"}, NormPublishers: pub},
		{ID: "Google.Chrome", Name: "Google Chrome", LatestVersion: "156.0.8078.48", ProductCodes: []string{"google chrome"}, NormNames: []string{"googlechrome"}, NormPublishers: pub},
		{ID: "Mozilla.Firefox", Name: "Mozilla Firefox", LatestVersion: "150.0", ProductCodes: []string{"mozilla firefox"}, NormNames: []string{"mozillafirefox"}, NormPublishers: []string{"mozilla"}},
		{ID: "Mozilla.Firefox.ESR", Name: "Mozilla Firefox ESR", LatestVersion: "140.5", ProductCodes: []string{"mozilla firefox"}, NormNames: []string{"mozillafirefox"}, NormPublishers: []string{"mozilla"}},
	}})
	// Found by its uninstall key, and by name and publisher alone.
	for _, in := range []Installed{
		{Name: "Google Chrome", Publisher: "Google LLC", ItemKey: "Google Chrome", Source: "reg64"},
		{Name: "Google Chrome", Publisher: "Google LLC", Source: "reg64"},
	} {
		if mt, why := m.Recognise(in, nil); why != nil || mt.ID != "Google.Chrome" {
			t.Errorf("%+v: want Google.Chrome, got %+v %+v", in, mt, why)
		}
	}
	// Different newest versions mean different programs: still not guessed.
	if _, why := m.Recognise(Installed{Name: "Mozilla Firefox", Publisher: "Mozilla", ItemKey: "Mozilla Firefox", Source: "reg64"}, nil); why == nil || why.Code != "ambiguous" {
		t.Fatalf("Firefox and Firefox ESR stay ambiguous, got %+v", why)
	}
}
