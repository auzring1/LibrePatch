package vulns

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/internal/shared/vercmp"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

type fleet struct {
	t    *testing.T
	pool *pgxpool.Pool
	org  uuid.UUID
	site uuid.UUID
	st   *Store
}

func newFleet(t *testing.T) *fleet {
	db := pgtest.New(t)
	f := &fleet{t: t, pool: db.Pool, org: uuid.New(), site: uuid.New(), st: &Store{Pool: db.Pool}}
	f.exec("INSERT INTO organizations (id, name) VALUES ($1, 'Contoso Health')", f.org)
	f.exec("INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 's')", f.site, f.org)
	return f
}

func (f *fleet) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

// device adds an active device running a Windows build ("26100.1000").
func (f *fleet) device(host, caption, build string, status string) uuid.UUID {
	id := uuid.New()
	num := strings.SplitN(build, ".", 2)[0]
	f.exec(`INSERT INTO devices (id, org_id, site_id, status, hostname, arch, os_caption, os_build, hardware) VALUES ($1,$2,$3,$4,$5,'amd64',$6,$7,$8::jsonb)`,
		id, f.org, f.site, status, host, caption, build, `{"os_build":`+num+`}`)
	return id
}

func (f *fleet) install(dev uuid.UUID, name, version string) {
	var title uuid.UUID
	err := f.pool.QueryRow(context.Background(), `INSERT INTO software_titles (id, org_id, normalized_name, normalized_publisher, display_name, display_publisher)
		VALUES ($1,$2,$3,'p',$4,'P') ON CONFLICT (org_id, normalized_name, normalized_publisher) DO UPDATE SET display_name = EXCLUDED.display_name RETURNING id`,
		uuid.New(), f.org, strings.ToLower(name), name).Scan(&title)
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(`INSERT INTO software_installs (device_id, source, scope, user_sid, item_key, title_id, name, version, version_key, first_seen_at, last_seen_at)
		VALUES ($1,'reg64','machine','',$2,$3,$4,$5,$6,now(),now())`, dev, name+version, title, name, version, vercmp.Key(version))
}

func (f *fleet) load() {
	f.t.Helper()
	ctx := context.Background()
	if err := f.st.EnsureBuiltinProducts(ctx, f.org); err != nil {
		f.t.Fatal(err)
	}
	p, err := ParseNVD(fixture(f.t, "nvd_page.json"), nil)
	if err != nil {
		f.t.Fatal(err)
	}
	var scope [][2]string
	for _, c := range p.CVEs {
		for _, r := range c.Ranges {
			scope = append(scope, [2]string{r.Vendor, r.Product})
		}
	}
	if err := f.st.UpsertCVEs(ctx, p.CVEs, scope); err != nil {
		f.t.Fatal(err)
	}
	k, err := ParseKEV(fixture(f.t, "kev.json"))
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.st.ApplyKEV(ctx, k); err != nil {
		f.t.Fatal(err)
	}
}

func ids(items []Item) string {
	var s []string
	for _, i := range items {
		s = append(s, i.ID)
	}
	return strings.Join(s, ",")
}

func TestMatchingFindsWhatTheFleetHas(t *testing.T) {
	f := newFleet(t)
	ctx := context.Background()
	unpatched := f.device("PC-OLD", "Windows 11 Pro", "26100.1000", "active")
	patched := f.device("PC-NEW", "Windows 11 Pro", "26100.3000", "active")
	server := f.device("SRV-1", "Windows Server 2025 Standard", "26100.1000", "active")
	win10 := f.device("PC-10", "Windows 10 Pro", "19045.1000", "active")
	f.device("PC-GONE", "Windows 10 Pro", "19045.1000", "revoked")
	f.install(unpatched, "Google Chrome", "129.0.6668.1")
	f.install(patched, "Google Chrome", "131.0.1")
	f.install(win10, "Notepad++", "8.1.1")
	f.load()

	items, sum, err := f.st.Overview(ctx, f.org, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	// Exploited first (the higher score before the lower), then the rest.
	if ids(items) != "CVE-2026-0001,CVE-2026-0002,CVE-2026-0003" {
		t.Fatalf("order and content: %s", ids(items))
	}
	byID := map[string]Item{}
	for _, it := range items {
		byID[it.ID] = it
	}
	if c := byID["CVE-2026-0001"]; c.Devices != 1 || !c.Exploited || c.Severity != "high" || c.CVSS == nil || *c.CVSS != 8.8 || len(c.FixedIn) != 1 || c.FixedIn[0] != "Google Chrome 130.0.6723.58" || c.ExploitedName == "" || c.KEVDue == nil {
		t.Fatalf("chrome cve: %+v", c)
	}
	if w := byID["CVE-2026-0002"]; w.Devices != 2 || !w.Ransomware || len(w.Products) != 2 {
		t.Fatalf("windows cve affects the old Windows 11 and the Windows 10 PC, not the patched one, the server or the revoked device: %+v", w)
	}
	if n := byID["CVE-2026-0003"]; n.Devices != 1 || n.Exploited || n.Severity != "medium" {
		t.Fatalf("notepad++: %+v", n)
	}
	if sum.CVEs != 3 || sum.Exploited != 2 || sum.High != 2 || sum.Critical != 0 || sum.Devices != 2 || sum.Active != 4 || sum.Covered != 4 {
		t.Fatalf("summary: %+v", sum)
	}
	_ = server

	// Who has CVE-2026-0002, and what to do about it.
	hits, err := f.st.DevicesFor(ctx, f.org, "CVE-2026-0002", false)
	if err != nil || len(hits) != 2 {
		t.Fatalf("devices: %+v %v", hits, err)
	}
	if hits[0].Hostname != "PC-10" || hits[1].Hostname != "PC-OLD" || hits[1].FixedIn != "10.0.26100.2033" || hits[1].Product != "Windows 11 24H2" {
		t.Fatalf("device hits: %+v", hits)
	}

	// What one device has.
	own, err := f.st.ForDevice(ctx, f.org, unpatched, false)
	if err != nil || len(own) != 2 || own[0].ID != "CVE-2026-0001" || own[0].Product != "Google Chrome" || own[0].Installed != "129.0.6668.1" || own[1].Product != "Windows 11 24H2" {
		t.Fatalf("device items: %+v %v", own, err)
	}
	if none, _ := f.st.ForDevice(ctx, f.org, patched, false); len(none) != 0 {
		t.Fatalf("a patched device has nothing: %+v", none)
	}
	if none, _ := f.st.ForDevice(ctx, f.org, server, false); len(none) != 0 {
		t.Fatalf("Windows Server 2025 shares a build number with Windows 11 24H2 and must not get its CVEs: %+v", none)
	}

	// Filters.
	if got, _, _ := f.st.Overview(ctx, f.org, Filter{Exploited: true}); ids(got) != "CVE-2026-0001,CVE-2026-0002" {
		t.Fatalf("exploited only: %s", ids(got))
	}
	if got, _, _ := f.st.Overview(ctx, f.org, Filter{Severity: []string{"medium"}}); ids(got) != "CVE-2026-0003" {
		t.Fatalf("severity: %s", ids(got))
	}
	if got, _, _ := f.st.Overview(ctx, f.org, Filter{Query: "NOTEPAD"}); ids(got) != "CVE-2026-0003" {
		t.Fatalf("search by product: %s", ids(got))
	}
	if got, _, _ := f.st.Overview(ctx, f.org, Filter{Query: "v8"}); ids(got) != "CVE-2026-0001" {
		t.Fatalf("search by text: %s", ids(got))
	}
	// Another organization sees nothing of this fleet.
	if got, s2, _ := f.st.Overview(ctx, uuid.New(), Filter{}); len(got) != 0 || s2.Devices != 0 {
		t.Fatalf("another organization: %+v %+v", got, s2)
	}
}

func TestAProgramTheMappingDoesNotKnowIsNotLookedUp(t *testing.T) {
	f := newFleet(t)
	d := f.device("PC", "Windows 11 Pro", "26100.3000", "active")
	f.install(d, "Obscure Tool", "1.0")
	f.load()
	items, sum, err := f.st.Overview(context.Background(), f.org, Filter{})
	if err != nil || len(items) != 0 || sum.Covered != 1 {
		t.Fatalf("%+v %+v %v", items, sum, err)
	}
	// Mapped by the administrator, a CVE for it then shows up.
	if _, err := f.st.AddProduct(context.Background(), f.org, "Obscure Tool (x64)", "UnknownVendor", "UnknownProduct"); err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO cves (id, severity, cvss) VALUES ('CVE-2026-0099','critical',9.8)`)
	f.exec(`INSERT INTO cve_ranges (cve_id, vendor, product, end_key, end_text) VALUES ('CVE-2026-0099','unknownvendor','unknownproduct',$1,'2.0')`, vercmp.Key("2.0"))
	items, sum, err = f.st.Overview(context.Background(), f.org, Filter{})
	if err != nil || ids(items) != "CVE-2026-0099" || sum.Critical != 1 {
		t.Fatalf("after mapping: %+v %+v %v", items, sum, err)
	}
	// Switched off, it is not looked up again.
	list, _ := f.st.ListProducts(context.Background(), f.org)
	for _, p := range list {
		if p.Vendor == "unknownvendor" {
			if p.Devices != 1 || p.Source != "user" {
				t.Fatalf("mapping line: %+v", p)
			}
			if err := f.st.SetProductEnabled(context.Background(), f.org, p.ID, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	if items, _, _ = f.st.Overview(context.Background(), f.org, Filter{}); len(items) != 0 {
		t.Fatalf("a switched-off mapping must not match: %+v", items)
	}
}

func TestRangesAreHonoredAtTheirEdges(t *testing.T) {
	f := newFleet(t)
	ctx := context.Background()
	f.exec(`INSERT INTO cves (id) VALUES ('CVE-2026-0100')`)
	// Affects 2.0 up to but not including 3.0, and exactly 4.0 (both ends included).
	f.exec(`INSERT INTO cve_ranges (cve_id, vendor, product, start_key, start_incl, end_key, end_incl, end_text) VALUES ('CVE-2026-0100','acme','tool',$1,true,$2,false,'3.0')`, vercmp.Key("2.0"), vercmp.Key("3.0"))
	f.exec(`INSERT INTO cve_ranges (cve_id, vendor, product, start_key, start_incl, end_key, end_incl, end_text) VALUES ('CVE-2026-0100','acme','tool',$1,true,$1,true,'4.0')`, vercmp.Key("4.0"))
	if _, err := f.st.AddProduct(ctx, f.org, "Acme Tool", "acme", "tool"); err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{"1.9": false, "2.0": true, "2.9.9": true, "3.0": false, "3.5": false, "4.0": true, "4.0.1": false}
	for v, want := range cases {
		d := f.device("PC-"+v, "Windows 11 Pro", "26100.3000", "active")
		f.install(d, "Acme Tool", v)
		got, err := f.st.ForDevice(ctx, f.org, d, false)
		if err != nil || (len(got) == 1) != want {
			t.Errorf("version %s: affected=%v, want %v (%+v %v)", v, len(got) == 1, want, got, err)
		}
	}
}

func TestStoringCVEs(t *testing.T) {
	f := newFleet(t)
	ctx := context.Background()
	f.load()
	n, _ := f.st.Counts(ctx)
	if n.CVEs != 4 || n.Exploited != 2 || n.WithRanges != 3 {
		// 0001, 0002, 0003, 0005 from the NVD page (0004 is rejected) with 0002 also in the catalog; 0001 and 0002 are exploited.
		t.Fatalf("counts: %+v", n)
	}
	// A later sync of one product replaces that product's ranges for the CVE and leaves the others.
	f.exec(`INSERT INTO cve_ranges (cve_id, vendor, product, end_key, end_text) VALUES ('CVE-2026-0002','microsoft','windows_11_23h2',$1,'10.0.22631.1')`, vercmp.Key("10.0.22631.1"))
	cves := []CVE{{ID: "CVE-2026-0002", Summary: "revised", Ranges: []Range{{Vendor: "microsoft", Product: "windows_11_24h2", EndKey: vercmp.Key("10.0.26100.9999"), EndText: "10.0.26100.9999"}}}}
	if err := f.st.UpsertCVEs(ctx, cves, [][2]string{{"microsoft", "windows_11_24h2"}}); err != nil {
		t.Fatal(err)
	}
	var cnt int
	f.pool.QueryRow(ctx, `SELECT count(*) FROM cve_ranges WHERE cve_id = 'CVE-2026-0002'`).Scan(&cnt)
	// Windows 10 22H2 and 11 23H2 (another sync's) are untouched; Windows 11 24H2 (this sync's scope) was replaced by the new range.
	if cnt != 3 {
		t.Fatalf("ranges after a one-product sync: %d", cnt)
	}
	var end string
	f.pool.QueryRow(ctx, `SELECT end_text FROM cve_ranges WHERE cve_id = 'CVE-2026-0002' AND product = 'windows_11_24h2'`).Scan(&end)
	if end != "10.0.26100.9999" {
		t.Fatalf("the in-scope range must be the new one: %q", end)
	}
	var sum string
	var kev bool
	f.pool.QueryRow(ctx, `SELECT summary, kev FROM cves WHERE id = 'CVE-2026-0002'`).Scan(&sum, &kev)
	if sum != "revised" || !kev {
		t.Fatalf("the summary changes and the exploited mark stays: %q %v", sum, kev)
	}
	// A rejected CVE is removed.
	if err := f.st.UpsertCVEs(ctx, []CVE{{ID: "CVE-2026-0003", Rejected: true}}, nil); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.st.Counts(ctx); n.CVEs != 3 {
		t.Fatalf("a rejected CVE must go: %+v", n)
	}
	// The catalog replaces the exploited marks: a CVE that is no longer in it loses its mark, an empty one is refused.
	if err := f.st.ApplyKEV(ctx, []KEVEntry{{CVE: "CVE-2026-0001", Name: "only one"}}); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.st.Counts(ctx); n.Exploited != 1 {
		t.Fatalf("exploited after a smaller catalog: %+v", n)
	}
	if err := f.st.ApplyKEV(ctx, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an empty catalog: %v", err)
	}
}

func TestProductMapping(t *testing.T) {
	f := newFleet(t)
	ctx := context.Background()
	if err := f.st.EnsureBuiltinProducts(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if err := f.st.EnsureBuiltinProducts(ctx, f.org); err != nil { // idempotent
		t.Fatal(err)
	}
	list, _ := f.st.ListProducts(ctx, f.org)
	if len(list) < 8 || list[0].Source != "builtin" {
		t.Fatalf("built-in lines: %+v", list)
	}
	var chrome Product
	for _, p := range list {
		if p.Name == "google chrome" {
			chrome = p
		}
	}
	if chrome.Vendor != "google" || chrome.Product != "chrome" || !chrome.Enabled {
		t.Fatalf("chrome: %+v", chrome)
	}
	// A switched-off built-in line stays off after the next start.
	if err := f.st.SetProductEnabled(ctx, f.org, chrome.ID, false); err != nil {
		t.Fatal(err)
	}
	_ = f.st.EnsureBuiltinProducts(ctx, f.org)
	list, _ = f.st.ListProducts(ctx, f.org)
	for _, p := range list {
		if p.ID == chrome.ID && p.Enabled {
			t.Fatal("a line an administrator switched off came back")
		}
	}
	// Built-in lines cannot be deleted; a user's line can; the same line twice is refused; bad words are refused.
	if err := f.st.DeleteProduct(ctx, f.org, chrome.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting a built-in line: %v", err)
	}
	if _, err := f.st.AddProduct(ctx, f.org, "Google Chrome (x64)", "Google", "Chrome"); !errors.Is(err, ErrConflict) {
		t.Fatalf("the same mapping again (the name is normalized): %v", err)
	}
	for _, bad := range [][3]string{{"", "a", "b"}, {"X", "a b", "b"}, {"X", "a", "b:c"}, {"X", "a*", "b"}, {"X", "", "b"}} {
		if _, err := f.st.AddProduct(ctx, f.org, bad[0], bad[1], bad[2]); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
	p, err := f.st.AddProduct(ctx, f.org, "My Tool", "me", "tool")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.DeleteProduct(ctx, uuid.New(), p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another organization's line: %v", err)
	}
	if err := f.st.DeleteProduct(ctx, f.org, p.ID); err != nil {
		t.Fatal(err)
	}
}

func TestFleetPairsAreWhatTheFleetHas(t *testing.T) {
	f := newFleet(t)
	ctx := context.Background()
	a := f.device("A", "Windows 11 Pro", "26100.3000", "active")
	f.device("S", "Windows Server 2022 Standard", "20348.1", "active")
	f.device("U", "Windows 7", "7601.1", "active") // not a tracked build
	f.install(a, "Google Chrome", "131.0")
	_ = f.st.EnsureBuiltinProducts(ctx, f.org)
	pairs, err := f.st.FleetPairs(ctx, f.org)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range pairs {
		got = append(got, p.Part+":"+p.Vendor+":"+p.Product)
	}
	want := map[string]bool{"a:google:chrome": true, "o:microsoft:windows_11_24h2": true, "o:microsoft:windows_server_2022": true}
	if len(got) != len(want) {
		t.Fatalf("pairs: %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Fatalf("unexpected %s in %v", g, got)
		}
	}
}

// A range with no start and no end ("every version") is the NVD not knowing which versions are meant: decades-old Firefox entries
// and recent Microsoft ones then list a fully patched PC. Such a CVE is left out unless it is on the CISA list or the person asks
// for it, and the number left out is reported (D147).
func TestRangesThatNameNoVersionsAreLeftOutUnlessAskedFor(t *testing.T) {
	f := newFleet(t)
	ctx := context.Background()
	f.exec(`INSERT INTO cves (id, published, summary) VALUES ('CVE-2007-1111', now() - interval '19 years', 'old, no versions named')`)
	f.exec(`INSERT INTO cves (id, published, summary) VALUES ('CVE-2026-2222', now() - interval '3 months', 'recent, no versions named')`)
	f.exec(`INSERT INTO cves (id, published, kev, summary) VALUES ('CVE-2010-3333', now() - interval '16 years', true, 'old but known to be exploited')`)
	f.exec(`INSERT INTO cves (id, published, summary) VALUES ('CVE-2008-4444', now() - interval '18 years', 'old with a real range')`)
	for _, id := range []string{"CVE-2007-1111", "CVE-2026-2222", "CVE-2010-3333"} {
		f.exec(`INSERT INTO cve_ranges (cve_id, vendor, product) VALUES ($1,'acme','tool')`, id)
	}
	f.exec(`INSERT INTO cve_ranges (cve_id, vendor, product, end_key, end_text) VALUES ('CVE-2008-4444','acme','tool',$1,'200.0')`, vercmp.Key("200.0"))
	if _, err := f.st.AddProduct(ctx, f.org, "Acme Tool", "acme", "tool"); err != nil {
		t.Fatal(err)
	}
	d := f.device("PC", "Windows 11 Pro", "26100.3000", "active")
	f.install(d, "Acme Tool", "150.0")

	items, sum, err := f.st.Overview(ctx, f.org, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Item{}
	for _, i := range items {
		got[i.ID] = i
	}
	if len(got) != 2 || got["CVE-2010-3333"].ID == "" || got["CVE-2008-4444"].ID == "" {
		t.Fatalf("only the exploited one and the one with a real range: %v", ids(items))
	}
	if sum.NoVersions != 2 || sum.CVEs != 2 {
		t.Fatalf("two were left out, and the summary says so: %+v", sum)
	}
	if got["CVE-2008-4444"].NoVersions || !got["CVE-2010-3333"].NoVersions {
		t.Fatalf("an exploited entry without versions is marked as such: %+v %+v", got["CVE-2008-4444"], got["CVE-2010-3333"])
	}
	if hits, err := f.st.DevicesFor(ctx, f.org, "CVE-2026-2222", false); err != nil || len(hits) != 0 {
		t.Fatalf("the device list agrees: %v %+v", err, hits)
	}
	if mine, err := f.st.ForDevice(ctx, f.org, d, false); err != nil || len(mine) != 2 {
		t.Fatalf("so does the device page: %v %d", err, len(mine))
	}

	all, sum, err := f.st.Overview(ctx, f.org, Filter{IncludeNoVersions: true})
	if err != nil || len(all) != 4 || sum.NoVersions != 0 {
		t.Fatalf("asked for: %v %+v %v", ids(all), sum, err)
	}
	if hits, err := f.st.DevicesFor(ctx, f.org, "CVE-2026-2222", true); err != nil || len(hits) != 1 {
		t.Fatalf("and the device list can show them: %v %+v", err, hits)
	}
	if mine, err := f.st.ForDevice(ctx, f.org, d, true); err != nil || len(mine) != 4 {
		t.Fatalf("and the device page: %v %d", err, len(mine))
	}
}
