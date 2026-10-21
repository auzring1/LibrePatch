package catalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

type fakeSource struct {
	files map[string][][]byte
	vers  []string
}

func (f *fakeSource) Versions(context.Context, string) ([]string, error) { return f.vers, nil }
func (f *fakeSource) Manifests(_ context.Context, id, v string) ([][]byte, error) {
	if m, ok := f.files[id+"@"+v]; ok {
		return m, nil
	}
	return nil, ErrNotFound
}

func newOrg(t *testing.T, pool *pgxpool.Pool) (org, user uuid.UUID) {
	t.Helper()
	org, user = uuid.New(), uuid.New()
	ctx := context.Background()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO organizations (id, name) VALUES ($1, 'o')", []any{org}},
		{"INSERT INTO users (id, org_id, email, display_name, password_hash) VALUES ($1, $2, $3, 'A', 'x')", []any{user, org, user.String() + "@example.com"}},
	} {
		if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	return
}

func TestImportStoresAndReimportReplaces(t *testing.T) {
	db := pgtest.New(t)
	org, user := newOrg(t, db.Pool)
	src := &fakeSource{files: map[string][][]byte{"7zip.7zip@24.09": fixture(t, "7zip.version.yaml", "7zip.installer.yaml", "7zip.locale.yaml")}, vers: []string{"24.09"}}
	s := &Service{Pool: db.Pool, Source: src}
	ctx := context.Background()
	res, err := s.Import(ctx, org, user, "7zip.7zip", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Version != "24.09" || res.Installers != 6 || res.Deployable != 5 || len(res.Warnings) == 0 {
		t.Fatalf("%+v", res)
	}
	q := dbq.New(db.Pool)
	pkg, err := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: res.PackageID, OrgID: org})
	if err != nil || pkg.Name != "7-Zip" || pkg.Verified || pkg.SelfUpdating {
		t.Fatalf("%+v %v", pkg, err)
	}
	ins, _ := q.ListVersionInstallers(ctx, res.VersionID)
	if len(ins) != 6 {
		t.Fatalf("installers %d", len(ins))
	}
	// importing again replaces rather than duplicates
	if _, err := s.Import(ctx, org, user, "7zip.7zip", "24.09"); err != nil {
		t.Fatal(err)
	}
	ins, _ = q.ListVersionInstallers(ctx, res.VersionID)
	vs, _ := q.ListPackageVersions(ctx, res.PackageID)
	if len(ins) != 6 || len(vs) != 1 {
		t.Fatalf("after re-import: %d installers, %d versions", len(ins), len(vs))
	}
	// selection: an x64 machine gets the x64 MSI (best type) for machine scope
	sel := SelectInstaller(ins, "amd64", "machine")
	if sel == nil || sel.Architecture != "x64" || sel.InstallerType != "msi" {
		t.Fatalf("selected %+v", sel)
	}
	if sel := SelectInstaller(ins, "arm64", "machine"); sel == nil || sel.Architecture != "arm64" {
		t.Fatalf("arm64 selected %+v", sel)
	}
	if SelectInstaller(ins, "amd64", "user") != nil {
		t.Fatal("7-Zip's manifest is machine-scope only: no installer may be chosen for user scope")
	}
	// the manifest must describe what was asked for
	src.files["7zip.7zip@99.0"] = src.files["7zip.7zip@24.09"]
	if _, err := s.Import(ctx, org, user, "7zip.7zip", "99.0"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched manifest accepted: %v", err)
	}
	if _, err := s.Import(ctx, org, user, "not valid", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad identifier: %v", err)
	}
	// tenant isolation
	org2, _ := newOrg(t, db.Pool)
	if _, err := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: res.PackageID, OrgID: org2}); err == nil {
		t.Fatal("package visible to another organization")
	}
}

func TestBuildInstallBodyFromImported(t *testing.T) {
	db := pgtest.New(t)
	org, user := newOrg(t, db.Pool)
	src := &fakeSource{files: map[string][][]byte{"7zip.7zip@24.09": fixture(t, "7zip.version.yaml", "7zip.installer.yaml", "7zip.locale.yaml")}}
	s := &Service{Pool: db.Pool, Source: src}
	ctx := context.Background()
	res, _ := s.Import(ctx, org, user, "7zip.7zip", "24.09")
	q := dbq.New(db.Pool)
	pkg, _ := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: res.PackageID, OrgID: org})
	ver, _ := q.GetCatalogVersion(ctx, dbq.GetCatalogVersionParams{ID: res.VersionID, OrgID: org})
	ins, _ := q.ListVersionInstallers(ctx, res.VersionID)
	var exe *dbq.CatalogInstaller
	for i := range ins {
		if ins[i].Architecture == "x64" && ins[i].InstallerType == "exe" {
			exe = &ins[i]
		}
	}
	body, err := BuildInstallBody(BuildInput{Pkg: pkg, Ver: ver, Inst: *exe, Scope: "machine"})
	if err != nil {
		t.Fatal(err)
	}
	if len(body.Installer.Args) != 1 || body.Installer.Args[0] != "/S" || len(body.Installer.Sha256) != 32 ||
		body.Installer.Sources[0].Url == "" || len(body.Detection) != 1 || body.Installer.Size != 0 {
		t.Fatalf("%+v", body)
	}
	// The manifest's product code of this EXE installer is an uninstall key name ("7-Zip"), which the agent refuses in a
	// job body ("product code is not a GUID"); a GUID product code is still sent.
	if exe.ProductCode == "" || body.Installer.ProductCode != "" {
		t.Fatalf("a non-GUID product code must not be sent to the agent: stored %q, sent %q", exe.ProductCode, body.Installer.ProductCode)
	}
	msi := *exe
	msi.ProductCode = "{23170F69-40C1-2701-2409-000001000000}"
	if b, err := BuildInstallBody(BuildInput{Pkg: pkg, Ver: ver, Inst: msi, Scope: "machine"}); err != nil || b.Installer.ProductCode != msi.ProductCode {
		t.Fatalf("a GUID product code is sent: %v %+v", err, b)
	}
	// an override replaces the switches (validated) and adds a detection rule
	if err := s.SetOverride(ctx, org, user, pkg.ID, Override{SilentArgs: []string{"/S", "/D=C:\\Tools\\7z"},
		ExtraDetection: []Detection{{Kind: "file", Key: `%ProgramFiles%\7-Zip\7z.exe`}}}); err != nil {
		t.Fatal(err)
	}
	ov, _ := q.GetPackageOverride(ctx, dbq.GetPackageOverrideParams{OrgID: org, PackageID: pkg.ID})
	body, _ = BuildInstallBody(BuildInput{Pkg: pkg, Ver: ver, Inst: *exe, Override: &ov, Scope: "machine"})
	if len(body.Installer.Args) != 2 || len(body.Detection) != 2 {
		t.Fatalf("override not applied: %+v", body)
	}
}

func TestOverrideValidation(t *testing.T) {
	db := pgtest.New(t)
	org, user := newOrg(t, db.Pool)
	s := &Service{Pool: db.Pool, Source: &fakeSource{files: map[string][][]byte{"7zip.7zip@24.09": fixture(t, "7zip.version.yaml", "7zip.installer.yaml", "7zip.locale.yaml")}}}
	res, _ := s.Import(context.Background(), org, user, "7zip.7zip", "24.09")
	bad := []Override{
		{SilentArgs: []string{"/S & calc"}},
		{SilentArgs: []string{"/x"}},
		{Pin: "<> 1"},
		{Pin: "= not a version?"},
		{UserScopePolicy: "destroy"},
		{SelfUpdate: "yes"},
		{ExtraDetection: []Detection{{Kind: "file", Key: `%TEMP%\x`}}},
		{ExtraDetection: []Detection{{Kind: "file", Key: `%ProgramFiles%\..\x`}}},
		{ExtraDetection: []Detection{{Kind: "msi", Key: "7-Zip"}}},
		{ExtraDetection: []Detection{{Kind: "registry", Key: "k", Version: "???", Cmp: "ge"}}},
		{Processes: &[]string{`C:\Program Files\x\a.exe`}},
		{Processes: &[]string{"*.exe"}},
		{Processes: &[]string{"svchost.exe"}},
	}
	for i, o := range bad {
		if err := s.SetOverride(context.Background(), org, user, res.PackageID, o); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d accepted: %v", i, err)
		}
	}
	good := Override{Pin: "< 25.0", Excluded: false, UserScopePolicy: "convert_to_machine", SelfUpdate: "enforce"}
	if err := s.SetOverride(context.Background(), org, user, res.PackageID, good); err != nil {
		t.Fatal(err)
	}
	// Program names are stored, and an override saved by a client that does not send them keeps them.
	progs := []string{"7zFM.exe"}
	if err := s.SetOverride(context.Background(), org, user, res.PackageID, Override{Processes: &progs}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetOverride(context.Background(), org, user, res.PackageID, Override{Pin: "< 26.0"}); err != nil {
		t.Fatal(err)
	}
	if ov, err := dbq.New(db.Pool).GetPackageOverride(context.Background(), dbq.GetPackageOverrideParams{OrgID: org, PackageID: res.PackageID}); err != nil || len(ov.Processes) != 1 || ov.Processes[0] != "7zFM.exe" || ov.Pin != "< 26.0" {
		t.Fatalf("programs must survive a save that does not mention them: %v %+v", err, ov)
	}
	empty := []string{}
	if err := s.SetOverride(context.Background(), org, user, res.PackageID, Override{Processes: &empty}); err != nil {
		t.Fatal(err)
	}
	if ov, _ := dbq.New(db.Pool).GetPackageOverride(context.Background(), dbq.GetPackageOverrideParams{OrgID: org, PackageID: res.PackageID}); len(ov.Processes) != 0 {
		t.Fatalf("an empty list clears them: %+v", ov.Processes)
	}
	// another organization cannot override this package
	org2, user2 := newOrg(t, db.Pool)
	if err := s.SetOverride(context.Background(), org2, user2, res.PackageID, good); err == nil {
		t.Fatal("cross-organization override accepted")
	}
}

func TestChooseVersionPins(t *testing.T) {
	vs := []dbq.CatalogVersion{{Version: "1.0"}, {Version: "2.0"}, {Version: "2.5"}, {Version: "10.0"}}
	pick := func(req, pin string) (string, error) {
		v, err := ChooseVersion(vs, req, pin)
		if err != nil {
			return "", err
		}
		return v.Version, nil
	}
	for _, c := range []struct{ req, pin, want string }{
		{"", "", "10.0"}, {"", "latest", "10.0"}, {"", "< 3", "2.5"}, {"", "= 2.0", "2.0"}, {"2.5", "< 3", "2.5"}, {"1.0", "", "1.0"},
	} {
		if got, err := pick(c.req, c.pin); err != nil || got != c.want {
			t.Errorf("%+v: %q %v", c, got, err)
		}
	}
	for _, c := range []struct{ req, pin string }{{"10.0", "< 3"}, {"9.9", ""}, {"", "< 1"}, {"", "= 7"}} {
		if _, err := pick(c.req, c.pin); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v accepted: %v", c, err)
		}
	}
}

func TestCustomUploadAndPackage(t *testing.T) {
	db := pgtest.New(t)
	org, user := newOrg(t, db.Pool)
	cs := &Store{Dir: t.TempDir()}
	s := &Service{Pool: db.Pool, Content: cs}
	ctx := context.Background()
	payload := bytes.Repeat([]byte("MZ"), 1000)
	sha, n, err := cs.Put(org, bytes.NewReader(payload), 1<<20)
	if err != nil || n != int64(len(payload)) {
		t.Fatal(err)
	}
	if err := dbq.New(db.Pool).InsertContentBlob(ctx, dbq.InsertContentBlobParams{OrgID: org, Sha256: sha, Size: n, FileName: "tool.exe", UploadedBy: &user}); err != nil {
		t.Fatal(err)
	}
	spec := CustomSpec{Identifier: "AcmeTool", Name: "Acme Tool", Publisher: "Acme", Version: "1.2.3", SHA256: hex.EncodeToString(sha), FileName: "tool.exe",
		Type: "exe", Arch: "x64", Scope: "machine", Args: []string{"/silent"},
		Detection: []Detection{{Kind: "file", Key: `%ProgramFiles%\Acme\tool.exe`}}}
	res, err := s.AddCustom(ctx, org, user, spec)
	if err != nil || res.Identifier != "Custom.AcmeTool" || len(res.Warnings) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	q := dbq.New(db.Pool)
	ins, _ := q.ListVersionInstallers(ctx, res.VersionID)
	pkg, _ := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: res.PackageID, OrgID: org})
	ver, _ := q.GetCatalogVersion(ctx, dbq.GetCatalogVersionParams{ID: res.VersionID, OrgID: org})
	body, err := BuildInstallBody(BuildInput{Pkg: pkg, Ver: ver, Inst: ins[0], Scope: "machine"})
	if err != nil || body.Installer.Sources[0].Url != "" || body.Installer.Size != uint64(n) || body.Installer.Args[0] != "/silent" {
		t.Fatalf("%+v %v", body, err)
	}
	// unknown hash, other-org hash, bad inputs
	cases := map[string]func(*CustomSpec){
		"unknown hash":  func(c *CustomSpec) { c.SHA256 = strings.Repeat("ab", 32) },
		"bad type":      func(c *CustomSpec) { c.Type = "msix" },
		"exe no args":   func(c *CustomSpec) { c.Args = nil },
		"evil arg":      func(c *CustomSpec) { c.Args = []string{"/S;calc"} },
		"path name":     func(c *CustomSpec) { c.FileName = "../x.exe" },
		"portable user": func(c *CustomSpec) { c.Type, c.Scope, c.Args = "portable", "user", nil },
		"no version":    func(c *CustomSpec) { c.Version = "" },
	}
	for name, mut := range cases {
		c := spec
		mut(&c)
		if _, err := s.AddCustom(ctx, org, user, c); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	org2, user2 := newOrg(t, db.Pool)
	if _, err := s.AddCustom(ctx, org2, user2, spec); !errors.Is(err, ErrInvalid) {
		t.Errorf("another organization's content accepted: %v", err)
	}
}

func TestContentStore(t *testing.T) {
	org := uuid.New()
	cs := &Store{Dir: t.TempDir()}
	sha, n, err := cs.Put(org, strings.NewReader("hello"), 100)
	h := sha256.Sum256([]byte("hello"))
	if err != nil || n != 5 || !bytes.Equal(sha, h[:]) {
		t.Fatalf("%v %v", err, n)
	}
	f, size, err := cs.Open(org, sha)
	if err != nil || size != 5 {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, _, err := cs.Open(uuid.New(), sha); err == nil {
		t.Fatal("content visible to another organization")
	}
	if _, _, err := cs.Put(org, strings.NewReader(strings.Repeat("x", 101)), 100); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("limit: %v", err)
	}
	if _, _, err := cs.Put(org, strings.NewReader(""), 100); err == nil {
		t.Fatal("empty upload accepted")
	}
	if _, _, err := cs.Open(org, []byte("short")); err == nil {
		t.Fatal("bad hash accepted")
	}
}

func TestGitHubSource(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/microsoft/winget-pkgs/contents/manifests/a/Acme/Tool", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"name":"1.0","type":"dir"},{"name":"2.0","type":"dir"},{"name":"10.0","type":"dir"},{"name":"Dev","type":"dir"},{"name":"README.md","type":"file"}]`))
	})
	mux.HandleFunc("/winget/manifests/a/Acme/Tool/2.0/Acme.Tool.yaml", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(fixtureBytes(t, "7zip.version.yaml")) })
	mux.HandleFunc("/winget/manifests/a/Acme/Tool/2.0/Acme.Tool.installer.yaml", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(fixtureBytes(t, "7zip.installer.yaml")) })
	mux.HandleFunc("/winget/manifests/a/Acme/Tool/2.0/Acme.Tool.locale.en-US.yaml", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(fixtureBytes(t, "7zip.locale.yaml")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	g := &GitHubSource{RawBase: srv.URL + "/winget", APIBase: srv.URL + "/repos/microsoft/winget-pkgs"}
	vs, err := g.Versions(context.Background(), "Acme.Tool")
	if err != nil || strings.Join(vs, ",") != "10.0,2.0,1.0" {
		t.Fatalf("%v %v", vs, err)
	}
	files, err := g.Manifests(context.Background(), "Acme.Tool", "2.0")
	if err != nil || len(files) != 3 {
		t.Fatalf("%d %v", len(files), err)
	}
	if _, err := g.Manifests(context.Background(), "Acme.Tool", "3.0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing version: %v", err)
	}
	for _, bad := range []string{"../etc.passwd", "a/b.c", "x"} {
		if _, err := g.Versions(context.Background(), bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := g.Manifests(context.Background(), "Acme.Tool", "../2.0"); err == nil {
		t.Error("traversal in version accepted")
	}
}

func TestAdministratorCanMarkAPackageVerifiedAndTheMarkSurvivesAnImport(t *testing.T) {
	db := pgtest.New(t)
	org, user := newOrg(t, db.Pool)
	src := &fakeSource{files: map[string][][]byte{"7zip.7zip@24.09": fixture(t, "7zip.version.yaml", "7zip.installer.yaml", "7zip.locale.yaml")}, vers: []string{"24.09"}}
	s := &Service{Pool: db.Pool, Source: src}
	ctx := context.Background()
	res, err := s.Import(ctx, org, user, "7zip.7zip", "")
	if err != nil {
		t.Fatal(err)
	}
	q := dbq.New(db.Pool)
	get := func() dbq.CatalogPackage {
		p, err := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: res.PackageID, OrgID: org})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if p := get(); p.Verified || p.VerifiedByOrg {
		t.Fatalf("a fresh import is unverified: %+v", p)
	}

	ch, err := s.SetOrgVerified(ctx, org, user, res.PackageID, true)
	if err != nil || ch.Version != "24.09" || ch.BeforeVerified || !ch.AfterVerified || ch.TestsPassed {
		t.Fatalf("%+v %v", ch, err)
	}
	p := get()
	if !p.Verified || !p.VerifiedByOrg || p.VerifiedBy == nil || *p.VerifiedBy != user || p.VerifiedAt == nil || p.VerifiedVersion != "24.09" {
		t.Fatalf("after marking: %+v", p)
	}

	// Importing again (a newer version, a refresh) must not wipe the administrator's mark.
	if _, err := s.Import(ctx, org, user, "7zip.7zip", ""); err != nil {
		t.Fatal(err)
	}
	if p := get(); !p.Verified || !p.VerifiedByOrg {
		t.Fatalf("the mark was lost by an import: %+v", p)
	}

	// Removing the mark makes the package unverified again.
	ch, err = s.SetOrgVerified(ctx, org, user, res.PackageID, false)
	if err != nil || !ch.BeforeVerified || ch.AfterVerified || !ch.BeforeByOrg {
		t.Fatalf("%+v %v", ch, err)
	}
	if p := get(); p.Verified || p.VerifiedByOrg || p.VerifiedBy != nil || p.VerifiedAt != nil || p.VerifiedVersion != "" {
		t.Fatalf("after removing the mark: %+v", p)
	}

	// A package that passed the VM test matrix stays verified without the mark.
	s.Overlay = &Overlay{byID: map[string]OverlayEntry{}, results: map[string][]MatrixResult{"7zip.7zip": {{Identifier: "7zip.7zip", Scope: "machine", OS: "win11"}}}}
	if ch, err = s.SetOrgVerified(ctx, org, user, res.PackageID, true); err != nil || !ch.TestsPassed {
		t.Fatalf("%+v %v", ch, err)
	}
	if ch, err = s.SetOrgVerified(ctx, org, user, res.PackageID, false); err != nil || !ch.AfterVerified {
		t.Fatalf("tested packages stay verified: %+v %v", ch, err)
	}
	if p := get(); !p.Verified || p.VerifiedByOrg {
		t.Fatalf("%+v", p)
	}
}

func TestVerificationIsForWingetPackagesInTheCallersOrganization(t *testing.T) {
	db := pgtest.New(t)
	org, user := newOrg(t, db.Pool)
	otherOrg, _ := newOrg(t, db.Pool)
	s := &Service{Pool: db.Pool}
	ctx := context.Background()
	pid, err := dbq.New(db.Pool).UpsertCatalogPackage(ctx, dbq.UpsertCatalogPackageParams{ID: uuid.New(), OrgID: org, Source: "custom", Identifier: "Custom.Tool", Name: "Tool", Publisher: "Me"})
	if err != nil {
		t.Fatal(err)
	}
	custom := struct{ PackageID uuid.UUID }{pid}
	if _, verr := s.SetOrgVerified(ctx, org, user, custom.PackageID, true); !errors.Is(verr, ErrInvalid) {
		t.Fatalf("a custom package needs no verification: %v", verr)
	}
	if _, verr := s.SetOrgVerified(ctx, otherOrg, user, custom.PackageID, true); !errors.Is(verr, ErrNotFound) {
		t.Fatalf("another organization's package: %v", verr)
	}
}
