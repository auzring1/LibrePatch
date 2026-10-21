package catalog

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/shared/overlay"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

func overlayKey(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pub), priv
}

func overlayDoc(version int, packages string) string {
	return `{"format":"librepatch-overlay/1","name":"Clinic IT overlay","version":` + itoa(version) + `,"issued_at":"2026-10-19T12:00:00Z","packages":[` + packages + `]}`
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

const sevenZip = `{"identifier":"7zip.7zip","self_updating":false,"verified":true,"verified_note":"Tested on the Windows 11 image","silent_args":["/S"]},{"identifier":"Google.Chrome","self_updating":true,"note":"Updates itself."}`

func signed(t *testing.T, priv ed25519.PrivateKey, doc string) []byte {
	t.Helper()
	b, err := overlay.Sign(priv, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(b)
	return raw
}

func importSevenZip(t *testing.T, s *Service, org, user uuid.UUID) uuid.UUID {
	t.Helper()
	s.Source = &fakeSource{files: map[string][][]byte{"7zip.7zip@24.09": fixture(t, "7zip.version.yaml", "7zip.installer.yaml", "7zip.locale.yaml")}, vers: []string{"24.09"}}
	res, err := s.Import(context.Background(), org, user, "7zip.7zip", "")
	if err != nil {
		t.Fatal(err)
	}
	return res.PackageID
}

func TestASignedOverlayVerifiesAndAppliesToTheCatalog(t *testing.T) {
	db := pgtest.New(t)
	org, user := newOrg(t, db.Pool)
	other, _ := newOrg(t, db.Pool)
	s := &Service{Pool: db.Pool, Overlay: LoadOverlay()}
	ctx := context.Background()
	pkg := importSevenZip(t, s, org, user)
	q := dbq.New(db.Pool)
	if p, _ := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: pkg, OrgID: org}); p.Verified || p.VerifiedByOverlay != "" {
		t.Fatalf("not verified before the overlay: %+v", p)
	}

	pub, priv := overlayKey(t)
	// A file signed with another key, and one that is not an overlay at all, are refused and leave nothing behind.
	otherPub, _ := overlayKey(t)
	if _, err := s.AddOverlay(ctx, org, user, "", otherPub, "", signed(t, priv, overlayDoc(1, sevenZip))); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("a wrong key: %v", err)
	}
	if _, err := s.AddOverlay(ctx, org, user, "", pub, "", []byte(`{"hello":1}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("not an overlay: %v", err)
	}
	if list, _ := s.ListOverlays(ctx, org); len(list) != 0 {
		t.Fatalf("a refused file left a source: %+v", list)
	}

	src, err := s.AddOverlay(ctx, org, user, "", pub, "", signed(t, priv, overlayDoc(1, sevenZip)))
	if err != nil {
		t.Fatal(err)
	}
	if src.Label != "Clinic IT overlay" || src.Entries != 2 || src.Verified != 1 || src.DocVersion != 1 || src.Status != "ok" || src.KeyID == "" {
		t.Fatalf("source: %+v", src)
	}
	p, _ := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: pkg, OrgID: org})
	if !p.Verified || p.VerifiedByOverlay != "Clinic IT overlay" || p.VerifiedByOrg {
		t.Fatalf("the overlay vouches for the package: %+v", p)
	}
	e, ok := s.overlay().EntryFor(org, "7ZIP.7zip")
	if !ok || e.Source != "Clinic IT overlay" || len(e.SilentArgs) != 1 || e.SilentArgs[0] != "/S" || e.VerifiedNote == "" {
		t.Fatalf("entry: %+v ok=%v", e, ok)
	}
	// The overlay is this organization's: another one sees nothing of it.
	if e, _ := s.overlay().EntryFor(other, "7zip.7zip"); e.Source != "" {
		t.Fatalf("an overlay leaked to another organization: %+v", e)
	}
	// What the built-in overlay knew is still there for what the signed one does not say.
	if c, ok := s.overlay().EntryFor(org, "Google.Chrome"); !ok || !c.SelfUpdating || c.Source != "Clinic IT overlay" {
		t.Fatalf("chrome: %+v", c)
	}

	// An administrator's own mark and removing it: the overlay keeps the package verified.
	if _, err := s.SetOrgVerified(ctx, org, user, pkg, true); err != nil {
		t.Fatal(err)
	}
	ch, err := s.SetOrgVerified(ctx, org, user, pkg, false)
	if err != nil || !ch.AfterVerified {
		t.Fatalf("an overlay keeps it verified: %+v %v", ch, err)
	}
	if p, _ := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: pkg, OrgID: org}); !p.Verified {
		t.Fatal("removing the administrator's mark must not drop the overlay's")
	}

	// Switched off, deleted: it stops applying.
	if _, err := s.UpdateOverlay(ctx, org, src.ID, src.Label, false, 100, ""); err != nil {
		t.Fatal(err)
	}
	if p, _ := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: pkg, OrgID: org}); p.Verified || p.VerifiedByOverlay != "" {
		t.Fatalf("a disabled overlay must not vouch: %+v", p)
	}
	if _, err := s.UpdateOverlay(ctx, org, src.ID, src.Label, true, 100, ""); err != nil {
		t.Fatal(err)
	}
	if label, err := s.DeleteOverlay(ctx, org, src.ID); err != nil || label != "Clinic IT overlay" {
		t.Fatalf("delete: %q %v", label, err)
	}
	if p, _ := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: pkg, OrgID: org}); p.Verified || p.VerifiedByOverlay != "" {
		t.Fatalf("a deleted overlay must not vouch: %+v", p)
	}
	if e, _ := s.overlay().EntryFor(org, "7zip.7zip"); e.Source != "" {
		t.Fatalf("the signed entry must be gone: %+v", e)
	}
}

func TestAnOverlayAddedBeforeAnImportStillApplies(t *testing.T) {
	db := pgtest.New(t)
	org, user := newOrg(t, db.Pool)
	s := &Service{Pool: db.Pool, Overlay: LoadOverlay()}
	ctx := context.Background()
	pub, priv := overlayKey(t)
	if _, err := s.AddOverlay(ctx, org, user, "Clinic", pub, "", signed(t, priv, overlayDoc(1, sevenZip))); err != nil {
		t.Fatal(err)
	}
	pkg := importSevenZip(t, s, org, user)
	if p, _ := dbq.New(db.Pool).GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: pkg, OrgID: org}); !p.Verified || p.VerifiedByOverlay != "Clinic" {
		t.Fatalf("an import must pick the overlay up: %+v", p)
	}
}

func TestOverlayPriorityAndRollbackProtection(t *testing.T) {
	db := pgtest.New(t)
	org, user := newOrg(t, db.Pool)
	s := &Service{Pool: db.Pool, Overlay: LoadOverlay()}
	ctx := context.Background()
	pubA, privA := overlayKey(t)
	pubB, privB := overlayKey(t)
	a, err := s.AddOverlay(ctx, org, user, "A", pubA, "", signed(t, privA, overlayDoc(2, `{"identifier":"7zip.7zip","silent_args":["/silent"]}`)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.AddOverlay(ctx, org, user, "B", pubB, "", signed(t, privB, overlayDoc(1, `{"identifier":"7zip.7zip","silent_args":["/quiet"]}`)))
	if err != nil {
		t.Fatal(err)
	}
	// Equal priority: the older source (A) wins; giving B the lower number makes it win.
	if e, _ := s.overlay().EntryFor(org, "7zip.7zip"); e.Source != "A" {
		t.Fatalf("the older source wins a tie: %+v", e)
	}
	if _, err := s.UpdateOverlay(ctx, org, b.ID, "B", true, 10, ""); err != nil {
		t.Fatal(err)
	}
	if e, _ := s.overlay().EntryFor(org, "7zip.7zip"); e.Source != "B" || e.SilentArgs[0] != "/quiet" {
		t.Fatalf("a lower priority number wins: %+v", e)
	}
	if _, err := s.UpdateOverlay(ctx, org, b.ID, "A", true, 10, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("a name already taken: %v", err)
	}
	if _, err := s.UpdateOverlay(ctx, org, b.ID, "B", true, 0, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a priority of 0: %v", err)
	}

	// An older document is refused, a newer one replaces, the same one changes nothing, and another key's file is refused.
	if _, err := s.ReplaceOverlay(ctx, org, a.ID, signed(t, privA, overlayDoc(1, `{"identifier":"7zip.7zip","silent_args":["/norestart"]}`))); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "older") {
		t.Fatalf("a rollback: %v", err)
	}
	if ch, err := s.ReplaceOverlay(ctx, org, a.ID, signed(t, privA, overlayDoc(2, `{"identifier":"7zip.7zip","silent_args":["/silent"]}`))); err != nil || ch.Changed {
		t.Fatalf("the same document: %+v %v", ch, err)
	}
	if ch, err := s.ReplaceOverlay(ctx, org, a.ID, signed(t, privA, overlayDoc(3, `{"identifier":"7zip.7zip","silent_args":["/silent3"]}`))); err != nil || !ch.Changed || ch.DocVersion != 3 {
		t.Fatalf("a newer document: %+v %v", ch, err)
	}
	if _, err := s.ReplaceOverlay(ctx, org, a.ID, signed(t, privB, overlayDoc(9, `{"identifier":"7zip.7zip"}`))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("another key's file: %v", err)
	}
	if _, err := s.ReplaceOverlay(ctx, uuid.New(), a.ID, signed(t, privA, overlayDoc(9, `{"identifier":"7zip.7zip"}`))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another organization's source: %v", err)
	}
}

func TestMergeOverrideLayersTheOverlayUnderTheAdministrator(t *testing.T) {
	e := OverlayEntry{SilentArgs: []string{"/S"}, ExtraDetection: []Detection{{Kind: "registry", Key: `HKLM\SOFTWARE\Acme`}}}
	// No override: the overlay's own.
	got := MergeOverride(nil, e)
	if got == nil || len(got.SilentArgs) != 1 || got.SilentArgs[0] != "/S" || !strings.Contains(string(got.ExtraDetection), "Acme") {
		t.Fatalf("no override: %+v", got)
	}
	// The administrator's silent arguments win; the detection rules of both are used.
	mine, _ := json.Marshal([]Detection{{Kind: "file", Key: `%ProgramFiles%\Acme\a.exe`}})
	own := &dbq.PackageOverride{SilentArgs: []string{"/VERYSILENT"}, ExtraDetection: mine, Pin: "= 1.0"}
	got = MergeOverride(own, e)
	if got.SilentArgs[0] != "/VERYSILENT" || got.Pin != "= 1.0" || !strings.Contains(string(got.ExtraDetection), "Acme") || !strings.Contains(string(got.ExtraDetection), "a.exe") {
		t.Fatalf("with an override: %+v", got)
	}
	if own.SilentArgs[0] != "/VERYSILENT" || strings.Contains(string(own.ExtraDetection), "HKLM") {
		t.Fatal("the administrator's override must not be changed")
	}
	// Program names: the administrator's list wins; the overlay's are used when there is none.
	pe := OverlayEntry{Processes: []string{"acme.exe"}}
	if got := MergeOverride(nil, pe); got == nil || len(got.Processes) != 1 || got.Processes[0] != "acme.exe" {
		t.Fatalf("overlay programs: %+v", got)
	}
	if got := MergeOverride(&dbq.PackageOverride{Processes: []string{"mine.exe"}}, pe); got.Processes[0] != "mine.exe" {
		t.Fatalf("own programs must win: %+v", got.Processes)
	}
	// An entry with nothing to add returns the override as it is, including nil.
	if MergeOverride(nil, OverlayEntry{}) != nil || MergeOverride(own, OverlayEntry{}) != own {
		t.Fatal("an empty entry must change nothing")
	}
}

func TestOverlayFromAURLIsRefreshedAndNeverRolledBack(t *testing.T) {
	db := pgtest.New(t)
	org, user := newOrg(t, db.Pool)
	pub, priv := overlayKey(t)
	var mu sync.Mutex
	body := signed(t, priv, overlayDoc(1, `{"identifier":"7zip.7zip","silent_args":["/S"]}`))
	etag := `"v1"`
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		hits++
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	set := func(doc []byte, tag string) { mu.Lock(); body, etag = doc, tag; mu.Unlock() }

	s := &Service{Pool: db.Pool, Overlay: LoadOverlay(), HTTP: srv.Client()}
	ctx := context.Background()
	src, err := s.AddOverlay(ctx, org, user, "Remote", pub, srv.URL+"/overlay.lpov", nil)
	if err != nil {
		t.Fatal(err)
	}
	if src.Kind != "url" || src.DocVersion != 1 {
		t.Fatalf("source: %+v", src)
	}
	// Nothing new: answered 304, nothing changes.
	if ch, err := s.RefreshOverlay(ctx, org, src.ID); err != nil || ch.Changed {
		t.Fatalf("not modified: %+v %v", ch, err)
	}
	// A newer version arrives.
	set(signed(t, priv, overlayDoc(2, `{"identifier":"7zip.7zip","silent_args":["/S","/D"]}`)), `"v2"`)
	if ch, err := s.RefreshOverlay(ctx, org, src.ID); err != nil || !ch.Changed || ch.DocVersion != 2 {
		t.Fatalf("newer: %+v %v", ch, err)
	}
	if e, _ := s.overlay().EntryFor(org, "7zip.7zip"); len(e.SilentArgs) != 2 {
		t.Fatalf("the new document applies: %+v", e)
	}
	// The address now serves an older document (a rollback, or a stale mirror): refused, the good one stays, the source says so.
	set(signed(t, priv, overlayDoc(1, `{"identifier":"7zip.7zip","silent_args":["/EVIL"]}`)), `"v0"`)
	if _, err := s.RefreshOverlay(ctx, org, src.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a rollback: %v", err)
	}
	if e, _ := s.overlay().EntryFor(org, "7zip.7zip"); len(e.SilentArgs) != 2 || e.SilentArgs[0] != "/S" {
		t.Fatalf("a refused document must not apply: %+v", e)
	}
	list, _ := s.ListOverlays(ctx, org)
	if list[0].Status != "error" || !strings.Contains(list[0].LastError, "older") || list[0].DocVersion != 2 {
		t.Fatalf("the source must say what happened: %+v", list[0])
	}
	// Content signed by somebody else is refused too.
	_, otherPriv := overlayKey(t)
	set(signed(t, otherPriv, overlayDoc(9, `{"identifier":"7zip.7zip","silent_args":["/EVIL"]}`)), `"v9"`)
	if _, err := s.RefreshOverlay(ctx, org, src.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("another key: %v", err)
	}
	// An uploaded source cannot be refreshed; a bad address is refused up front.
	up, _ := s.AddOverlay(ctx, org, user, "Uploaded", pub, "", signed(t, priv, overlayDoc(1, `{"identifier":"A.B"}`)))
	if _, err := s.RefreshOverlay(ctx, org, up.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("refreshing an upload: %v", err)
	}
	for _, bad := range []string{"ftp://example.org/x", "https://user:pw@example.org/x", "not a url"} {
		if _, err := s.AddOverlay(ctx, org, user, "Bad", pub, bad, nil); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestTheDefaultClientRefusesAddressesOnTheServerItself(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("x")) }))
	defer srv.Close()
	s := &Service{}
	if _, _, _, err := s.fetchBundle(context.Background(), srv.URL, ""); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("a loopback address must be refused: %v", err)
	}
}

func TestTemplateStartsFromWhatTheAdministratorAlreadySet(t *testing.T) {
	db := pgtest.New(t)
	org, user := newOrg(t, db.Pool)
	s := &Service{Pool: db.Pool, Overlay: LoadOverlay()}
	ctx := context.Background()
	pkg := importSevenZip(t, s, org, user)
	if err := s.SetOverride(ctx, org, user, pkg, Override{SilentArgs: []string{"/S"}}); err != nil {
		t.Fatal(err)
	}
	doc, err := s.Template(ctx, org, "Contoso Health")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Name != "Contoso Health overlay" || len(doc.Packages) != 1 || doc.Packages[0].Identifier != "7zip.7zip" || doc.Packages[0].SilentArgs[0] != "/S" {
		t.Fatalf("template: %+v", doc)
	}
	// It is ready to sign.
	raw, _ := json.Marshal(doc)
	_, priv := overlayKey(t)
	if _, err := overlay.Sign(priv, raw); err != nil {
		t.Fatalf("the template must be signable: %v", err)
	}
	// And a package with nothing set is left out.
	if _, err := s.SetOrgVerified(ctx, org, user, pkg, true); err != nil {
		t.Fatal(err)
	}
	doc, _ = s.Template(ctx, org, "")
	if doc.Name != "My overlay" || !doc.Packages[0].Verified {
		t.Fatalf("with a mark and no organization name: %+v", doc)
	}
}
