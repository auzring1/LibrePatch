package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

func randKey() []byte {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return k
}

// asApp returns the URL of the same database for the least-privilege role.
func asApp(t testing.TB, ownerURL string) string {
	u, err := url.Parse(ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("librepatch_app", pgtest.AppPassword)
	return u.String()
}

func assertNoRows(t testing.TB, dbURL string) {
	t.Helper()
	c := connectT(t, dbURL)
	st, err := inspectTarget(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.rowsIn) != 0 {
		t.Fatalf("database must be empty but tables have rows: %v", st.rowsIn)
	}
}

func assertNoTables(t testing.TB, dbURL string) {
	t.Helper()
	c := connectT(t, dbURL)
	st, err := inspectTarget(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if st.hasGoose || len(st.tables) != 0 {
		t.Fatalf("database must be untouched (no schema), found goose=%v tables=%d", st.hasGoose, len(st.tables))
	}
}

func makeBackup(t *testing.T, src *pgtest.DB, contentDir string, rcp age.Recipient) ([]byte, *Manifest) {
	t.Helper()
	var buf bytes.Buffer
	m, err := Backup(context.Background(), BackupOptions{DatabaseURL: src.OwnerURL, ContentDir: contentDir, Out: &buf,
		Recipients: []age.Recipient{rcp}, Log: discard})
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), m
}

func fillContent(t *testing.T) string {
	dir := t.TempDir()
	writeFile(t, dir, "org-a/"+strings.Repeat("a", 64), "installer one")
	writeFile(t, dir, "org-a/"+strings.Repeat("b", 64), strings.Repeat("big", 100_000))
	writeFile(t, dir, "org-b/"+strings.Repeat("c", 64), "")
	writeFile(t, dir, "org-b/.upload-123", "half uploaded") // temp file of the store: skipped
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "org-b", "link")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func readTree(t *testing.T, dir string) map[string]string {
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		out[rel] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func roundTrip(t *testing.T, extras bool) {
	ctx := context.Background()
	src := pgtest.New(t)
	key := randKey()
	populate(t, src.OwnerURL, key, extras)
	contentSrc := fillContent(t)
	id, rcp := genKey(t)
	archive, m := makeBackup(t, src, contentSrc, rcp)

	if m.Content.Files != 3 {
		t.Fatalf("content files = %d, want 3 (dot-files and symlinks are skipped)", m.Content.Files)
	}
	if extras {
		var haveParent, havePart bool
		for _, tb := range m.Tables {
			haveParent = haveParent || (tb.Name == "ev" && tb.Kind == "partitioned")
			havePart = havePart || strings.HasPrefix(tb.Name, "ev_20")
		}
		if !haveParent || havePart {
			t.Fatalf("partitioned parent must be dumped and its partitions not: %+v", m.Tables)
		}
		for _, tb := range m.Tables {
			if tb.Name == "ev" && strings.Join(tb.Columns, ",") != "id,ts,n,note" {
				t.Fatalf("generated column must not be dumped: %v", tb.Columns)
			}
		}
	}
	if m.RowCounts["audit_log"] != 7 {
		t.Fatalf("audit rows = %d", m.RowCounts["audit_log"])
	}

	dstURL := newEmptyDB(t)
	if extras {
		// The extra tables are not in the migrations, so the target needs them too.
		if err := migrate(ctx, dstURL, 0, discard); err != nil {
			t.Fatal(err)
		}
		mustExec(t, connectT(t, dstURL), extraDDL)
	}
	contentDst := filepath.Join(t.TempDir(), "content")
	res, err := Restore(ctx, RestoreOptions{DatabaseURL: dstURL, ContentDir: contentDst, Source: bytesSource(archive, true),
		Identities: []age.Identity{id}, MasterKey: key, Log: discard})
	if err != nil {
		t.Fatal(err)
	}
	if res.AuditEntries != 7 {
		t.Fatalf("audit entries verified = %d", res.AuditEntries)
	}

	sc, dc := connectT(t, src.OwnerURL), connectT(t, dstURL)
	want := tableDigests(t, sc, m.RowCounts["audit_log"])
	got := tableDigests(t, dc, m.RowCounts["audit_log"])
	if !reflect.DeepEqual(want, got) {
		for k := range want {
			if want[k] != got[k] {
				t.Errorf("table %s differs after restore", k)
			}
		}
		t.FailNow()
	}
	if want["audit_log"] == "empty" || want["devices"] == "empty" {
		t.Fatal("test data missing")
	}
	// The restore itself is recorded after the restored entries, and the whole chain verifies.
	var n int64
	if err := dc.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&n); err != nil || n != 8 {
		t.Fatalf("audit rows after restore = %d, %v", n, err)
	}
	if r, err := audit.Verify(ctx, dbq.New(dc)); err != nil || r.BrokenAt != 0 || r.Checked != 8 {
		t.Fatalf("audit.Verify: %+v %v", r, err)
	}
	var last string
	if err := dc.QueryRow(ctx, `SELECT action FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&last); err != nil || last != "admin.restore" {
		t.Fatalf("last audit action = %q %v", last, err)
	}
	// The source got an admin.backup entry, written after the snapshot.
	if err := sc.QueryRow(ctx, `SELECT action FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&last); err != nil || last != "admin.backup" {
		t.Fatalf("source last audit action = %q %v", last, err)
	}

	// Sequences continue where the source left off.
	for _, s := range m.Sequences {
		if s.Name == "audit_log_id_seq" {
			continue
		}
		var lv int64
		var called bool
		if err := dc.QueryRow(ctx, `SELECT last_value, is_called FROM `+qident("public", s.Name)).Scan(&lv, &called); err != nil {
			t.Fatal(err)
		}
		if lv != s.LastValue || called != s.IsCalled {
			t.Errorf("sequence %s = %d/%v, want %d/%v", s.Name, lv, called, s.LastValue, s.IsCalled)
		}
	}
	var hid int64
	if err := dc.QueryRow(ctx, `INSERT INTO software_history (device_id, title_id, name, scope, change, observed_at)
		SELECT device_id, title_id, 'again', 'machine', 'added', now() FROM software_installs LIMIT 1 RETURNING id`).Scan(&hid); err != nil || hid != 6 {
		t.Fatalf("next software_history id = %d, %v (want 6)", hid, err)
	}
	if extras {
		var evID int64
		if err := dc.QueryRow(ctx, `INSERT INTO ev (ts, n) VALUES ('2026-07-01', 3) RETURNING id`).Scan(&evID); err != nil || evID != 7 {
			t.Fatalf("next ev id = %d, %v (want 7)", evID, err)
		}
		var enabled string
		if err := dc.QueryRow(ctx, `SELECT tgenabled::text FROM pg_trigger WHERE tgname = 'ev_ref_touch'`).Scan(&enabled); err != nil || enabled != "O" {
			t.Fatalf("user trigger must be enabled again after restore: %q %v", enabled, err)
		}
		var label string
		if err := dc.QueryRow(ctx, `SELECT label FROM ev_ref WHERE label LIKE 'a%'`).Scan(&label); err != nil || label != "ax" {
			t.Fatalf("triggers must not re-run on restored rows: label=%q %v", label, err)
		}
	}
	// The least-privilege role works on the restored database, and audit_log stays append-only.
	app, err := pgx.Connect(ctx, asApp(t, dstURL))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close(ctx) }()
	if err := app.QueryRow(ctx, `SELECT count(*) FROM devices`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("app role: %d %v", n, err)
	}
	if _, err := app.Exec(ctx, `DELETE FROM audit_log`); err == nil {
		t.Fatal("audit_log must stay append-only after restore")
	}

	// Content files came through byte for byte; skipped entries did not.
	gotFiles := readTree(t, contentDst)
	wantFiles := map[string]string{
		filepath.Join("org-a", strings.Repeat("a", 64)): "installer one",
		filepath.Join("org-a", strings.Repeat("b", 64)): strings.Repeat("big", 100_000),
		filepath.Join("org-b", strings.Repeat("c", 64)): "",
	}
	if !reflect.DeepEqual(gotFiles, wantFiles) {
		t.Fatalf("content mismatch: got %d files", len(gotFiles))
	}
	st, err := os.Stat(filepath.Join(contentDst, "org-a", strings.Repeat("a", 64)))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("restored file mode: %v %v", st, err)
	}
	if ents, _ := os.ReadDir(contentDst); len(ents) != 2 {
		t.Fatalf("staging directory left behind: %v", ents)
	}
}

func TestRoundTripFreshSchema(t *testing.T) { roundTrip(t, false) }

func TestRoundTripPartitionedAndGenerated(t *testing.T) { roundTrip(t, true) }

func TestBackupRefusesWithoutRecipient(t *testing.T) {
	var buf bytes.Buffer
	_, err := Backup(context.Background(), BackupOptions{DatabaseURL: "postgres://unused", Out: &buf})
	if !errors.Is(err, ErrNoRecipient) || buf.Len() != 0 {
		t.Fatalf("err=%v written=%d", err, buf.Len())
	}
}

func TestWrongKeyAndTamperedCiphertext(t *testing.T) {
	src := pgtest.New(t)
	populate(t, src.OwnerURL, randKey(), false)
	id, rcp := genKey(t)
	archive, _ := makeBackup(t, src, "", rcp)
	ctx := context.Background()

	if _, err := Verify(ctx, bytesSource(archive, true), []age.Identity{id}); err != nil {
		t.Fatalf("good archive: %v", err)
	}
	other, _ := genKey(t)
	if _, err := Verify(ctx, bytesSource(archive, true), []age.Identity{other}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong key: %v", err)
	}
	// Flip a byte in the payload (after the age header), in the middle and near the end.
	for _, off := range []int{len(archive) / 2, len(archive) - 20, len(archive) - 1} {
		bad := bytes.Clone(archive)
		bad[off] ^= 0x01
		dst := newEmptyDB(t)
		_, err := Restore(ctx, RestoreOptions{DatabaseURL: dst, Source: bytesSource(bad, true), Identities: []age.Identity{id}, Log: discard})
		if err == nil {
			t.Fatalf("tampered byte at %d was accepted", off)
		}
		assertNoTables(t, dst)
	}
	// Truncation, at a chunk boundary and inside one.
	for _, n := range []int{len(archive) - 1, len(archive) - 100, len(archive) / 3, 10} {
		if _, err := Verify(ctx, bytesSource(archive[:n], true), []age.Identity{id}); err == nil {
			t.Fatalf("archive truncated to %d bytes was accepted", n)
		}
	}
	// Garbage appended after the age stream.
	if _, err := Verify(ctx, bytesSource(append(bytes.Clone(archive), 1, 2, 3), true), []age.Identity{id}); err == nil {
		t.Fatal("trailing garbage was accepted")
	}
	if _, err := Verify(ctx, bytesSource([]byte("not an age file at all"), true), []age.Identity{id}); err == nil {
		t.Fatal("plaintext was accepted")
	}
}

func TestTamperedMemberWithValidEncryption(t *testing.T) {
	ctx := context.Background()
	src := pgtest.New(t)
	populate(t, src.OwnerURL, randKey(), false)
	id, rcp := genKey(t)
	archive, _ := makeBackup(t, src, "", rcp)

	// Someone with the public key (or the key itself) rewrites a data chunk but
	// cannot fix the manifest hash without also rewriting the manifest.
	ms := readTar(t, archive, id)
	changed := false
	for i := range ms {
		if strings.HasPrefix(ms[i].name, "db/") && bytes.Contains(ms[i].data, []byte("HOST")) {
			ms[i].data = bytes.Replace(ms[i].data, []byte("HOST"), []byte("EVIL"), 1)
			changed = true
		}
	}
	if !changed {
		t.Fatal("test data not found")
	}
	bad := encryptTar(t, rcp, ms)

	if _, err := Verify(ctx, bytesSource(bad, true), []age.Identity{id}); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("Verify: %v", err)
	}
	// File source: caught by the verification pass, the database is never touched.
	dst := newEmptyDB(t)
	_, err := Restore(ctx, RestoreOptions{DatabaseURL: dst, Source: bytesSource(bad, true), Identities: []age.Identity{id}, Log: discard})
	if err == nil {
		t.Fatal("tampered archive restored")
	}
	assertNoTables(t, dst)
	// Stream source (cannot be read twice): caught before COMMIT, so no rows remain.
	dst2 := newEmptyDB(t)
	_, err = Restore(ctx, RestoreOptions{DatabaseURL: dst2, Source: bytesSource(bad, false), Identities: []age.Identity{id}, Log: discard})
	if err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("stream restore: %v", err)
	}
	assertNoRows(t, dst2)

	// A dropped data member, a reordered one and an extra one are all caught as well.
	for name, mut := range map[string]func([]tarMember) []tarMember{
		"dropped": func(ms []tarMember) []tarMember {
			for i, m := range ms {
				if strings.HasPrefix(m.name, "db/") {
					return append(append([]tarMember{}, ms[:i]...), ms[i+1:]...)
				}
			}
			return ms
		},
		"extra": func(ms []tarMember) []tarMember {
			return append(append([]tarMember{}, ms[:len(ms)-1]...), tarMember{name: "files/x", data: []byte("x")}, ms[len(ms)-1])
		},
		"after-manifest": func(ms []tarMember) []tarMember {
			return append(append([]tarMember{}, ms...), tarMember{name: "files/late", data: []byte("x")})
		},
	} {
		if _, err := Verify(ctx, bytesSource(encryptTar(t, rcp, mut(readTar(t, archive, id))), true), []age.Identity{id}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRefusesNewerSchemaAndUnknownFormat(t *testing.T) {
	ctx := context.Background()
	src := pgtest.New(t)
	populate(t, src.OwnerURL, randKey(), false)
	mustExec(t, connectT(t, src.OwnerURL), `INSERT INTO goose_db_version (version_id, is_applied) VALUES (999, true)`)
	id, rcp := genKey(t)
	archive, m := makeBackup(t, src, "", rcp)
	if m.SchemaVersion != 999 {
		t.Fatalf("schema version = %d", m.SchemaVersion)
	}
	for _, repeatable := range []bool{true, false} {
		dst := newEmptyDB(t)
		_, err := Restore(ctx, RestoreOptions{DatabaseURL: dst, Source: bytesSource(archive, repeatable), Identities: []age.Identity{id}, Log: discard})
		if !errors.Is(err, ErrNewerSchema) || !strings.Contains(err.Error(), "newer librepatch-server") {
			t.Fatalf("newer schema: %v", err)
		}
		assertNoTables(t, dst)
	}

	// Unknown format version in both header and manifest.
	src2 := pgtest.New(t)
	populate(t, src2.OwnerURL, randKey(), false)
	a2, _ := makeBackup(t, src2, "", rcp)
	ms := readTar(t, a2, id)
	for i := range ms {
		if ms[i].name == memberHeader || ms[i].name == memberManifest {
			ms[i].data = bytes.Replace(ms[i].data, []byte(`"format_version":1`), []byte(`"format_version":2,"future_field":true`), 1)
			ms[i].data = bytes.Replace(ms[i].data, []byte(`"format_version": 1`), []byte(`"format_version": 2,"future_field":true`), 1)
		}
	}
	future := encryptTar(t, rcp, ms)
	if _, err := Verify(ctx, bytesSource(future, true), []age.Identity{id}); !errors.Is(err, ErrUnknownFormat) || !strings.Contains(err.Error(), "format version 2") {
		t.Fatalf("unknown format: %v", err)
	}
	dst := newEmptyDB(t)
	if _, err := Restore(ctx, RestoreOptions{DatabaseURL: dst, Source: bytesSource(future, false), Identities: []age.Identity{id}, Log: discard}); !errors.Is(err, ErrUnknownFormat) {
		t.Fatalf("restore unknown format: %v", err)
	}
	assertNoTables(t, dst)
}

func TestRestoreRefusesNonEmptyTarget(t *testing.T) {
	ctx := context.Background()
	src := pgtest.New(t)
	populate(t, src.OwnerURL, randKey(), false)
	id, rcp := genKey(t)
	archive, m := makeBackup(t, src, "", rcp)
	opts := func(url string) RestoreOptions {
		return RestoreOptions{DatabaseURL: url, Source: bytesSource(archive, true), Identities: []age.Identity{id}, Log: discard}
	}

	// A target that already holds data (here: its own first user).
	dst := pgtest.New(t)
	mustExec(t, connectT(t, dst.OwnerURL), `INSERT INTO organizations (id, name) VALUES (gen_random_uuid(), 'existing')`)
	for name, o := range map[string]RestoreOptions{"plain": opts(dst.OwnerURL), "force only": func() RestoreOptions { o := opts(dst.OwnerURL); o.Force = true; return o }(),
		"wipe only": func() RestoreOptions { o := opts(dst.OwnerURL); o.Wipe = true; return o }()} {
		if _, err := Restore(ctx, o); !errors.Is(err, ErrTargetNotEmpty) || !strings.Contains(err.Error(), "--force and --wipe") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	var n int
	if err := connectT(t, dst.OwnerURL).QueryRow(ctx, `SELECT count(*) FROM organizations WHERE name='existing'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("existing data must be untouched: %d %v", n, err)
	}
	// With --force --wipe the old contents are replaced by the backup.
	o := opts(dst.OwnerURL)
	o.Force, o.Wipe = true, true
	res, err := Restore(ctx, o)
	if err != nil || !res.Wiped {
		t.Fatalf("wipe restore: %+v %v", res, err)
	}
	if err := connectT(t, dst.OwnerURL).QueryRow(ctx, `SELECT count(*) FROM organizations WHERE name='existing'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("old data must be gone: %d %v", n, err)
	}
	want := tableDigests(t, connectT(t, src.OwnerURL), m.RowCounts["audit_log"])
	got := tableDigests(t, connectT(t, dst.OwnerURL), m.RowCounts["audit_log"])
	if !reflect.DeepEqual(want, got) {
		t.Fatal("restored data differs after --wipe")
	}
	// Restoring again into the now populated database is refused.
	if _, err := Restore(ctx, opts(dst.OwnerURL)); !errors.Is(err, ErrTargetNotEmpty) {
		t.Fatalf("second restore: %v", err)
	}

	// An empty database whose schema is already newer than the backup needs --wipe.
	srcOld := newEmptyDB(t)
	if err := migrate(ctx, srcOld, 3, discard); err != nil {
		t.Fatal(err)
	}
	oldArchive := backupOf(t, srcOld, rcpOf(id))
	emptyNewer := pgtest.New(t) // migrated to the latest version, no rows
	oo := RestoreOptions{DatabaseURL: emptyNewer.OwnerURL, Source: bytesSource(oldArchive, true), Identities: []age.Identity{id}, Log: discard}
	if _, err := Restore(ctx, oo); !errors.Is(err, ErrTargetNotEmpty) || !strings.Contains(err.Error(), "--wipe") {
		t.Fatalf("empty newer schema: %v", err)
	}
	oo.Wipe = true
	res, err = Restore(ctx, oo)
	if latest, _, _ := migrationVersions(); err != nil || !res.Wiped || res.SchemaVersion != latest {
		t.Fatalf("wipe of empty newer schema: %+v %v", res, err)
	}
}

func rcpOf(id *age.X25519Identity) age.Recipient { return id.Recipient() }

func backupOf(t *testing.T, ownerURL string, rcp age.Recipient) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := Backup(context.Background(), BackupOptions{DatabaseURL: ownerURL, Out: &buf, Recipients: []age.Recipient{rcp}, Log: discard}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A backup from an older release restores into a newer binary: the schema is
// built up to the backup's version, the data loaded, then migrated forward.
func TestOlderBackupRestoresIntoNewerBinary(t *testing.T) {
	ctx := context.Background()
	oldURL := newEmptyDB(t)
	if err := migrate(ctx, oldURL, 3, discard); err != nil {
		t.Fatal(err)
	}
	c := connectT(t, oldURL)
	mustExec(t, c, `INSERT INTO organizations (id, name) VALUES (gen_random_uuid(), 'old install')`)
	for i := 0; i < 3; i++ {
		if err := audit.Log(ctx, c, audit.Entry{ActorType: audit.ActorSystem, Action: "old.action", Outcome: audit.Success}); err != nil {
			t.Fatal(err)
		}
	}
	id, rcp := genKey(t)
	archive := backupOf(t, oldURL, rcp)
	m, err := Verify(ctx, bytesSource(archive, true), []age.Identity{id})
	if err != nil || m.SchemaVersion != 3 {
		t.Fatalf("manifest: %+v %v", m, err)
	}

	dst := newEmptyDB(t)
	latest, _, _ := migrationVersions()
	res, err := Restore(ctx, RestoreOptions{DatabaseURL: dst, Source: bytesSource(archive, true), Identities: []age.Identity{id}, Log: discard})
	if err != nil {
		t.Fatal(err)
	}
	if res.SchemaVersion != latest || res.AuditEntries != 3 {
		t.Fatalf("result: %+v", res)
	}
	dc := connectT(t, dst)
	_, v, err := schemaVersion(ctx, dc)
	if err != nil || v != latest {
		t.Fatalf("schema after restore = %d, %v", v, err)
	}
	var name string
	if err := dc.QueryRow(ctx, `SELECT name FROM organizations`).Scan(&name); err != nil || name != "old install" {
		t.Fatalf("data: %q %v", name, err)
	}
	// Tables added by later migrations exist and are empty.
	var cnt int
	if err := dc.QueryRow(ctx, `SELECT count(*) FROM wu_rings`).Scan(&cnt); err != nil || cnt != 0 {
		t.Fatalf("wu_rings: %d %v", cnt, err)
	}
}

func TestCorruptAuditChainIsReported(t *testing.T) {
	ctx := context.Background()
	src := pgtest.New(t)
	populate(t, src.OwnerURL, randKey(), false)
	c := connectT(t, src.OwnerURL)
	mustExec(t, c, `ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete`)
	mustExec(t, c, `UPDATE audit_log SET action = 'tampered' WHERE id = 3`)
	id, rcp := genKey(t)
	archive, _ := makeBackup(t, src, "", rcp)
	dst := newEmptyDB(t)
	res, err := Restore(ctx, RestoreOptions{DatabaseURL: dst, Source: bytesSource(archive, true), Identities: []age.Identity{id}, Log: discard})
	if !errors.Is(err, ErrAuditChainBroken) || !strings.Contains(err.Error(), "entry 3") {
		t.Fatalf("err = %v", err)
	}
	if res == nil || res.AuditEntries != 2 {
		t.Fatalf("res = %+v", res)
	}
}

func TestWrongMasterKeyFailsRestoreAtomically(t *testing.T) {
	ctx := context.Background()
	src := pgtest.New(t)
	populate(t, src.OwnerURL, randKey(), false)
	id, rcp := genKey(t)
	archive, _ := makeBackup(t, src, "", rcp)
	dst := newEmptyDB(t)
	_, err := Restore(ctx, RestoreOptions{DatabaseURL: dst, Source: bytesSource(archive, true), Identities: []age.Identity{id}, MasterKey: randKey(), Log: discard})
	if err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("wrong KEK: %v", err)
	}
	assertNoRows(t, dst)
	// The operator can still override.
	if _, err := Restore(ctx, RestoreOptions{DatabaseURL: dst, Source: bytesSource(archive, true), Identities: []age.Identity{id}, MasterKey: randKey(), SkipKEKCheck: true, Log: discard}); err != nil {
		t.Fatal(err)
	}
}

func TestFKCycleIsReportedAndRealSchemaOrders(t *testing.T) {
	ctx := context.Background()
	d := pgtest.New(t)
	c := connectT(t, d.OwnerURL)
	tables, err := discoverTables(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	ordered, err := orderTables(ctx, c, tables)
	if err != nil {
		t.Fatalf("the real schema must be orderable (a migration added an FK cycle?): %v", err)
	}
	pos := map[string]int{}
	for i, tb := range ordered {
		pos[tb.name] = i
	}
	if len(ordered) != len(tables) || pos["organizations"] > pos["users"] || pos["users"] > pos["devices"] || pos["devices"] > pos["jobs"] {
		t.Fatalf("bad order: %v", sortedNames(ordered))
	}
	mustExec(t, c, `CREATE TABLE cyc_a (id int PRIMARY KEY, b int); CREATE TABLE cyc_b (id int PRIMARY KEY, a int REFERENCES cyc_a(id));
		ALTER TABLE cyc_a ADD FOREIGN KEY (b) REFERENCES cyc_b(id)`)
	tables, _ = discoverTables(ctx, c)
	if _, err := orderTables(ctx, c, tables); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle not reported: %v", err)
	}
}

func TestBackupIsConsistentSnapshot(t *testing.T) {
	// Rows committed by concurrent writers after the snapshot started must not
	// leak into the archive; the row counts in the manifest always match the data.
	ctx := context.Background()
	src := pgtest.New(t)
	populate(t, src.OwnerURL, randKey(), false)
	id, rcp := genKey(t)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := pgx.Connect(ctx, src.OwnerURL)
		if err != nil {
			return
		}
		defer func() { _ = c.Close(ctx) }()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = c.Exec(ctx, `INSERT INTO organizations (id, name) VALUES (gen_random_uuid(), 'w')`)
		}
	}()
	archive, m := makeBackup(t, src, "", rcp)
	close(stop)
	<-done
	v, err := Verify(ctx, bytesSource(archive, true), []age.Identity{id})
	if err != nil {
		t.Fatal(err)
	}
	if v.RowCounts["organizations"] != m.RowCounts["organizations"] || v.RowCounts["organizations"] < 1 {
		t.Fatalf("counts: %d vs %d", v.RowCounts["organizations"], m.RowCounts["organizations"])
	}
}
