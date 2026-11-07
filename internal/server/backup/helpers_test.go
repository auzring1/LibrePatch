package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/kek"
	"github.com/auzring1/librepatch/internal/server/pki"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

// newEmptyDB creates an empty database (no schema at all) and returns its owner URL.
func newEmptyDB(t testing.TB) string {
	t.Helper()
	base := os.Getenv("LIBREPATCH_TEST_PG_URL")
	if base == "" {
		if os.Getenv("LIBREPATCH_REQUIRE_DB") == "1" {
			t.Fatal("LIBREPATCH_TEST_PG_URL is required")
		}
		t.Skip("LIBREPATCH_TEST_PG_URL not set; skipping database test")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(ctx) }()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "lp_b_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	_, _ = admin.Exec(ctx, `DO $$ BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='librepatch_app') THEN
			CREATE ROLE librepatch_app LOGIN PASSWORD '`+pgtest.AppPassword+`';
		END IF; END $$`)
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), base)
		if err == nil {
			_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			_ = c.Close(context.Background())
		}
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

func connectT(t testing.TB, url string) *pgx.Conn {
	t.Helper()
	c, err := pgx.Connect(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func mustExec(t testing.TB, c *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := c.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// extraDDL adds objects the migrations do not have: a partitioned table with an
// identity column and a generated column, a serial table with an INSERT
// trigger, and a foreign key into the real schema.
const extraDDL = `
CREATE TABLE ev (
    id bigint GENERATED ALWAYS AS IDENTITY,
    ts timestamptz NOT NULL,
    n integer NOT NULL,
    doubled integer GENERATED ALWAYS AS (n * 2) STORED,
    note text NOT NULL DEFAULT '',
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);
CREATE TABLE ev_2026 PARTITION OF ev FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
CREATE TABLE ev_2027 PARTITION OF ev FOR VALUES FROM ('2027-01-01') TO ('2028-01-01');
CREATE TABLE ev_ref (
    id serial PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(id),
    label text NOT NULL,
    f8 double precision,
    amount numeric(12,4),
    tags text[] NOT NULL DEFAULT '{}'
);
CREATE FUNCTION ev_ref_touch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.label := NEW.label || 'x'; RETURN NEW; END; $$;
CREATE TRIGGER ev_ref_touch BEFORE INSERT ON ev_ref FOR EACH ROW EXECUTE FUNCTION ev_ref_touch();
`

// populate fills a migrated database with data from every layer, including
// awkward values (tabs, newlines, backslashes, \N, unicode, binary, NULLs).
func populate(t testing.TB, ownerURL string, key []byte, extras bool) (org uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	c := connectT(t, ownerURL)
	org, site, user := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, c, `INSERT INTO organizations (id, name) VALUES ($1, $2)`, org, "Org with\ttab and \\N and ünïcödé 😀")
	mustExec(t, c, `INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 'HQ')`, site, org)
	mustExec(t, c, `INSERT INTO users (id, org_id, email, display_name, password_hash) VALUES ($1, $2, 'Admin@Example.com', $3, 'argon2id$x\y')`,
		user, org, "Line1\nLine2\r\nTab\there")
	tok := uuid.New()
	mustExec(t, c, `INSERT INTO enrollment_tokens (id, org_id, site_id, name, token_hash, max_uses, expires_at, require_approval, created_by)
		VALUES ($1, $2, $3, 'tok', '\x00ff10'::bytea, 5, now() + interval '1 day', true, $4)`, tok, org, site, user)
	d1, d2 := uuid.New(), uuid.New()
	mustExec(t, c, `INSERT INTO devices (id, org_id, site_id, status, hostname, enrolled_via, hardware, hardware_updated_at, pending_csr)
		VALUES ($1, $2, $3, 'active', $5, $4, '{"cpu":{"cores":8,"name":"x\\ty"},"list":[1,2.5,null]}', now(), '\x0001feff')`, d1, org, site, tok, "HOST\t\\N\n1")
	mustExec(t, c, `INSERT INTO devices (id, org_id, site_id, status, hostname, replaces_device_id) VALUES ($1, $2, $3, 'revoked', 'old', $4)`, d2, org, site, d1)
	mustExec(t, c, `INSERT INTO device_certs (serial, device_id, public_key_sha256, not_before, not_after) VALUES ('abcd', $1, '\xdeadbeef', now() - interval '1 hour', now() + interval '90 days')`, d1)
	title := uuid.New()
	mustExec(t, c, `INSERT INTO software_titles (id, org_id, normalized_name, normalized_publisher, display_name, display_publisher) VALUES ($1, $2, '7zip', 'igor pavlov', '7-Zip', 'Igor Pavlov')`, title, org)
	mustExec(t, c, `INSERT INTO software_installs (device_id, source, scope, item_key, title_id, name, version, version_key, first_seen_at, last_seen_at)
		VALUES ($1, 'reg64', 'machine', '7-Zip', $2, '7-Zip', '24.08', '\x0018', now(), now())`, d1, title)
	for i := 0; i < 5; i++ {
		mustExec(t, c, `INSERT INTO software_history (device_id, title_id, name, scope, change, new_version, observed_at) VALUES ($1, $2, '7-Zip', 'machine', 'added', $3, now())`, d1, title, "1."+itoa(int64(i)))
	}

	// CA material sealed with the KEK, as setup does.
	h, err := pki.NewHierarchy("Test Org", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s, err := kek.New(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.SaveHierarchy(ctx, dbq.New(c), s, h, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}

	if extras {
		mustExec(t, c, extraDDL)
		for i := 0; i < 6; i++ {
			ts := "2026-06-01"
			if i%2 == 1 {
				ts = "2027-03-01"
			}
			mustExec(t, c, `INSERT INTO ev (ts, n, note) VALUES ($1, $2, $3)`, ts, i, "note\t"+string(rune('a'+i)))
		}
		mustExec(t, c, `INSERT INTO ev_ref (org_id, label, f8, amount, tags) VALUES ($1, 'a', 0.1, 12345.6789, ARRAY['x','y z','\N'])`, org)
		mustExec(t, c, `INSERT INTO ev_ref (org_id, label, f8, amount) VALUES ($1, 'b', NULL, NULL)`, org)
	}

	for i := 0; i < 7; i++ {
		if err := audit.Log(ctx, c, audit.Entry{OrgID: &org, ActorType: audit.ActorUser, ActorID: user.String(), ActorIP: "10.0.0.1",
			Action: "test.action", TargetType: "device", TargetIDs: []string{d1.String(), "x\ty"}, Outcome: audit.Success,
			Details: map[string]any{"n": i, "txt": "a\tb\nc\\d", "nested": map[string]any{"b": "<x>", "a": true}, "f": 1.5}}); err != nil {
			t.Fatal(err)
		}
	}
	return org
}

// tableDigests returns an md5 over the text form of every row, per table.
// For audit_log only rows up to upToAudit are considered (the backup itself
// appends an entry to the source after its snapshot).
func tableDigests(t testing.TB, c *pgx.Conn, upToAudit int64) map[string]string {
	t.Helper()
	ctx := context.Background()
	tables, err := discoverTables(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, tb := range tables {
		where := ""
		if tb.name == "audit_log" {
			where = " WHERE x.id <= " + itoa(upToAudit)
		}
		var d *string
		q := `SELECT md5(string_agg(x::text, E'\n' ORDER BY x::text)) FROM ` + qident("public", tb.name) + ` x` + where
		if err := c.QueryRow(ctx, q).Scan(&d); err != nil {
			t.Fatalf("digest %s: %v", tb.name, err)
		}
		if d != nil {
			out[tb.name] = *d
		} else {
			out[tb.name] = "empty"
		}
	}
	return out
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

// genKey makes a throwaway age key pair at test time.
func genKey(t testing.TB) (*age.X25519Identity, age.Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id, id.Recipient()
}

func writeFile(t testing.TB, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// ---- archive crafting ----

type tarMember struct {
	name     string
	data     []byte
	typeflag byte
	link     string
}

// encryptTar writes members to a tar inside an age stream.
func encryptTar(t testing.TB, rcp age.Recipient, members []tarMember) []byte {
	t.Helper()
	var out bytes.Buffer
	enc, err := age.Encrypt(&out, rcp)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(enc)
	for _, m := range members {
		tf := m.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		h := &tar.Header{Typeflag: tf, Name: m.name, Size: int64(len(m.data)), Mode: 0o600, Linkname: m.link}
		if tf != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if tf == tar.TypeReg {
			if _, err := tw.Write(m.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// readTar decrypts an archive and returns its members in order.
func readTar(t testing.TB, archive []byte, ids ...age.Identity) []tarMember {
	t.Helper()
	dec, err := age.Decrypt(bytes.NewReader(archive), ids...)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(dec)
	var ms []tarMember
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return ms
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		ms = append(ms, tarMember{name: h.Name, data: b})
	}
}

// craft builds a valid archive (correct manifest) from a header and extra
// members; edit may change the manifest before it is written.
func craft(t testing.TB, rcp age.Recipient, hdr Header, extra []tarMember, edit func(*Manifest)) []byte {
	t.Helper()
	rawH, _ := json.Marshal(hdr)
	ms := []tarMember{{name: memberHeader, data: rawH}}
	ms = append(ms, extra...)
	m := Manifest{Header: hdr, RowCounts: map[string]int64{}, Content: ContentInfo{}}
	for _, tb := range hdr.Tables {
		m.RowCounts[tb.Name] = 0
	}
	for _, x := range ms {
		m.Members = append(m.Members, Member{Name: x.name, Size: int64(len(x.data)), SHA256: sumBytes(x.data)})
	}
	for _, x := range extra {
		if len(x.name) > len(prefixFiles) && x.name[:len(prefixFiles)] == prefixFiles {
			m.Content.Files++
			m.Content.Bytes += int64(len(x.data))
		}
	}
	if edit != nil {
		edit(&m)
	}
	rawM, _ := json.Marshal(m)
	return encryptTar(t, rcp, append(ms, tarMember{name: memberManifest, data: rawM}))
}

func fakeHeader() Header {
	return Header{FormatVersion: FormatVersion, AppVersion: "test", AppCommit: "x", SchemaVersion: 1,
		CreatedAt: time.Unix(1_700_000_000, 0).UTC(), Notes: []string{"n"},
		Tables: []TableDef{{Name: "organizations", Kind: "table", Columns: []string{"id"}}}, Sequences: []SeqDef{}}
}

func bytesSource(b []byte, repeatable bool) Source {
	return Source{Repeatable: repeatable, Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }}
}
