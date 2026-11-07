package masterkey

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

func TestGroupedAndParseRoundTrip(t *testing.T) {
	k, err := Generate()
	if err != nil || len(k) != Size {
		t.Fatalf("generate: %v %d", err, len(k))
	}
	g := Grouped(k)
	if strings.Count(g, "-") != 7 || len(g) != 71 {
		t.Fatalf("grouped form: %q", g)
	}
	for _, in := range []string{g, strings.ToUpper(g), Hex(k), "Master key: " + g + "\nKey id: 1234abcd\n"} {
		got, err := Parse(in)
		if err != nil || Hex(got) != Hex(k) {
			t.Fatalf("parse %q: %v", in, err)
		}
	}
	for _, bad := range []string{"", "abc", strings.Repeat("g", 64), Hex(k)[:62]} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("parse accepted %q", bad)
		}
	}
}

func TestWriteNewNeverReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "master_key")
	k, _ := Generate()
	if err := WriteNew(path, k); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o400 {
		t.Fatalf("mode: %v %v", fi, err)
	}
	other, _ := Generate()
	if err := WriteNew(path, other); !errors.Is(err, os.ErrExist) {
		t.Fatalf("an existing key must not be replaced: %v", err)
	}
	if b, _ := os.ReadFile(path); strings.TrimSpace(string(b)) != Hex(k) {
		t.Fatal("the key file changed")
	}
}

func TestProvisionRecordsTheKeyOnceAndRefusesWhenDataIsSealed(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, db.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()

	path := filepath.Join(t.TempDir(), "master_key")
	k, _ := Generate()
	if err := Provision(ctx, conn, path, k); err != nil {
		t.Fatal(err)
	}
	var id string
	var acked *string
	if err := conn.QueryRow(ctx, "SELECT key_id, acknowledged_at::text FROM master_key_ack WHERE id = 1").Scan(&id, &acked); err != nil {
		t.Fatal(err)
	}
	want, _ := ID(k)
	if id != want || acked != nil {
		t.Fatalf("recorded key id %q (want %q), acknowledged %v", id, want, acked)
	}

	// A crash between the record and the file is repaired by the next run: the unacknowledged row is replaced.
	path2 := filepath.Join(t.TempDir(), "master_key")
	k2, _ := Generate()
	if err := Provision(ctx, conn, path2, k2); err != nil {
		t.Fatal(err)
	}
	want2, _ := ID(k2)
	if err := conn.QueryRow(ctx, "SELECT key_id FROM master_key_ack WHERE id = 1").Scan(&id); err != nil || id != want2 {
		t.Fatalf("the unacknowledged row was not replaced: %q %v", id, err)
	}

	// Once the database holds sealed data, a missing key is never replaced.
	if _, err := conn.Exec(ctx, "INSERT INTO setup_state (id, totp_secret_enc) VALUES (1, '\\x00')"); err != nil {
		t.Fatal(err)
	}
	k3, _ := Generate()
	path3 := filepath.Join(t.TempDir(), "master_key")
	if err := Provision(ctx, conn, path3, k3); !errors.Is(err, ErrKeyMissing) {
		t.Fatalf("expected ErrKeyMissing, got %v", err)
	}
	if _, err := os.Stat(path3); err == nil {
		t.Fatal("a key file was written although the database holds sealed data")
	}
}
