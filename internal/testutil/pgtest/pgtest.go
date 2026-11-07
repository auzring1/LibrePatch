// Package pgtest creates an isolated, migrated database per test.
//
// Set LIBREPATCH_TEST_PG_URL to a superuser URL (e.g. postgres://postgres:pw@127.0.0.1:55432/postgres).
// Tests that need a database are skipped when it is unset, except in CI
// where LIBREPATCH_REQUIRE_DB=1 turns the skip into a failure.
package pgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/internal/server/store"
)

// AppPassword is the password of the test-only librepatch_app role.
const AppPassword = "librepatch-app-test-only"

// DB is a migrated test database.
type DB struct {
	Pool     *pgxpool.Pool // connected as the least-privilege librepatch_app role
	AppURL   string
	OwnerURL string
}

// New creates a fresh database, migrates it as the owner and connects as librepatch_app.
func New(t testing.TB) *DB {
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
		t.Fatalf("connect admin: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()

	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "lp_t_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create db: %v", err)
	}
	// Roles are cluster-wide; create once, tolerate races between packages.
	_, _ = admin.Exec(ctx, `DO $$ BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='librepatch_app') THEN
			CREATE ROLE librepatch_app LOGIN PASSWORD '`+AppPassword+`';
		END IF; END $$`)

	ownerURL := withDB(t, base, name, "")
	if err := store.Migrate(ctx, ownerURL, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	appURL := withDB(t, base, name, "librepatch_app:"+AppPassword)
	pool, err := store.Open(ctx, appURL)
	if err != nil {
		t.Fatalf("open app pool: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		c, err := pgx.Connect(context.Background(), base)
		if err == nil {
			_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			_ = c.Close(context.Background())
		}
	})
	return &DB{Pool: pool, AppURL: appURL, OwnerURL: ownerURL}
}

func withDB(t testing.TB, base, db, userinfo string) string {
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + db
	if userinfo != "" {
		user, pw := userinfo, ""
		for i := range userinfo {
			if userinfo[i] == ':' {
				user, pw = userinfo[:i], userinfo[i+1:]
				break
			}
		}
		u.User = url.UserPassword(user, pw)
	}
	q := u.Query()
	if q.Get("sslmode") == "" {
		q.Set("sslmode", "disable")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// OwnerConn returns a connection with schema-owner rights (for tamper tests).
func OwnerConn(t testing.TB, d *DB) *pgx.Conn {
	t.Helper()
	c, err := pgx.Connect(context.Background(), d.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}
