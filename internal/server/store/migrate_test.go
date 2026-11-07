package store_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

func tableExists(t *testing.T, c *pgx.Conn, name string) bool {
	t.Helper()
	var ok bool
	if err := c.QueryRow(context.Background(), `SELECT to_regclass('public.'||$1) IS NOT NULL`, name).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}

// TestBrandingMigrationIsReversible: migration 10 can be rolled back (dropping only the branding tables, other data
// untouched) and applied again, even while it holds data.
func TestBrandingMigrationIsReversible(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := pgx.Connect(ctx, db.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close(ctx) }()

	org := uuid.New()
	if _, err := c.Exec(ctx, `INSERT INTO organizations (id, name) VALUES ($1, 'Example')`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `INSERT INTO branding (org_id, org_name, updated_at) VALUES ($1, 'Example', now())`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `INSERT INTO branding_assets (org_id, kind, content, content_type, width, height, sha256, updated_at) VALUES ($1, 'icon', '\x89504e47', 'image/png', 64, 64, decode(repeat('00',32),'hex'), now())`, org); err != nil {
		t.Fatal(err)
	}
	// The table constraints hold at the database level too.
	for name, q := range map[string]string{
		"bad color":   `UPDATE branding SET accent_color = 'red' WHERE org_id = $1`,
		"bad kind":    `INSERT INTO branding_assets (org_id, kind, content, content_type, width, height, sha256, updated_at) VALUES ($1, 'script', '\x00', 'image/png', 1, 1, decode(repeat('00',32),'hex'), now())`,
		"huge name":   `UPDATE branding SET org_name = repeat('x', 500) WHERE org_id = $1`,
		"empty image": `INSERT INTO branding_assets (org_id, kind, content, content_type, width, height, sha256, updated_at) VALUES ($1, 'logo_dark', '\x', 'image/png', 1, 1, decode(repeat('00',32),'hex'), now())`,
	} {
		if _, err := c.Exec(ctx, q, org); err == nil {
			t.Errorf("%s was accepted by the database", name)
		}
	}

	if _, err := c.Exec(ctx, `UPDATE branding SET default_theme = 'dark', allowed_themes = '{light,dark}' WHERE org_id = $1`, org); err != nil {
		t.Fatalf("theme columns: %v", err)
	}
	if _, err := c.Exec(ctx, `UPDATE branding SET default_theme = 'Dark Mode' WHERE org_id = $1`, org); err == nil {
		t.Error("a malformed theme id was accepted by the database")
	}
	// Migration 11 (appearance) rolls back on its own, leaving branding in place.
	if err := store.MigrateDown(ctx, db.OwnerURL, 10, log); err != nil {
		t.Fatalf("down to 10: %v", err)
	}
	if tableExists(t, c, "user_preferences") || !tableExists(t, c, "branding") {
		t.Fatal("rolling back migration 11 must drop user_preferences and keep branding")
	}
	if err := store.Migrate(ctx, db.OwnerURL, log); err != nil {
		t.Fatalf("up to 11 again: %v", err)
	}
	if !tableExists(t, c, "user_preferences") {
		t.Fatal("user_preferences must exist after migrating up")
	}
	if err := store.MigrateDown(ctx, db.OwnerURL, 9, log); err != nil {
		t.Fatalf("down: %v", err)
	}
	if tableExists(t, c, "branding") || tableExists(t, c, "branding_assets") {
		t.Fatal("the branding tables must be gone after rolling back")
	}
	var n int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM organizations`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rolling back must leave other data alone: %d %v", n, err)
	}
	if err := store.Migrate(ctx, db.OwnerURL, log); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if !tableExists(t, c, "branding") || !tableExists(t, c, "branding_assets") {
		t.Fatal("the branding tables must exist after migrating up again")
	}
	if err := c.QueryRow(ctx, `SELECT count(*) FROM branding`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("branding data is not restored by a round trip (it was dropped by the rollback): %d %v", n, err)
	}
	// The runtime role can use the re-created tables.
	var ok bool
	if err := c.QueryRow(ctx, `SELECT has_table_privilege('librepatch_app', 'branding', 'INSERT,UPDATE,DELETE') AND has_table_privilege('librepatch_app', 'branding_assets', 'SELECT,INSERT,UPDATE,DELETE')`).Scan(&ok); err != nil || !ok {
		t.Fatalf("librepatch_app privileges: %v %v", ok, err)
	}
}
