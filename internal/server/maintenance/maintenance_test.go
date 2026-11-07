package maintenance

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

// The software change history is deleted in batches, only for the organization asked, and only what is older than
// the limit.
func TestPruneSoftwareHistoryBatchesAndKeepsRecentAndOtherOrganizations(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	mk := func(name string) (org, dev uuid.UUID) {
		org, site, dev, title := uuid.New(), uuid.New(), uuid.New(), uuid.New()
		exec("INSERT INTO organizations (id, name) VALUES ($1, $2)", org, name)
		exec("INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 's')", site, org)
		exec("INSERT INTO devices (id, org_id, site_id, status, hostname) VALUES ($1, $2, $3, 'active', 'h')", dev, org, site)
		exec("INSERT INTO software_titles (id, org_id, normalized_name, normalized_publisher, display_name, display_publisher) VALUES ($1,$2,'t','p','T','P')", title, org)
		// 45,000 old entries (three batches of 20,000 are needed) and 10 recent ones.
		exec(`INSERT INTO software_history (device_id, title_id, name, scope, change, observed_at)
			SELECT $1, $2, 'T', 'machine', 'added', now() - interval '800 days' - (g || ' seconds')::interval FROM generate_series(1, 45000) g`, dev, title)
		exec(`INSERT INTO software_history (device_id, title_id, name, scope, change, observed_at)
			SELECT $1, $2, 'T', 'machine', 'added', now() - (g || ' days')::interval FROM generate_series(1, 10) g`, dev, title)
		return org, dev
	}
	orgA, devA := mk("a")
	_, devB := mk("b")

	s := &Service{Pool: db.Pool}
	n, err := s.pruneSoftwareHistory(ctx, orgA, time.Now().AddDate(0, 0, -730))
	if err != nil || n != 45000 {
		t.Fatalf("removed %d, %v; want 45000", n, err)
	}
	count := func(dev uuid.UUID) (n int) {
		if err := db.Pool.QueryRow(ctx, "SELECT count(*) FROM software_history WHERE device_id = $1", dev).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := count(devA); got != 10 {
		t.Fatalf("organization A keeps %d entries; want the 10 recent ones", got)
	}
	if got := count(devB); got != 45010 {
		t.Fatalf("organization B has %d entries; another organization's history must not be touched", got)
	}
}
