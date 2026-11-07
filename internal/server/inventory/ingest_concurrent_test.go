package inventory

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

// Many devices of one organization ingest the same common software at the same moment, as happens when
// a fleet enrolls or comes back after an outage. This used to fail with "deadlock detected": the title
// upsert locked existing rows in random order. Found by cmd/librepatch-loadsim.
func TestConcurrentSnapshotsOfCommonSoftwareDoNotDeadlock(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	org, site := uuid.New(), uuid.New()
	for _, q := range []struct {
		q    string
		args []any
	}{
		{"INSERT INTO organizations (id, name) VALUES ($1, 'o')", []any{org}},
		{"INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 's')", []any{site, org}},
	} {
		if _, err := db.Pool.Exec(ctx, q.q, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	const devices, titles = 24, 60
	var items []*agentv1.SoftwareItem
	for i := 0; i < titles; i++ {
		items = append(items, item(reg64, fmt.Sprintf("K%03d", i), fmt.Sprintf("Common Product %03d", i), "1.0"))
	}
	svc := &Service{Pool: db.Pool}
	ids := make([]uuid.UUID, devices)
	for i := range ids {
		ids[i] = uuid.New()
		if _, err := db.Pool.Exec(ctx, "INSERT INTO devices (id, org_id, site_id, status, hostname) VALUES ($1, $2, $3, 'active', 'h')", ids[i], org, site); err != nil {
			t.Fatal(err)
		}
	}
	errs := make(chan error, devices)
	start := make(chan struct{})
	for _, id := range ids {
		go func() {
			<-start
			errs <- svc.ApplySnapshot(ctx, id, 1, items, false)
		}()
	}
	close(start)
	for range ids {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent snapshot failed: %v", err)
		}
	}
	if n := count(t, db.Pool, "SELECT count(*) FROM software_titles WHERE org_id=$1", org); n != titles {
		t.Fatalf("%d titles, want %d (each title must exist exactly once)", n, titles)
	}
	if n := count(t, db.Pool, "SELECT count(*) FROM software_installs"); n != devices*titles {
		t.Fatalf("%d install rows, want %d", n, devices*titles)
	}
}
