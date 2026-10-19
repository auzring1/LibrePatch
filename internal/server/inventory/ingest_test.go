package inventory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/shared/vercmp"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

func newDevice(t *testing.T, pool *pgxpool.Pool) (*Service, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	org, site, dev := uuid.New(), uuid.New(), uuid.New()
	for _, s := range []struct {
		q    string
		args []any
	}{
		{"INSERT INTO organizations (id, name) VALUES ($1, 'o')", []any{org}},
		{"INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 's')", []any{site, org}},
		{"INSERT INTO devices (id, org_id, site_id, status, hostname) VALUES ($1, $2, $3, 'active', 'h')", []any{dev, org, site}},
	} {
		if _, err := pool.Exec(ctx, s.q, s.args...); err != nil {
			t.Fatal(err)
		}
	}
	return &Service{Pool: pool}, dev
}

func item(src agentv1.SoftwareSource, key, name, ver string) *agentv1.SoftwareItem {
	return &agentv1.SoftwareItem{Key: &agentv1.SoftwareItemKey{Source: src, Scope: agentv1.SoftwareScope_SOFTWARE_SCOPE_MACHINE, ItemKey: key},
		Name: name, Version: ver, Publisher: "Acme Inc."}
}

func keyOf(it *agentv1.SoftwareItem) *agentv1.SoftwareItemKey { return it.Key }

func count(t *testing.T, pool *pgxpool.Pool, q string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

const reg64 = agentv1.SoftwareSource_SOFTWARE_SOURCE_REG64

func TestSnapshotThenDeltaWithHistory(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	s, dev := newDevice(t, db.Pool)

	a, b := item(reg64, "A", "Acme Tool 1.0 (x64)", "1.0"), item(reg64, "B", "Other", "2.0")
	if err := s.ApplySnapshot(ctx, dev, 1, []*agentv1.SoftwareItem{a, b}, false); err != nil {
		t.Fatal(err)
	}
	// Baseline: no "added" history for the first snapshot.
	if n := count(t, db.Pool, "SELECT count(*) FROM software_history WHERE device_id=$1", dev); n != 0 {
		t.Fatalf("baseline recorded %d history rows", n)
	}
	var rev int64
	var cnt int
	if err := db.Pool.QueryRow(ctx, "SELECT software_rev, software_count FROM devices WHERE id=$1", dev).Scan(&rev, &cnt); err != nil || rev != 1 || cnt != 2 {
		t.Fatalf("rev=%d count=%d err=%v", rev, cnt, err)
	}
	// Both Acme items share one title regardless of version/arch decoration.
	a2 := item(reg64, "A", "Acme Tool 2.0 (x64)", "2.0")
	c := item(reg64, "C", "Brand New", "1")
	err := s.ApplyDelta(ctx, dev, 2, &agentv1.SoftwareDelta{BaseRev: 1, Upserts: []*agentv1.SoftwareItem{a2, c}, Removes: []*agentv1.SoftwareItemKey{keyOf(b)}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if n := count(t, db.Pool, "SELECT count(*) FROM software_installs WHERE device_id=$1", dev); n != 2 {
		t.Fatalf("installs=%d", n)
	}
	for change, want := range map[string]int{"added": 1, "version": 1, "removed": 1} {
		if n := count(t, db.Pool, "SELECT count(*) FROM software_history WHERE device_id=$1 AND change=$2", dev, change); n != want {
			t.Fatalf("history %s=%d want %d", change, n, want)
		}
	}
	if n := count(t, db.Pool, "SELECT count(*) FROM software_titles"); n != 3 {
		t.Fatalf("titles=%d", n)
	}
	// Version ordering key is usable in SQL.
	if n := count(t, db.Pool, `SELECT count(*) FROM software_installs WHERE device_id=$1 AND version_key < $2`, dev, versionKeyOf("2.5")); n != 2 {
		t.Fatalf("version_key compare: %d", n)
	}
}

func TestDeltaRevMismatchChangesNothing(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	s, dev := newDevice(t, db.Pool)
	if err := s.ApplySnapshot(ctx, dev, 5, []*agentv1.SoftwareItem{item(reg64, "A", "A", "1")}, false); err != nil {
		t.Fatal(err)
	}
	err := s.ApplyDelta(ctx, dev, 4, &agentv1.SoftwareDelta{BaseRev: 3, Upserts: []*agentv1.SoftwareItem{item(reg64, "Z", "Z", "1")}}, false)
	if !errors.Is(err, ErrRevMismatch) {
		t.Fatalf("want ErrRevMismatch, got %v", err)
	}
	if n := count(t, db.Pool, "SELECT count(*) FROM software_installs WHERE device_id=$1", dev); n != 1 {
		t.Fatalf("mismatched delta modified data: %d", n)
	}
	// Replaying an already applied delta is also a mismatch (idempotent protection).
	d := &agentv1.SoftwareDelta{BaseRev: 5, Upserts: []*agentv1.SoftwareItem{item(reg64, "B", "B", "1")}}
	if err := s.ApplyDelta(ctx, dev, 6, d, false); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyDelta(ctx, dev, 6, d, false); !errors.Is(err, ErrRevMismatch) {
		t.Fatalf("replay: %v", err)
	}
}

func TestFullSnapshotRemovesMissingAndSetsTruncated(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	s, dev := newDevice(t, db.Pool)
	_ = s.ApplySnapshot(ctx, dev, 1, []*agentv1.SoftwareItem{item(reg64, "A", "A", "1"), item(reg64, "B", "B", "1")}, false)
	if err := s.ApplySnapshot(ctx, dev, 2, []*agentv1.SoftwareItem{item(reg64, "A", "A", "1")}, true); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db.Pool, "SELECT count(*) FROM software_history WHERE device_id=$1 AND change='removed'", dev); n != 1 {
		t.Fatalf("removed history=%d", n)
	}
	var trunc bool
	_ = db.Pool.QueryRow(ctx, "SELECT inventory_truncated FROM devices WHERE id=$1", dev).Scan(&trunc)
	if !trunc {
		t.Fatal("truncated flag not stored")
	}
	// An empty snapshot clears everything.
	if err := s.ApplySnapshot(ctx, dev, 3, nil, false); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db.Pool, "SELECT count(*) FROM software_installs WHERE device_id=$1", dev); n != 0 {
		t.Fatalf("installs=%d", n)
	}
}

func TestIngestRejectsInvalidData(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	s, dev := newDevice(t, db.Pool)
	long := strings.Repeat("a", maxName+1)
	user := func(sid string) *agentv1.SoftwareItem {
		it := item(reg64, "U", "U", "1")
		it.Key.Scope, it.Key.UserSid = agentv1.SoftwareScope_SOFTWARE_SCOPE_USER, sid
		return it
	}
	bad := map[string]*agentv1.SoftwareItem{
		"long name":      item(reg64, "k", long, "1"),
		"empty name":     item(reg64, "k", "  ", "1"),
		"no key":         item(reg64, "", "n", "1"),
		"bad source":     item(agentv1.SoftwareSource_SOFTWARE_SOURCE_UNSPECIFIED, "k", "n", "1"),
		"machine+sid":    func() *agentv1.SoftwareItem { i := item(reg64, "k", "n", "1"); i.Key.UserSid = "S-1-5-21-1"; return i }(),
		"user bad sid":   user("not-a-sid"),
		"user empty sid": user(""),
		"bad date":       func() *agentv1.SoftwareItem { i := item(reg64, "k", "n", "1"); i.InstallDate = "yesterday"; return i }(),
	}
	for name, it := range bad {
		if err := s.ApplySnapshot(ctx, dev, 1, []*agentv1.SoftwareItem{it}, false); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	if err := s.ApplySnapshot(ctx, dev, 1, make([]*agentv1.SoftwareItem, MaxItems+1), false); !errors.Is(err, ErrInvalid) {
		t.Errorf("too many items: %v", err)
	}
	if err := s.ApplyDelta(ctx, dev, 5, &agentv1.SoftwareDelta{BaseRev: 0}, false); !errors.Is(err, ErrInvalid) {
		t.Errorf("non-sequential rev: %v", err)
	}
	// NUL bytes are stripped rather than breaking PostgreSQL.
	if err := s.ApplySnapshot(ctx, dev, 1, []*agentv1.SoftwareItem{item(reg64, "k", "Na\x00me", "1\x00.0")}, false); err != nil {
		t.Fatalf("NUL handling: %v", err)
	}
	var name string
	_ = db.Pool.QueryRow(ctx, "SELECT name FROM software_installs WHERE device_id=$1", dev).Scan(&name)
	if name != "Name" {
		t.Fatalf("name=%q", name)
	}
}

func TestUserScopedItemsAndUsers(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	s, dev := newDevice(t, db.Pool)
	const sid1, sid2 = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	mk := func(sid string) *agentv1.SoftwareItem {
		it := item(agentv1.SoftwareSource_SOFTWARE_SOURCE_HKU, "Chrome", "Google Chrome", "129.0")
		it.Key.Scope, it.Key.UserSid = agentv1.SoftwareScope_SOFTWARE_SCOPE_USER, sid
		return it
	}
	if err := s.ApplySnapshot(ctx, dev, 1, []*agentv1.SoftwareItem{mk(sid1), mk(sid2)}, false); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db.Pool, "SELECT count(*) FROM software_installs WHERE device_id=$1", dev); n != 2 {
		t.Fatalf("per-user rows: %d", n)
	}
	users := []*agentv1.DeviceUser{{Sid: sid1, Username: "alice", Domain: "CORP", LastLogon: time.Now().Unix(), Loaded: true}, {Sid: sid2, Username: "bob"}}
	if err := s.ApplyUsers(ctx, dev, 1, users); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyUsers(ctx, dev, 2, users[:1]); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db.Pool, "SELECT count(*) FROM device_users WHERE device_id=$1", dev); n != 1 {
		t.Fatalf("users after replace: %d", n)
	}
	if err := s.ApplyUsers(ctx, dev, 3, []*agentv1.DeviceUser{{Sid: "bogus"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad user sid: %v", err)
	}
	var rev int64
	_ = db.Pool.QueryRow(ctx, "SELECT users_rev FROM devices WHERE id=$1", dev).Scan(&rev)
	if rev != 2 {
		t.Fatalf("users_rev=%d", rev)
	}
}

func versionKeyOf(v string) []byte { return vercmp.Key(v) }

// The Software page has one query for the default view (system components left out, written out so a partial index
// can serve it) and one for the view that includes them. With system components off both must answer the same.
func TestSoftwareSearchWithoutSystemComponentsMatchesTheGeneralQuery(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	s, dev := newDevice(t, db.Pool)
	var org uuid.UUID
	if err := db.Pool.QueryRow(ctx, "SELECT org_id FROM devices WHERE id=$1", dev).Scan(&org); err != nil {
		t.Fatal(err)
	}
	sys := item(reg64, "KB1", "Update for Windows", "1.0")
	sys.SystemComponent = true
	items := []*agentv1.SoftwareItem{item(reg64, "A", "Acme Tool", "1.0"), item(reg64, "B", "Acme Tool", "2.0"), item(reg64, "C", "Other Program", "3.0"), sys}
	if err := s.ApplySnapshot(ctx, dev, 1, items, false); err != nil {
		t.Fatal(err)
	}
	q := dbq.New(db.Pool)
	for _, filter := range []string{"", "acme", "nothing"} {
		general, err := q.SearchSoftwareTitles(ctx, dbq.SearchSoftwareTitlesParams{OrgID: org, IncludeSystem: false, Q: filter, RowLimit: 50})
		if err != nil {
			t.Fatal(err)
		}
		plain, err := q.SearchSoftwareTitlesNoSystem(ctx, dbq.SearchSoftwareTitlesNoSystemParams{OrgID: org, Q: filter, RowLimit: 50})
		if err != nil {
			t.Fatal(err)
		}
		if len(general) != len(plain) {
			t.Fatalf("filter %q: %d rows vs %d", filter, len(general), len(plain))
		}
		for i := range general {
			if dbq.SearchSoftwareTitlesNoSystemRow(general[i]) != plain[i] {
				t.Fatalf("filter %q row %d: %+v vs %+v", filter, i, general[i], plain[i])
			}
		}
		if filter == "" && (len(plain) != 2 || plain[0].DisplayName != "Acme Tool" || plain[0].VersionCount != 2) {
			t.Fatalf("expected Acme Tool (2 versions) and Other Program, no system component: %+v", plain)
		}
	}
	withSystem, _ := q.SearchSoftwareTitles(ctx, dbq.SearchSoftwareTitlesParams{OrgID: org, IncludeSystem: true, RowLimit: 50})
	if len(withSystem) != 3 {
		t.Fatalf("with system components: %+v", withSystem)
	}
}
