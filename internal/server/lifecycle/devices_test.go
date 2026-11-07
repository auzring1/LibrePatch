package lifecycle

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

func TestListReadsTheFleetAndSortsTheWorstFirst(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	org, other, site := uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec("INSERT INTO organizations (id, name) VALUES ($1, 'Contoso Health'), ($2, 'Other')", org, other)
	exec("INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 's')", site, org)
	add := func(o uuid.UUID, host, status, caption, hw string) {
		exec(`INSERT INTO devices (id, org_id, site_id, status, hostname, arch, os_caption, hardware) VALUES ($1,$2,$3,$4,$5,'amd64',$6,$7::jsonb)`,
			uuid.New(), o, site, status, host, caption, hw)
	}
	add(org, "new-11", "active", "Windows 11 Pro", `{"os_build":26200,"os_edition":"Professional","os_display_version":"25H2"}`)
	add(org, "old-10", "active", "Windows 10 Pro", `{"os_build":19045,"os_edition":"Professional","os_display_version":"22H2"}`)
	add(org, "srv-2016", "active", "Windows Server 2016 Standard", `{"os_build":14393,"os_edition":"ServerStandard"}`)
	add(org, "nohw", "active", "Windows 11 Pro", `{}`)                     // no hardware report yet
	add(org, "revoked", "revoked", "Windows 10 Pro", `{"os_build":19045}`) // not an active device
	add(other, "elsewhere", "active", "Windows 10 Pro", `{"os_build":19045}`)

	rows, err := List(ctx, db.Pool, org, today, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rows {
		got = append(got, r.Hostname+":"+r.Status)
	}
	want := []string{"old-10:unsupported", "srv-2016:ending_soon", "new-11:supported", "nohw:unknown"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if rows[2].Version != "25H2" || rows[2].Edition != "Professional" || rows[2].Build != 26200 {
		t.Fatalf("device fields: %+v", rows[2])
	}
	if s := Summarize(rows); s.Unsupported != 1 || s.EndingSoon != 1 || s.Supported != 1 || s.Unknown != 1 {
		t.Fatalf("summary %+v", s)
	}
}
