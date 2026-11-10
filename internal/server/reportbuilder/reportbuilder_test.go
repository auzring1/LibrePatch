package reportbuilder

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/internal/server/groups"
	"github.com/auzring1/librepatch/internal/server/pdf"
	"github.com/auzring1/librepatch/internal/shared/vercmp"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

func TestEveryBuiltinReportIsValid(t *testing.T) {
	seen := map[string]bool{}
	for _, b := range Builtins() {
		if seen[b.ID] || b.Name == "" || b.Description == "" {
			t.Errorf("builtin %q: duplicate id or missing text", b.ID)
		}
		seen[b.ID] = true
		if _, _, err := b.Spec.Validate(true); err != nil {
			t.Errorf("builtin %q: %v", b.ID, err)
		}
	}
}

func TestEveryColumnHasAWidthAndLabelAndOps(t *testing.T) {
	for _, d := range Datasets() {
		for _, id := range d.DefaultColumns {
			if _, ok := d.Column(id); !ok {
				t.Errorf("%s default column %q does not exist", d.ID, id)
			}
		}
		if _, ok := d.Column(d.DefaultSort); !ok {
			t.Errorf("%s default sort %q does not exist", d.ID, d.DefaultSort)
		}
		for _, c := range d.Columns {
			if c.Label == "" || c.Group == "" || c.width == 0 || len(Ops(c.Kind)) == 0 {
				t.Errorf("%s.%s is incomplete", d.ID, c.ID)
			}
		}
	}
}

func TestValidateRejectsWhatIsNotAllowListed(t *testing.T) {
	ok := Spec{Dataset: "devices", Columns: []string{"hostname"}}
	cases := map[string]Spec{
		"unknown dataset":   {Dataset: "users", Columns: []string{"hostname"}},
		"no columns":        {Dataset: "devices"},
		"unknown column":    {Dataset: "devices", Columns: []string{"hostname; DROP TABLE devices"}},
		"column of another": {Dataset: "devices", Columns: []string{"drive"}},
		"bad op":            {Dataset: "devices", Columns: []string{"hostname"}, Filters: []Filter{{Column: "hostname", Op: "gt", Value: "a"}}},
		"number text":       {Dataset: "devices", Columns: []string{"hostname"}, Filters: []Filter{{Column: "ram_gb", Op: "gt", Value: "lots"}}},
		"number NaN":        {Dataset: "devices", Columns: []string{"hostname"}, Filters: []Filter{{Column: "ram_gb", Op: "gt", Value: "NaN"}}},
		"bool maybe":        {Dataset: "devices", Columns: []string{"hostname"}, Filters: []Filter{{Column: "online", Op: "is", Value: "maybe"}}},
		"bad date":          {Dataset: "devices", Columns: []string{"hostname"}, Filters: []Filter{{Column: "last_seen", Op: "after", Value: "yesterday"}}},
		"negative days":     {Dataset: "devices", Columns: []string{"hostname"}, Filters: []Filter{{Column: "last_seen", Op: "within_days", Value: "-3"}}},
		"empty text value":  {Dataset: "devices", Columns: []string{"hostname"}, Filters: []Filter{{Column: "hostname", Op: "contains"}}},
		"sort not shown":    {Dataset: "devices", Columns: []string{"hostname"}, Sort: &Sort{Column: "model"}},
		"patch without WU":  {Dataset: "patching", Columns: []string{"hostname"}},
	}
	for name, sp := range cases {
		if _, _, err := sp.Validate(true); err == nil && name != "patch without WU" {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := cases["patch without WU"].Validate(false); err == nil {
		t.Error("patch data must need Windows updates")
	}
	got, _, err := Spec{Dataset: "devices", Columns: []string{"hostname", "hostname", "model"}}.Validate(false)
	if err != nil || len(got.Columns) != 2 || got.Sort == nil || got.Sort.Column != "hostname" {
		t.Errorf("duplicates and the default sort: %+v %v", got, err)
	}
	if _, _, err := ok.Validate(false); err != nil {
		t.Error(err)
	}
}

func TestCSVIsFormulaSafeAndHasBOM(t *testing.T) {
	r := &Result{Columns: []ColumnInfo{{ID: "a", Label: "Device"}, {ID: "b", Label: "Note, with comma"}},
		Rows: [][]string{{"=cmd|' /C calc'!A0", "plain, text"}, {"@SUM(1)", "ok"}, {"-5", "+1"}}}
	b, err := CSV(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.HasPrefix(s, "\xef\xbb\xbf") {
		t.Error("missing BOM")
	}
	for _, want := range []string{`"Note, with comma"`, `'=cmd|' /C calc'!A0`, `'@SUM(1)`, `'-5,'+1`, `"plain, text"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in %q", want, s)
		}
	}
}

func TestPDFIsAPDFAndSaysWhenItIsCut(t *testing.T) {
	r := &Result{Columns: []ColumnInfo{{ID: "a", Label: "Device", Width: 20}}, Total: 3, Truncated: true, Rows: [][]string{{"PC-1"}, {"PC-2"}}}
	b := PDF(pdf.Doc{Title: "Test", ProductName: "LibrePatch"}, r)
	if !strings.HasPrefix(string(b), "%PDF-1.4") || !strings.Contains(string(b), "First 2 of 3 rows") {
		t.Errorf("pdf: %q", string(b[:80]))
	}
}

type fleet struct {
	t          *testing.T
	pool       *pgxpool.Pool
	org        uuid.UUID
	north, sth uuid.UUID
}

func (f *fleet) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fleet) device(site uuid.UUID, host, status, model string, ramGB int, hw string) uuid.UUID {
	id := uuid.New()
	f.exec(`INSERT INTO devices (id, org_id, site_id, status, hostname, arch, os_caption, os_build, online, hardware, last_seen_at)
		VALUES ($1,$2,$3,$4,$5,'amd64','Windows 11 Pro','26100.1',true,$6::jsonb, now() - interval '40 days')`,
		id, f.org, site, status, host, strings.NewReplacer("RAM", strconv.Itoa(ramGB*1073741824), "MODEL", model).Replace(hw))
	return id
}

func newFleet(t *testing.T) *fleet {
	db := pgtest.New(t)
	f := &fleet{t: t, pool: db.Pool, org: uuid.New(), north: uuid.New(), sth: uuid.New()}
	f.exec("INSERT INTO organizations (id, name) VALUES ($1, 'Contoso Health')", f.org)
	f.exec("INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 'North'), ($3, $2, 'South')", f.north, f.org, f.sth)
	const hw = `{"manufacturer":"Dell","model":"MODEL","ram_bytes":"RAM","cpu_model":"Core i5","cpu_logical_cores":8,
		"disks":[{"mount":"C:","filesystem":"NTFS","size_bytes":"500000000000","free_bytes":"50000000000","bitlocker":"unprotected"},
		         {"mount":"D:","filesystem":"NTFS","size_bytes":"1000000000000","free_bytes":"900000000000","bitlocker":"protected"}]}`
	f.device(f.north, "PC-A", "active", "Latitude", 16, hw)
	f.device(f.north, "PC-B", "active", "Optiplex", 8, hw)
	f.device(f.sth, "PC-C", "active", "Latitude", 32, hw)
	f.device(f.sth, "PC-OLD", "revoked", "Latitude", 4, hw)
	return f
}

func (f *fleet) run(sp Spec, grp *groups.Node) *Result {
	f.t.Helper()
	r, err := Run(context.Background(), f.pool, f.org, sp, grp, true, 100)
	if err != nil {
		f.t.Fatalf("%+v: %v", sp, err)
	}
	return r
}

func hosts(r *Result) string {
	var h []string
	for _, row := range r.Rows {
		h = append(h, row[0])
	}
	return strings.Join(h, ",")
}

func TestRunDevices(t *testing.T) {
	f := newFleet(t)
	base := Spec{Dataset: "devices", Columns: []string{"hostname", "site", "model", "ram_gb", "cores", "online"}}
	r := f.run(base, nil)
	if hosts(r) != "PC-A,PC-B,PC-C" || r.Total != 3 {
		t.Fatalf("only active devices, sorted by name: %v total %d", hosts(r), r.Total)
	}
	if got := strings.Join(r.Rows[0], "|"); got != "PC-A|North|Latitude|16.0|8|Yes" {
		t.Errorf("row: %s", got)
	}

	sp := base
	sp.SiteIDs = []uuid.UUID{f.sth}
	if h := hosts(f.run(sp, nil)); h != "PC-C" {
		t.Errorf("site scope: %s", h)
	}
	sp = base
	sp.Filters = []Filter{{Column: "model", Op: "eq", Value: "latitude"}, {Column: "ram_gb", Op: "ge", Value: "16"}}
	if h := hosts(f.run(sp, nil)); h != "PC-A,PC-C" {
		t.Errorf("filters: %s", h)
	}
	sp = base
	sp.Filters = []Filter{{Column: "hostname", Op: "starts_with", Value: "pc-b"}}
	if h := hosts(f.run(sp, nil)); h != "PC-B" {
		t.Errorf("starts with: %s", h)
	}
	sp = base
	sp.Filters = []Filter{{Column: "model", Op: "not_contains", Value: "lat"}}
	if h := hosts(f.run(sp, nil)); h != "PC-B" {
		t.Errorf("not contains: %s", h)
	}
	sp = base
	sp.Filters = []Filter{{Column: "last_seen", Op: "older_than_days", Value: "30"}}
	if r := f.run(sp, nil); r.Total != 3 {
		t.Errorf("older than: %d", r.Total)
	}
	sp.Filters = []Filter{{Column: "last_seen", Op: "within_days", Value: "30"}}
	if r := f.run(sp, nil); r.Total != 0 {
		t.Errorf("within: %d", r.Total)
	}
	sp = base
	sp.Sort = &Sort{Column: "ram_gb", Desc: true}
	if h := hosts(f.run(sp, nil)); h != "PC-C,PC-A,PC-B" {
		t.Errorf("numeric sort, not text sort: %s", h)
	}
	sp = base
	sp.Filters = []Filter{{Column: "hostname", Op: "contains", Value: "'; DROP TABLE devices; --"}}
	if r := f.run(sp, nil); r.Total != 0 {
		t.Errorf("a quote in a value is only a value: %d", r.Total)
	}
	var cnt int
	if err := f.pool.QueryRow(context.Background(), "SELECT count(*) FROM devices").Scan(&cnt); err != nil || cnt != 4 {
		t.Fatalf("devices table intact: %d %v", cnt, err)
	}
	if r, _ := Run(context.Background(), f.pool, f.org, base, nil, true, 2); len(r.Rows) != 2 || !r.Truncated || r.Total != 3 {
		t.Errorf("limit: %d rows, truncated=%v total=%d", len(r.Rows), r.Truncated, r.Total)
	}
	if r, err := Run(context.Background(), f.pool, uuid.New(), base, nil, true, 10); err != nil || r.Total != 0 {
		t.Errorf("another organization sees nothing: %v %v", r, err)
	}
}

func TestRunWithAGroupScope(t *testing.T) {
	f := newFleet(t)
	n, err := groups.Parse([]byte(`{"op":"device","field":"ram_bytes","cmp":"ge","value":17179869184}`))
	if err != nil {
		t.Fatal(err)
	}
	r := f.run(Spec{Dataset: "devices", Columns: []string{"hostname"}, Filters: []Filter{{Column: "model", Op: "eq", Value: "Latitude"}}}, n)
	if hosts(r) != "PC-A,PC-C" {
		t.Errorf("group scope and a filter together: %s", hosts(r))
	}
}

func TestRunDisks(t *testing.T) {
	f := newFleet(t)
	r := f.run(Spec{Dataset: "disks", Columns: []string{"hostname", "drive", "size_gb", "free_gb", "free_pct", "bitlocker"}}, nil)
	if r.Total != 6 {
		t.Fatalf("two drives on three devices: %d", r.Total)
	}
	if got := strings.Join(r.Rows[0], "|"); got != "PC-A|C:|465.7|46.6|10.0|unprotected" {
		t.Errorf("row: %s", got)
	}
	r = f.run(Spec{Dataset: "disks", Columns: []string{"hostname", "drive"}, Filters: []Filter{{Column: "free_pct", Op: "lt", Value: "15"}}}, nil)
	if r.Total != 3 {
		t.Errorf("low disk space: %d", r.Total)
	}
	r = f.run(Spec{Dataset: "disks", Columns: []string{"hostname", "drive"}, Filters: []Filter{{Column: "bitlocker", Op: "eq", Value: "protected"}}}, nil)
	if r.Total != 3 {
		t.Errorf("bitlocker: %d", r.Total)
	}
}

func TestRunSoftwareAndCounts(t *testing.T) {
	f := newFleet(t)
	var devs []uuid.UUID
	rows, _ := f.pool.Query(context.Background(), "SELECT id FROM devices WHERE status = 'active' ORDER BY hostname")
	for rows.Next() {
		var id uuid.UUID
		_ = rows.Scan(&id)
		devs = append(devs, id)
	}
	rows.Close()
	title := uuid.New()
	f.exec(`INSERT INTO software_titles (id, org_id, normalized_name, normalized_publisher, display_name, display_publisher) VALUES ($1,$2,'7-zip','igor','7-Zip','Igor Pavlov')`, title, f.org)
	for i, v := range []string{"23.01", "23.01", "24.08"} {
		f.exec(`INSERT INTO software_installs (device_id, source, scope, user_sid, item_key, title_id, name, version, version_key, first_seen_at, last_seen_at)
			VALUES ($1,'reg64','machine','','7z',$2,'7-Zip',$3,$4,now(),now())`, devs[i], title, v, vercmp.Key(v))
	}
	f.exec(`INSERT INTO software_installs (device_id, source, scope, user_sid, item_key, title_id, name, version, system_component, first_seen_at, last_seen_at)
		VALUES ($1,'reg64','machine','','vc',$2,'7-Zip',$3,true,now(),now())`, devs[0], title, "1.0")

	r := f.run(Spec{Dataset: "software", Columns: []string{"hostname", "name", "version"}, Filters: []Filter{{Column: "system_component", Op: "is", Value: "false"}}}, nil)
	if r.Total != 3 {
		t.Errorf("without Windows components: %d", r.Total)
	}
	r = f.run(Spec{Dataset: "programs", Columns: []string{"name", "publisher", "devices", "versions", "newest"}}, nil)
	if r.Total != 1 || strings.Join(r.Rows[0], "|") != "7-Zip|Igor Pavlov|3|2|24.08" {
		t.Errorf("programs: %v", r.Rows)
	}
	r = f.run(Spec{Dataset: "programs", Columns: []string{"name", "devices"}, Filters: []Filter{{Column: "devices", Op: "gt", Value: "5"}}}, nil)
	if r.Total != 0 {
		t.Errorf("filter on a count (HAVING): %d", r.Total)
	}
	r = f.run(Spec{Dataset: "versions", Columns: []string{"name", "version", "devices"}, Sort: &Sort{Column: "version"}}, nil)
	if r.Total != 2 || strings.Join(r.Rows[0], "|") != "7-Zip|23.01|2" {
		t.Errorf("versions: %v", r.Rows)
	}
	sp := Spec{Dataset: "programs", Columns: []string{"name", "devices"}, SiteIDs: []uuid.UUID{f.sth}}
	if r := f.run(sp, nil); r.Rows[0][1] != "1" {
		t.Errorf("a site scope applies before counting: %v", r.Rows)
	}
}

func TestRunPatching(t *testing.T) {
	f := newFleet(t)
	f.exec(`UPDATE devices SET wu_scanned_at = now() WHERE hostname = 'PC-A'`)
	r := f.run(Spec{Dataset: "patching", Columns: []string{"hostname", "state", "approved_missing", "critical_missing", "failed", "restart", "last_scan"}}, nil)
	if got := r.Rows[0][1]; got != "Compliant" || r.Rows[1][1] != "Not scanned lately" {
		t.Errorf("states: %v", r.Rows)
	}
	r = f.run(Spec{Dataset: "patching", Columns: []string{"hostname"}, Filters: []Filter{{Column: "state", Op: "ne", Value: "Compliant"}}}, nil)
	if hosts(r) != "PC-B,PC-C" {
		t.Errorf("needing patches: %s", hosts(r))
	}
}

func TestEveryBuiltinRunsAgainstARealDatabase(t *testing.T) {
	f := newFleet(t)
	for _, b := range Builtins() {
		if _, err := Run(context.Background(), f.pool, f.org, b.Spec, nil, true, 10); err != nil {
			t.Errorf("%s: %v", b.ID, err)
		}
	}
	for _, d := range Datasets() {
		var all []string
		for _, c := range d.Columns {
			all = append(all, c.ID)
		}
		if _, err := Run(context.Background(), f.pool, f.org, Spec{Dataset: d.ID, Columns: all}, nil, true, 10); err != nil {
			t.Errorf("%s with every column: %v", d.ID, err)
		}
		// Every column can be sorted and filtered on in every way it offers.
		for _, c := range d.Columns {
			for _, op := range Ops(c.Kind) {
				val := "1"
				switch {
				case c.Kind == KBool:
					val = "true"
				case c.Kind == KTime && (op == "before" || op == "after"):
					val = "2026-01-31"
				case c.Kind == KText:
					val = "x"
				}
				sp := Spec{Dataset: d.ID, Columns: []string{d.Columns[0].ID, c.ID}, Filters: []Filter{{Column: c.ID, Op: op, Value: val}}, Sort: &Sort{Column: c.ID, Desc: true}}
				if _, err := Run(context.Background(), f.pool, f.org, sp, nil, true, 10); err != nil {
					t.Errorf("%s.%s %s: %v", d.ID, c.ID, op, err)
				}
			}
		}
	}
}

func TestSavedReports(t *testing.T) {
	f := newFleet(t)
	st := &Store{Pool: f.pool}
	ctx := context.Background()
	sp := Spec{Dataset: "devices", Columns: []string{"hostname", "model"}, Sort: &Sort{Column: "hostname"}}
	a, err := st.Create(ctx, f.org, nil, "  Laptops  ", "", sp)
	if err != nil || a.Name != "Laptops" || a.Spec.Dataset != "devices" {
		t.Fatalf("create: %+v %v", a, err)
	}
	if _, err := st.Create(ctx, f.org, nil, "LAPTOPS", "", sp); err != ErrNameTaken {
		t.Errorf("names are unique ignoring case: %v", err)
	}
	b, err := st.Update(ctx, f.org, a.ID, "Laptops 2", "d", sp)
	if err != nil || b.Name != "Laptops 2" || b.Description != "d" {
		t.Fatalf("update: %+v %v", b, err)
	}
	if _, err := st.Update(ctx, uuid.New(), a.ID, "x", "", sp); err != ErrNotFound {
		t.Errorf("another organization cannot change it: %v", err)
	}
	if _, err := st.Get(ctx, uuid.New(), a.ID); err != ErrNotFound {
		t.Errorf("another organization cannot read it: %v", err)
	}
	if l, _ := st.List(ctx, f.org); len(l) != 1 {
		t.Errorf("list: %d", len(l))
	}
	if err := st.Delete(ctx, uuid.New(), a.ID); err != ErrNotFound {
		t.Errorf("another organization cannot delete it: %v", err)
	}
	if err := st.Delete(ctx, f.org, a.ID); err != nil {
		t.Error(err)
	}
	if err := st.Delete(ctx, f.org, a.ID); err != ErrNotFound {
		t.Errorf("twice: %v", err)
	}
}
