package groups

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/shared/vercmp"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

func mustCompile(t *testing.T, js string) *Compiled {
	t.Helper()
	n, err := Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Compile(n, "$1", 2)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGoldenSQL(t *testing.T) {
	c := mustCompile(t, `{"op":"and","children":[
	  {"op":"device","field":"chassis","cmp":"eq","value":"notebook"},
	  {"op":"software","title":"Google Chrome","match":"exact","version":{"cmp":"lt","value":"130"}}]}`)
	want := "((d.chassis = $2) AND EXISTS (SELECT 1 FROM software_installs si JOIN software_titles st ON st.id = si.title_id " +
		"WHERE si.device_id = d.id AND st.org_id = $1 AND NOT si.system_component AND st.normalized_name = $3 AND si.version_key < $4))"
	if c.SQL != want {
		t.Fatalf("sql:\n got %s\nwant %s", c.SQL, want)
	}
	if len(c.Args) != 3 || c.Args[0] != "notebook" || c.Args[1] != "google chrome" {
		t.Fatalf("args: %#v", c.Args)
	}
}

func TestInjectionStaysInParameters(t *testing.T) {
	payload := `'; DROP TABLE devices; --`
	for _, js := range []string{
		`{"op":"device","field":"hostname","cmp":"eq","value":"` + payload + `"}`,
		`{"op":"device","field":"hostname","cmp":"contains","value":"` + payload + `"}`,
		`{"op":"device","field":"hostname","cmp":"in","value":["` + payload + `"]}`,
		`{"op":"software","title":"` + payload + `","publisher":"` + payload + `"}`,
	} {
		c := mustCompile(t, js)
		if strings.Contains(c.SQL, "DROP") || strings.Contains(c.SQL, "'") && !strings.Contains(c.SQL, "'[]'") && !strings.Contains(c.SQL, "'active'") {
			t.Errorf("payload leaked into SQL: %s", c.SQL)
		}
	}
	// Field names are an allow-list: nothing user-supplied becomes an identifier.
	for _, js := range []string{
		`{"op":"device","field":"hostname; DROP TABLE devices","cmp":"eq","value":"x"}`,
		`{"op":"device","field":"hardware->>'x'","cmp":"eq","value":"x"}`,
		`{"op":"device","field":"hostname","cmp":"= 'a' OR 1=1 --","value":"x"}`,
		`{"op":"software","title":"x","version":{"cmp":"lt; DROP","value":"1"}}`,
		`{"op":"device","field":"os_build","cmp":"lt","value":"1 OR 1=1"}`,
		`{"op":"device","field":"site_id","cmp":"eq","value":"not-a-uuid"}`,
		`{"op":"device","field":"disk_bitlocker","cmp":"any","value":"x' OR '1'='1"}`,
	} {
		n, err := Parse([]byte(js))
		if err == nil {
			_, err = Compile(n, "$1", 2)
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("accepted %s (err=%v)", js, err)
		}
	}
}

func TestLimitsAndShape(t *testing.T) {
	deep := `{"op":"device","field":"online","cmp":"eq","value":true}`
	for i := 0; i < MaxDepth; i++ {
		deep = `{"op":"not","children":[` + deep + `]}`
	}
	wide := `{"op":"or","children":[` + strings.TrimSuffix(strings.Repeat(`{"op":"device","field":"online","cmp":"eq","value":true},`, MaxNodes), ",") + `]}`
	long := `{"op":"device","field":"hostname","cmp":"eq","value":"` + strings.Repeat("a", MaxValueLen+1) + `"}`
	manyIn := `{"op":"device","field":"hostname","cmp":"in","value":[` + strings.TrimSuffix(strings.Repeat(`"a",`, MaxInValues+1), ",") + `]}`
	for name, js := range map[string]string{
		"too deep":        deep,
		"too many nodes":  wide,
		"long value":      long,
		"too many in":     manyIn,
		"empty and":       `{"op":"and","children":[]}`,
		"not two":         `{"op":"not","children":[{"op":"device","field":"online","cmp":"eq","value":true},{"op":"device","field":"online","cmp":"eq","value":true}]}`,
		"unknown op":      `{"op":"sql","value":"1=1"}`,
		"unknown key":     `{"op":"device","field":"online","cmp":"eq","value":true,"raw":"1=1"}`,
		"trailing":        `{"op":"device","field":"online","cmp":"eq","value":true} {}`,
		"mixed leaf/node": `{"op":"and","field":"hostname","children":[{"op":"device","field":"online","cmp":"eq","value":true}]}`,
		"bool as string":  `{"op":"device","field":"online","cmp":"eq","value":"true"}`,
		"neg number":      `{"op":"device","field":"ram_bytes","cmp":"gt","value":-1}`,
		"text ordering":   `{"op":"device","field":"hostname","cmp":"lt","value":"a"}`,
		"bad version":     `{"op":"software","title":"x","version":{"cmp":"lt","value":"???"}}`,
		"no title":        `{"op":"software","version":{"cmp":"lt","value":"1"}}`,
		"bad match":       `{"op":"software","title":"x","match":"regex"}`,
		"nul":             `{"op":"software","title":"a\u0000b"}`,
	} {
		n, err := Parse([]byte(js))
		if err == nil {
			_, err = Compile(n, "$1", 2)
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	// At the limits is fine.
	ok := `{"op":"device","field":"online","cmp":"eq","value":true}`
	for i := 0; i < MaxDepth-1; i++ {
		ok = `{"op":"not","children":[` + ok + `]}`
	}
	mustCompile(t, ok)
}

func wordOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func FuzzCompile(f *testing.F) {
	f.Add(`{"op":"software","title":"soft"}`) // "soft" is part of the table name software_installs (found by the fuzzer)
	f.Add(`{"op":"device","field":"hostname","cmp":"in","value":["a","b"]}`)
	f.Add(`{"op":"software","title":"chrome","version":{"cmp":"lt","value":"1.2"}}`)
	f.Add(`{"op":"not","children":[{"op":"device","field":"online","cmp":"eq","value":true}]}`)
	f.Fuzz(func(t *testing.T, s string) {
		n, err := Parse([]byte(s))
		if err != nil {
			return
		}
		c, err := Compile(n, "$1", 2)
		if err != nil {
			return
		}
		// Whatever compiled must not carry literals from the input. The fixed template has three quoted
		// JSON keys of its own; any other quote in the SQL would be an inlined string.
		sql := strings.NewReplacer("'disks'", "", "'[]'", "", "'bitlocker'", "").Replace(c.SQL)
		if strings.Contains(sql, "'") {
			t.Fatalf("a quoted literal in %s", c.SQL)
		}
		for _, a := range c.Args {
			// An argument made only of word characters ("soft", "from") also occurs inside the template's own
			// table and keyword names, so a substring match proves nothing for it; the quote check above covers it.
			if str, ok := a.(string); ok && len(str) > 3 && !wordOnly(str) && strings.Contains(c.SQL, str) {
				t.Fatalf("argument %q inlined into %s", str, c.SQL)
			}
		}
	})
}

func TestEvaluateAgainstDatabase(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	org, other, site := uuid.New(), uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO organizations (id, name) VALUES ($1,'a'),($2,'b')", org, other)
	exec("INSERT INTO sites (id, org_id, name) VALUES ($1,$2,'s')", site, org)
	otherSite := uuid.New()
	exec("INSERT INTO sites (id, org_id, name) VALUES ($1,$2,'s')", otherSite, other)
	chrome := uuid.New()
	exec("INSERT INTO software_titles (id, org_id, normalized_name, normalized_publisher, display_name, display_publisher) VALUES ($1,$2,'google chrome','google','Google Chrome','Google')", chrome, org)
	foreignChrome := uuid.New()
	exec("INSERT INTO software_titles (id, org_id, normalized_name, normalized_publisher, display_name, display_publisher) VALUES ($1,$2,'google chrome','google','Google Chrome','Google')", foreignChrome, other)

	type dev struct {
		name, chassis, status string
		chromeVer             string
		org, site, title      uuid.UUID
		disks                 string
	}
	devs := []dev{
		{"lap-old", "notebook", "active", "129.0.6668.1", org, site, chrome, `[{"mount":"C:","bitlocker":"unprotected"}]`},
		{"lap-new", "notebook", "active", "130.0.1", org, site, chrome, `[{"mount":"C:","bitlocker":"protected"}]`},
		{"desk-old", "desktop", "active", "100.0", org, site, chrome, `[]`},
		{"lap-none", "notebook", "active", "", org, site, chrome, `[]`},
		{"lap-revoked", "notebook", "revoked", "90.0", org, site, chrome, `[]`},
		{"foreign", "notebook", "active", "50.0", other, otherSite, foreignChrome, `[]`},
	}
	for _, d := range devs {
		id := uuid.New()
		exec(`INSERT INTO devices (id, org_id, site_id, status, hostname, hardware) VALUES ($1,$2,$3,$4,$5,
			jsonb_build_object('chassis', $6::text, 'disks', $7::jsonb))`, id, d.org, d.site, d.status, d.name, d.chassis, d.disks)
		if d.chromeVer != "" {
			exec(`INSERT INTO software_installs (device_id, source, scope, user_sid, item_key, title_id, name, version, version_key, first_seen_at, last_seen_at)
				VALUES ($1,'reg64','machine','','chrome',$2,'Google Chrome',$3,$4,now(),now())`, id, d.title, d.chromeVer, versionKey(d.chromeVer))
		}
	}
	eval := func(js string) []string {
		t.Helper()
		n, err := Parse([]byte(js))
		if err != nil {
			t.Fatal(err)
		}
		ms, total, err := Evaluate(ctx, db.Pool, org, n, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if int(total) != len(ms) {
			t.Fatalf("total %d != %d", total, len(ms))
		}
		var names []string
		for _, m := range ms {
			names = append(names, m.Hostname)
		}
		return names
	}
	same := func(got []string, want ...string) {
		t.Helper()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	// The motivating example: all laptops with Chrome older than 130.
	same(eval(`{"op":"and","children":[
		{"op":"device","field":"chassis","cmp":"eq","value":"notebook"},
		{"op":"software","title":"chrome","version":{"cmp":"lt","value":"130"}}]}`), "lap-old")
	same(eval(`{"op":"software","title":"google chrome","match":"exact","version":{"cmp":"ge","value":"130"}}`), "lap-new")
	// Not installed (and revoked/foreign devices are never members).
	same(eval(`{"op":"and","children":[{"op":"device","field":"chassis","cmp":"eq","value":"notebook"},
		{"op":"not","children":[{"op":"software","title":"chrome"}]}]}`), "lap-none")
	same(eval(`{"op":"device","field":"disk_bitlocker","cmp":"any","value":"unprotected"}`), "lap-old")
	same(eval(`{"op":"device","field":"hostname","cmp":"prefix","value":"LAP-"}`), "lap-new", "lap-none", "lap-old")
	same(eval(`{"op":"device","field":"hostname","cmp":"in","value":["desk-old","nope"]}`), "desk-old")
	same(eval(`{"op":"device","field":"hostname","cmp":"contains","value":"%"}`)) // LIKE metacharacters are literal
}

func versionKey(v string) []byte { return vercmp.Key(v) }

func TestCustomFieldFilter(t *testing.T) {
	c := mustCompile(t, `{"op":"device","field":"custom.asset_tag","cmp":"contains","value":"HQ-"}`)
	want := "(EXISTS (SELECT 1 FROM device_custom_values v WHERE v.device_id = d.id AND v.field_key = $3 AND (strpos(lower(v.value), $2) > 0)))"
	if c.SQL != want {
		t.Fatalf("sql:\n got %s\nwant %s", c.SQL, want)
	}
	ne := mustCompile(t, `{"op":"device","field":"custom.owner","cmp":"ne","value":"alice"}`)
	if !strings.HasPrefix(ne.SQL, "(NOT EXISTS") {
		t.Fatalf("ne must include devices without a value: %s", ne.SQL)
	}
	for _, bad := range []string{`custom.`, `custom.Bad Key`, `custom.x"; drop table devices; --`, `custom.` + strings.Repeat("a", 40)} {
		n, err := Parse([]byte(`{"op":"device","field":"` + strings.ReplaceAll(bad, `"`, `\"`) + `","cmp":"eq","value":"x"}`))
		if err == nil {
			_, err = Compile(n, "$1", 2)
		}
		if err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	if n, err := Parse([]byte(`{"op":"device","field":"custom.tier","cmp":"lt","value":"x"}`)); err == nil {
		if _, err := Compile(n, "$1", 2); err == nil {
			t.Error("custom fields are text: lt is not allowed")
		}
	}
}
