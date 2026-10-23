package vulns

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

// osGroup is one Windows release and build number that devices of the organization run.
type osGroup struct {
	build   string // as devices store it: "26100.2033"
	server  bool
	product string // CPE product
	label   string
	key     []byte // sortable "10.0.<build>"
}

func (s *Store) osGroups(ctx context.Context, org uuid.UUID) ([]osGroup, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT os_build, lower(os_caption) LIKE '%server%', os_build_num FROM devices WHERE org_id = $1 AND status = 'active' AND os_build <> '' AND os_build_num > 0`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []osGroup
	for rows.Next() {
		var g osGroup
		var num int
		if err := rows.Scan(&g.build, &g.server, &num); err != nil {
			return nil, err
		}
		p, label, ok := OSProduct(g.server, num)
		if !ok {
			continue
		}
		key := vercmp.Key("10.0." + g.build)
		if key == nil {
			continue
		}
		g.product, g.label, g.key = p, label, key
		out = append(out, g)
	}
	return out, rows.Err()
}

// The hits are (device, CVE) pairs: a device has a program or a Windows build that a range of the CVE covers. Two sources feed
// them: installed programs, found through the mapping, and the Windows build of the device.
const rangeTest = `
	  AND (cr.start_key IS NULL OR %[1]s > cr.start_key OR (cr.start_incl AND %[1]s = cr.start_key))
	  AND (cr.end_key   IS NULL OR %[1]s < cr.end_key   OR (cr.end_incl   AND %[1]s = cr.end_key))`

func hitsSQL() string {
	// $6 narrows the hits to one device; NULL means every device.
	dev := " AND ($6::uuid IS NULL OR d.id = $6::uuid)"
	soft := `SELECT d.id AS device_id, cr.cve_id, st.display_name AS label, si.version AS installed,
	        CASE WHEN cr.end_key IS NOT NULL AND NOT cr.end_incl THEN cr.end_text ELSE '' END AS fixed_in,
	        st.normalized_name AS title
	 FROM devices d
	 JOIN software_installs si ON si.device_id = d.id
	 JOIN software_titles st ON st.id = si.title_id
	 JOIN cve_products m ON m.org_id = d.org_id AND m.enabled AND m.normalized_name = st.normalized_name
	 JOIN cve_ranges cr ON cr.vendor = m.vendor AND cr.product = m.product
	 WHERE d.org_id = $1 AND d.status = 'active' AND si.version_key IS NOT NULL` + strings.ReplaceAll(rangeTest, "%[1]s", "si.version_key") + dev
	os := `SELECT d.id, cr.cve_id, og.label, d.os_build, 
	        CASE WHEN cr.end_key IS NOT NULL AND NOT cr.end_incl THEN cr.end_text ELSE '' END,
	        ''
	 FROM devices d
	 JOIN unnest($2::text[], $3::bool[], $4::text[], $5::text[]) AS og(os_build, server, product, label) ON og.os_build = d.os_build AND og.server = (lower(d.os_caption) LIKE '%server%')
	 JOIN unnest($2::text[], $7::bytea[]) AS ok(os_build, key) ON ok.os_build = og.os_build
	 JOIN cve_ranges cr ON cr.vendor = 'microsoft' AND cr.product = og.product
	 WHERE d.org_id = $1 AND d.status = 'active'` + strings.ReplaceAll(rangeTest, "%[1]s", "ok.key") + dev
	return "WITH hits AS (" + soft + " UNION ALL " + os + ")"
}

// osArgs builds the arrays the hits query takes for the Windows builds.
func (s *Store) osArgs(ctx context.Context, org uuid.UUID) (builds []string, servers []bool, products, labels []string, keys [][]byte, err error) {
	gs, err := s.osGroups(ctx, org)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	builds, servers, products, labels, keys = []string{}, []bool{}, []string{}, []string{}, [][]byte{}
	for _, g := range gs {
		builds, servers, products, labels, keys = append(builds, g.build), append(servers, g.server), append(products, g.product), append(labels, g.label), append(keys, g.key)
	}
	return
}

// Item is one CVE that affects the fleet.
type Item struct {
	ID            string     `json:"id"`
	Published     *time.Time `json:"published"`
	Summary       string     `json:"summary"`
	CVSS          *float32   `json:"cvss"`
	Severity      string     `json:"severity"`
	Exploited     bool       `json:"exploited"`
	ExploitedName string     `json:"exploited_name"`
	KEVAdded      *time.Time `json:"kev_added"`
	KEVDue        *time.Time `json:"kev_due"`
	Ransomware    bool       `json:"ransomware"`
	Action        string     `json:"required_action"`
	Devices       int        `json:"devices"`
	Products      []string   `json:"products"`
	FixedIn       []string   `json:"fixed_in"`
}

// Summary counts what affects the fleet.
type Summary struct {
	CVEs      int `json:"cves"`
	Exploited int `json:"exploited"`
	Critical  int `json:"critical"`
	High      int `json:"high"`
	Devices   int `json:"devices"`
	// Covered is how many active devices have something the lookup knows about (a mapped program or a tracked Windows build).
	Covered int `json:"devices_covered"`
	Active  int `json:"devices_active"`
}

// Filter narrows the list.
type Filter struct {
	Exploited bool
	Severity  []string
	Query     string
	Limit     int
}

var severityRank = `CASE c.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END`

// Overview lists the CVEs that affect devices of the organization, the exploited ones first, then by severity and by how many
// devices have them.
func (s *Store) Overview(ctx context.Context, org uuid.UUID, f Filter) ([]Item, Summary, error) {
	builds, servers, products, labels, keys, err := s.osArgs(ctx, org)
	if err != nil {
		return nil, Summary{}, err
	}
	base := hitsSQL()
	args := func(extra ...any) []any {
		return append([]any{org, builds, servers, products, labels}, extra...)
	}
	// $6 is the device filter (none here) and $7 the sortable Windows versions.
	args6 := func() []any { return append(args(nil), keys) }

	var sum Summary
	// hitsSQL() and the text added here are all fixed strings; every value goes in as a $n parameter.
	// nosemgrep: no-sql-string-building
	err = s.Pool.QueryRow(ctx, base+`
		SELECT count(DISTINCT h.cve_id), count(DISTINCT h.cve_id) FILTER (WHERE c.kev), count(DISTINCT h.cve_id) FILTER (WHERE c.severity = 'critical'),
		       count(DISTINCT h.cve_id) FILTER (WHERE c.severity = 'high'), count(DISTINCT h.device_id)
		FROM hits h JOIN cves c ON c.id = h.cve_id`, args6()...).Scan(&sum.CVEs, &sum.Exploited, &sum.Critical, &sum.High, &sum.Devices)
	if err != nil {
		return nil, sum, err
	}
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM devices WHERE org_id = $1 AND status = 'active'`, org).Scan(&sum.Active); err != nil {
		return nil, sum, err
	}
	if err := s.Pool.QueryRow(ctx, `
		SELECT count(*) FROM devices d WHERE d.org_id = $1 AND d.status = 'active' AND (
		  EXISTS (SELECT 1 FROM software_installs si JOIN software_titles st ON st.id = si.title_id
		          JOIN cve_products m ON m.org_id = d.org_id AND m.enabled AND m.normalized_name = st.normalized_name WHERE si.device_id = d.id)
		  OR d.os_build = ANY($2::text[]))`, org, builds).Scan(&sum.Covered); err != nil {
		return nil, sum, err
	}

	limit := f.Limit
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	sevs := f.Severity
	if sevs == nil {
		sevs = []string{}
	}
	q := base + `
		SELECT c.id, c.published, c.summary, c.cvss, c.severity, c.kev, c.kev_name, c.kev_added, c.kev_due, c.kev_ransomware, c.kev_action,
		       count(DISTINCT h.device_id)::int,
		       COALESCE(array_agg(DISTINCT h.label), '{}'),
		       COALESCE(array_agg(DISTINCT h.label || ' ' || h.fixed_in) FILTER (WHERE h.fixed_in <> ''), '{}')
		FROM hits h JOIN cves c ON c.id = h.cve_id
		WHERE ($8::boolean IS NOT TRUE OR c.kev)
		  AND (cardinality($9::text[]) = 0 OR c.severity = ANY($9::text[]))
		  AND ($10::text = '' OR strpos(lower(c.id), $10) > 0 OR strpos(lower(c.summary), $10) > 0 OR strpos(lower(h.label), $10) > 0)
		GROUP BY c.id
		ORDER BY c.kev DESC, ` + severityRank + ` DESC, c.cvss DESC NULLS LAST, count(DISTINCT h.device_id) DESC, c.id
		LIMIT $11`
	rows, err := s.Pool.Query(ctx, q, append(args6(), f.Exploited, sevs, strings.ToLower(strings.TrimSpace(f.Query)), limit)...)
	if err != nil {
		return nil, sum, err
	}
	defer rows.Close()
	out := []Item{}
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.Published, &it.Summary, &it.CVSS, &it.Severity, &it.Exploited, &it.ExploitedName, &it.KEVAdded, &it.KEVDue, &it.Ransomware, &it.Action, &it.Devices, &it.Products, &it.FixedIn); err != nil {
			return nil, sum, err
		}
		out = append(out, it)
	}
	return out, sum, rows.Err()
}

// DeviceHit is one device that has a vulnerable program or Windows build.
type DeviceHit struct {
	DeviceID  uuid.UUID `json:"device_id"`
	Hostname  string    `json:"hostname"`
	Product   string    `json:"product"`
	Installed string    `json:"installed"`
	FixedIn   string    `json:"fixed_in"`
	// Title is the inventory's name for the program (empty for a Windows build); it ties the hit to the program's updates.
	Title string `json:"-"`
}

// DevicesFor lists the devices a CVE affects.
func (s *Store) DevicesFor(ctx context.Context, org uuid.UUID, cve string) ([]DeviceHit, error) {
	builds, servers, products, labels, keys, err := s.osArgs(ctx, org)
	if err != nil {
		return nil, err
	}
	// hitsSQL() and the text added here are all fixed strings; every value goes in as a $n parameter.
	// nosemgrep: no-sql-string-building
	rows, err := s.Pool.Query(ctx, hitsSQL()+`
		SELECT DISTINCT ON (h.device_id, h.label) h.device_id, d.hostname, h.label, h.installed, h.fixed_in, h.title
		FROM hits h JOIN devices d ON d.id = h.device_id WHERE h.cve_id = $8
		ORDER BY h.device_id, h.label, h.fixed_in DESC LIMIT 5000`, org, builds, servers, products, labels, nil, keys, cve)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeviceHit{}
	for rows.Next() {
		var h DeviceHit
		if err := rows.Scan(&h.DeviceID, &h.Hostname, &h.Product, &h.Installed, &h.FixedIn, &h.Title); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	sortHits(out)
	return out, rows.Err()
}

// DeviceItem is one CVE that affects a device.
type DeviceItem struct {
	Item
	Product   string `json:"product"`
	Installed string `json:"installed"`
}

// ForDevice lists the CVEs that affect one device.
func (s *Store) ForDevice(ctx context.Context, org, device uuid.UUID) ([]DeviceItem, error) {
	builds, servers, products, labels, keys, err := s.osArgs(ctx, org)
	if err != nil {
		return nil, err
	}
	// hitsSQL() and the text added here are all fixed strings; every value goes in as a $n parameter.
	// nosemgrep: no-sql-string-building
	rows, err := s.Pool.Query(ctx, hitsSQL()+`
		SELECT DISTINCT ON (c.id, h.label) c.id, c.published, c.summary, c.cvss, c.severity, c.kev, c.kev_name, c.kev_added, c.kev_due, c.kev_ransomware, c.kev_action,
		       h.label, h.installed, h.fixed_in
		FROM hits h JOIN cves c ON c.id = h.cve_id
		ORDER BY c.id, h.label, h.fixed_in DESC LIMIT 5000`, org, builds, servers, products, labels, device, keys)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeviceItem{}
	for rows.Next() {
		var it DeviceItem
		var fixed string
		if err := rows.Scan(&it.ID, &it.Published, &it.Summary, &it.CVSS, &it.Severity, &it.Exploited, &it.ExploitedName, &it.KEVAdded, &it.KEVDue, &it.Ransomware, &it.Action, &it.Product, &it.Installed, &fixed); err != nil {
			return nil, err
		}
		it.Devices = 1
		it.Products = []string{it.Product}
		if fixed != "" {
			it.FixedIn = []string{it.Product + " " + fixed}
		} else {
			it.FixedIn = []string{}
		}
		out = append(out, it)
	}
	sortDeviceItems(out)
	return out, rows.Err()
}
