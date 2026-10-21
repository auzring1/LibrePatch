package vulns

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/inventory"
	"github.com/auzring1/librepatch/internal/server/store"
)

// Errors the API maps to HTTP statuses.
var (
	ErrInvalid  = errors.New("vulns: invalid input")
	ErrNotFound = errors.New("vulns: not found")
	ErrConflict = errors.New("vulns: conflict")
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

//go:embed builtin.json
var builtinJSON []byte

// Store reads and writes the vulnerability tables.
type Store struct {
	Pool *pgxpool.Pool
	Now  func() time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// ---- CVE data ----

// UpsertCVEs stores what the NVD says. For each CVE the ranges of the products in scope are replaced by the new ones
// (ranges of other products, which another sync stored, stay); a rejected CVE is removed. The exploited marks are not touched.
func (s *Store) UpsertCVEs(ctx context.Context, cves []CVE, scope [][2]string) error {
	if len(cves) == 0 {
		return nil
	}
	vendors, products := make([]string, len(scope)), make([]string, len(scope))
	for i, p := range scope {
		vendors[i], products[i] = p[0], p[1]
	}
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, _ *dbq.Queries) error {
		b := &pgx.Batch{}
		for _, c := range cves {
			if c.Rejected {
				b.Queue(`DELETE FROM cves WHERE id = $1`, c.ID)
				continue
			}
			b.Queue(`INSERT INTO cves (id, published, modified, summary, cvss, severity) VALUES ($1,$2,$3,$4,$5,$6)
				ON CONFLICT (id) DO UPDATE SET published = EXCLUDED.published, modified = EXCLUDED.modified, summary = EXCLUDED.summary,
				    cvss = EXCLUDED.cvss, severity = EXCLUDED.severity`, c.ID, c.Published, c.Modified, c.Summary, c.CVSS, c.Severity)
			if len(scope) > 0 {
				b.Queue(`DELETE FROM cve_ranges WHERE cve_id = $1 AND (vendor, product) IN (SELECT * FROM unnest($2::text[], $3::text[]))`, c.ID, vendors, products)
			}
			for _, r := range c.Ranges {
				b.Queue(`INSERT INTO cve_ranges (cve_id, vendor, product, start_key, start_incl, start_text, end_key, end_incl, end_text) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
					c.ID, r.Vendor, r.Product, r.StartKey, r.StartIncl, r.StartText, r.EndKey, r.EndIncl, r.EndText)
			}
		}
		br := tx.SendBatch(ctx, b)
		for i := 0; i < b.Len(); i++ {
			if _, err := br.Exec(); err != nil {
				_ = br.Close()
				return err
			}
		}
		return br.Close()
	})
}

// ApplyKEV marks the CVEs of the CISA catalog as exploited and clears the mark from the ones that are no longer in it. A
// CVE the NVD data does not have yet gets a bare row, so the mark is there when the NVD data arrives.
func (s *Store) ApplyKEV(ctx context.Context, entries []KEVEntry) error {
	if len(entries) == 0 {
		return invalid("the catalog has no entries")
	}
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, _ *dbq.Queries) error {
		ids := make([]string, 0, len(entries))
		for _, e := range entries {
			ids = append(ids, e.CVE)
		}
		b := &pgx.Batch{}
		for _, e := range entries {
			b.Queue(`INSERT INTO cves (id, kev, kev_name, kev_added, kev_due, kev_ransomware, kev_action) VALUES ($1, true, $2, $3, $4, $5, $6)
				ON CONFLICT (id) DO UPDATE SET kev = true, kev_name = EXCLUDED.kev_name, kev_added = EXCLUDED.kev_added, kev_due = EXCLUDED.kev_due,
				    kev_ransomware = EXCLUDED.kev_ransomware, kev_action = EXCLUDED.kev_action`, e.CVE, e.Name, e.Added, e.Due, e.Ransomware, e.Action)
		}
		b.Queue(`UPDATE cves SET kev = false, kev_name = '', kev_added = NULL, kev_due = NULL, kev_ransomware = false, kev_action = '' WHERE kev AND NOT (id = ANY($1::text[]))`, ids)
		br := tx.SendBatch(ctx, b)
		for i := 0; i < b.Len(); i++ {
			if _, err := br.Exec(); err != nil {
				_ = br.Close()
				return err
			}
		}
		return br.Close()
	})
}

// Counts says how much data there is.
type Counts struct {
	CVEs       int `json:"cves"`
	WithRanges int `json:"cves_with_versions"`
	Exploited  int `json:"exploited"`
}

// Counts reads the size of the data.
func (s *Store) Counts(ctx context.Context) (Counts, error) {
	var c Counts
	err := s.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM cves), (SELECT count(DISTINCT cve_id) FROM cve_ranges), (SELECT count(*) FROM cves WHERE kev)`).Scan(&c.CVEs, &c.WithRanges, &c.Exploited)
	return c, err
}

// ---- product mapping ----

// Product is one line of the mapping from an installed program to a CPE product.
type Product struct {
	ID      uuid.UUID `json:"id"`
	Name    string    `json:"name"` // the normalized name inventory uses
	Vendor  string    `json:"vendor"`
	Product string    `json:"product"`
	Source  string    `json:"source"` // builtin | user
	Enabled bool      `json:"enabled"`
	Devices int       `json:"devices"` // active devices that have the program
}

// EnsureBuiltinProducts adds the mapping that ships with the product, once. A line an administrator switched off stays off.
func (s *Store) EnsureBuiltinProducts(ctx context.Context, org uuid.UUID) error {
	var f struct {
		Products []struct{ Name, Vendor, Product string } `json:"products"`
	}
	if err := json.Unmarshal(builtinJSON, &f); err != nil {
		return err
	}
	b := &pgx.Batch{}
	for _, p := range f.Products {
		b.Queue(`INSERT INTO cve_products (id, org_id, normalized_name, vendor, product, source) VALUES ($1,$2,$3,$4,$5,'builtin') ON CONFLICT (org_id, normalized_name, vendor, product) DO NOTHING`,
			uuid.New(), org, p.Name, p.Vendor, p.Product)
	}
	br := s.Pool.SendBatch(ctx, b)
	for i := 0; i < b.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return err
		}
	}
	return br.Close()
}

// ListProducts returns the mapping with how many devices have each program.
func (s *Store) ListProducts(ctx context.Context, org uuid.UUID) ([]Product, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT m.id, m.normalized_name, m.vendor, m.product, m.source, m.enabled,
		       (SELECT count(DISTINCT si.device_id) FROM software_titles st JOIN software_installs si ON si.title_id = st.id
		        JOIN devices d ON d.id = si.device_id AND d.status = 'active'
		        WHERE st.org_id = m.org_id AND st.normalized_name = m.normalized_name)::int
		FROM cve_products m WHERE m.org_id = $1 ORDER BY m.source DESC, m.normalized_name, m.vendor, m.product`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Product{}
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Name, &p.Vendor, &p.Product, &p.Source, &p.Enabled, &p.Devices); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func cleanCPEWord(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// AddProduct adds a line to the mapping: programs that inventory calls name are looked up as vendor and product in the CVE
// data. The name is normalized the way inventory normalizes it, so "Google Chrome (x64)" and "google chrome" are one.
func (s *Store) AddProduct(ctx context.Context, org uuid.UUID, name, vendor, product string) (Product, error) {
	norm := inventory.NormalizeName(name, "")
	vendor, product = cleanCPEWord(vendor), cleanCPEWord(product)
	// NormalizeName never returns an empty string: a name with nothing in it becomes "unknown".
	if strings.TrimSpace(name) == "" || norm == "unknown" || len(norm) > 200 {
		return Product{}, invalid("the program name is empty or too long")
	}
	for _, w := range []string{vendor, product} {
		if w == "" || len(w) > 100 || strings.ContainsAny(w, " \t\r\n:*?") {
			return Product{}, invalid("a vendor and a product are written the way the NVD writes them, for example google and chrome (no spaces, colons or wildcards)")
		}
	}
	id := uuid.New()
	_, err := s.Pool.Exec(ctx, `INSERT INTO cve_products (id, org_id, normalized_name, vendor, product, source) VALUES ($1,$2,$3,$4,$5,'user')`, id, org, norm, vendor, product)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return Product{}, fmt.Errorf("%w: that program is already mapped to that vendor and product", ErrConflict)
	}
	if err != nil {
		return Product{}, err
	}
	return Product{ID: id, Name: norm, Vendor: vendor, Product: product, Source: "user", Enabled: true}, nil
}

// SetProductEnabled switches a line on or off.
func (s *Store) SetProductEnabled(ctx context.Context, org, id uuid.UUID, enabled bool) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE cve_products SET enabled = $3 WHERE id = $1 AND org_id = $2`, id, org, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteProduct removes a line the administrator added; the lines that ship with the product can only be switched off.
func (s *Store) DeleteProduct(ctx context.Context, org, id uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM cve_products WHERE id = $1 AND org_id = $2 AND source = 'user'`, id, org)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Pair is a CPE product the fleet has, which the NVD sync needs to ask about.
type Pair struct {
	Vendor, Product string
	Part            string // a or o
}

// FleetPairs lists the CPE products that this organization's active devices actually have: the mapped programs that are
// installed somewhere, and the Windows releases of the devices.
func (s *Store) FleetPairs(ctx context.Context, org uuid.UUID) ([]Pair, error) {
	var out []Pair
	rows, err := s.Pool.Query(ctx, `
		SELECT DISTINCT m.vendor, m.product FROM cve_products m
		JOIN software_titles st ON st.org_id = m.org_id AND st.normalized_name = m.normalized_name
		JOIN software_installs si ON si.title_id = st.id
		JOIN devices d ON d.id = si.device_id AND d.status = 'active'
		WHERE m.org_id = $1 AND m.enabled ORDER BY 1, 2`, org)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p Pair
		if err := rows.Scan(&p.Vendor, &p.Product); err != nil {
			rows.Close()
			return nil, err
		}
		p.Part = "a"
		out = append(out, p)
	}
	rows.Close()
	osr, err := s.osGroups(ctx, org)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, g := range osr {
		if !seen[g.product] {
			seen[g.product] = true
			out = append(out, Pair{Vendor: "microsoft", Product: g.product, Part: "o"})
		}
	}
	return out, nil
}

// ---- feed state ----

// Feed is what was last fetched from one feed.
type Feed struct {
	Feed        string     `json:"feed"`
	LastOK      *time.Time `json:"last_ok"`
	LastAttempt *time.Time `json:"last_attempt"`
	Status      string     `json:"status"`
	LastError   string     `json:"last_error"`
	ETag        string     `json:"-"`
	Items       int        `json:"items"`
}

// Feeds lists the feeds with their state.
func (s *Store) Feeds(ctx context.Context) ([]Feed, error) {
	rows, err := s.Pool.Query(ctx, `SELECT feed, last_ok, last_attempt, status, last_error, etag, items FROM vuln_feeds ORDER BY feed`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Feed
	for rows.Next() {
		var f Feed
		if err := rows.Scan(&f.Feed, &f.LastOK, &f.LastAttempt, &f.Status, &f.LastError, &f.ETag, &f.Items); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// RecordFeed notes the outcome of a fetch. On success the time and item count are kept; on failure the last success stays.
func (s *Store) RecordFeed(ctx context.Context, feed string, ok bool, errText, etag string, items int) error {
	now := s.now()
	if len(errText) > 500 {
		errText = errText[:500]
	}
	if ok {
		_, err := s.Pool.Exec(ctx, `INSERT INTO vuln_feeds (feed, last_ok, last_attempt, status, last_error, etag, items) VALUES ($1,$2,$2,'ok','',$3,$4)
			ON CONFLICT (feed) DO UPDATE SET last_ok = $2, last_attempt = $2, status = 'ok', last_error = '', etag = $3, items = $4`, feed, now, etag, items)
		return err
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO vuln_feeds (feed, last_attempt, status, last_error) VALUES ($1,$2,'error',$3)
		ON CONFLICT (feed) DO UPDATE SET last_attempt = $2, status = 'error', last_error = $3`, feed, now, errText)
	return err
}
