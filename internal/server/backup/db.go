package backup

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

const gooseTable = "goose_db_version"

// querier is satisfied by *pgx.Conn and pgx.Tx.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// connect opens one owner-role connection with session settings that make
// COPY text output and input identical regardless of server defaults.
func connect(ctx context.Context, url, app string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	rp := cfg.RuntimeParams
	rp["application_name"] = app
	rp["DateStyle"] = "ISO, MDY"
	rp["TimeZone"] = "UTC"
	rp["IntervalStyle"] = "postgres"
	rp["extra_float_digits"] = "3"
	rp["client_encoding"] = "UTF8"
	rp["bytea_output"] = "hex"
	rp["statement_timeout"] = "0"
	rp["idle_in_transaction_session_timeout"] = "0"
	rp["search_path"] = "public"
	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	return c, nil
}

func qident(parts ...string) string { return pgx.Identifier(parts).Sanitize() }

type tableInfo struct {
	oid  int64
	name string
	kind string // "table" | "partitioned"
	cols []string
}

// schemaVersion reports whether goose's version table exists and the highest applied version.
func schemaVersion(ctx context.Context, q querier) (has bool, version int64, err error) {
	if err = q.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, qident("public", gooseTable)).Scan(&has); err != nil || !has {
		return false, 0, err
	}
	// Table and sequence names come from the catalog and are quoted with pgx.Identifier; identifiers cannot be bind parameters.
	// nosemgrep: no-sql-string-building
	err = q.QueryRow(ctx, `SELECT COALESCE(max(version_id), 0) FROM `+qident("public", gooseTable)+` WHERE is_applied`).Scan(&version)
	return has, version, err
}

// discoverTables lists every table of the public schema from the catalog
// (nothing is hard-coded). Partitions are not listed: a partitioned parent
// carries its partitions' rows. Extension-owned tables and goose's version
// table are skipped.
func discoverTables(ctx context.Context, q querier) ([]tableInfo, error) {
	rows, err := q.Query(ctx, `
SELECT c.oid::bigint, c.relname, CASE c.relkind WHEN 'p' THEN 'partitioned' ELSE 'table' END
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition
  AND c.relname <> $1
  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
ORDER BY c.relname`, gooseTable)
	if err != nil {
		return nil, err
	}
	tables, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (tableInfo, error) {
		var t tableInfo
		return t, r.Scan(&t.oid, &t.name, &t.kind)
	})
	if err != nil {
		return nil, err
	}
	for i := range tables {
		// Generated (stored) columns are recomputed by the target, never copied.
		crow, err := q.Query(ctx, `SELECT attname FROM pg_attribute
WHERE attrelid = $1::bigint::oid AND attnum > 0 AND NOT attisdropped AND attgenerated = '' ORDER BY attnum`, tables[i].oid)
		if err != nil {
			return nil, err
		}
		tables[i].cols, err = pgx.CollectRows(crow, pgx.RowTo[string])
		if err != nil {
			return nil, err
		}
		if len(tables[i].cols) == 0 {
			return nil, fmt.Errorf("table %q has no copyable columns", tables[i].name)
		}
	}
	return tables, nil
}

// orderTables sorts tables so that every table comes after the tables it
// references by foreign key (self references are fine: a table is loaded
// with one COPY, which checks its constraints at the end of the statement).
// Ties are broken by name so that archives are deterministic.
func orderTables(ctx context.Context, q querier, tables []tableInfo) ([]tableInfo, error) {
	rows, err := q.Query(ctx, `
SELECT COALESCE(pg_partition_root(conrelid::regclass), conrelid::regclass)::oid::bigint,
       COALESCE(pg_partition_root(confrelid::regclass), confrelid::regclass)::oid::bigint
FROM pg_constraint WHERE contype = 'f'`)
	if err != nil {
		return nil, err
	}
	type edge struct{ child, parent int64 }
	edges, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (edge, error) {
		var e edge
		return e, r.Scan(&e.child, &e.parent)
	})
	if err != nil {
		return nil, err
	}
	byOID := map[int64]int{}
	for i, t := range tables {
		byOID[t.oid] = i
	}
	deps := make([]map[int]bool, len(tables))
	for i := range deps {
		deps[i] = map[int]bool{}
	}
	for _, e := range edges {
		c, ok1 := byOID[e.child]
		p, ok2 := byOID[e.parent]
		if ok1 && ok2 && c != p {
			deps[c][p] = true
		}
	}
	done := make([]bool, len(tables))
	out := make([]tableInfo, 0, len(tables))
	for len(out) < len(tables) {
		progressed := false
		for i := range tables { // tables are sorted by name
			if done[i] {
				continue
			}
			ready := true
			for p := range deps[i] {
				if !done[p] {
					ready = false
					break
				}
			}
			if ready {
				done[i] = true
				out = append(out, tables[i])
				progressed = true
				break // restart so that the smallest ready name goes first
			}
		}
		if !progressed {
			var stuck []string
			for i, t := range tables {
				if !done[i] {
					stuck = append(stuck, t.name)
				}
			}
			return nil, fmt.Errorf("foreign keys form a cycle between tables (%s); backup/restore cannot order them", strings.Join(stuck, ", "))
		}
	}
	return out, nil
}

func discoverSequences(ctx context.Context, q querier) ([]string, error) {
	rows, err := q.Query(ctx, `
SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'S'
  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
ORDER BY c.relname`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func readSequences(ctx context.Context, q querier, names []string) ([]SeqDef, error) {
	out := make([]SeqDef, 0, len(names))
	for _, n := range names {
		s := SeqDef{Name: n}
		// Table and sequence names come from the catalog and are quoted with pgx.Identifier; identifiers cannot be bind parameters.
		// nosemgrep: no-sql-string-building
		if err := q.QueryRow(ctx, `SELECT last_value, is_called FROM `+qident("public", n)).Scan(&s.LastValue, &s.IsCalled); err != nil {
			return nil, fmt.Errorf("read sequence %q: %w", n, err)
		}
		out = append(out, s)
	}
	return out, nil
}

// targetState describes what is in the database a restore is aimed at.
type targetState struct {
	tables   []tableInfo
	hasGoose bool
	version  int64
	rowsIn   []string // tables that contain at least one row
}

func inspectTarget(ctx context.Context, q querier) (*targetState, error) {
	st := &targetState{}
	var err error
	if st.hasGoose, st.version, err = schemaVersion(ctx, q); err != nil {
		return nil, err
	}
	if st.tables, err = discoverTables(ctx, q); err != nil {
		return nil, err
	}
	if st.rowsIn, err = tablesWithRows(ctx, q, st.tables); err != nil {
		return nil, err
	}
	return st, nil
}

func tablesWithRows(ctx context.Context, q querier, tables []tableInfo) ([]string, error) {
	var out []string
	for _, t := range tables {
		var has bool
		// Table and sequence names come from the catalog and are quoted with pgx.Identifier; identifiers cannot be bind parameters.
		// nosemgrep: no-sql-string-building
		if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM `+qident("public", t.name)+`)`).Scan(&has); err != nil {
			return nil, err
		}
		if has {
			out = append(out, t.name)
		}
	}
	return out, nil
}

// matchSchema checks that the database has exactly the tables, columns and
// sequences the archive was made from.
func matchSchema(h *Header, target []tableInfo, seqs []string) error {
	byName := map[string]tableInfo{}
	for _, t := range target {
		byName[t.name] = t
	}
	if len(byName) != len(h.Tables) {
		return fmt.Errorf("schema mismatch: the backup has %d tables, the database %d", len(h.Tables), len(byName))
	}
	for _, t := range h.Tables {
		got, ok := byName[t.Name]
		if !ok {
			return fmt.Errorf("schema mismatch: the database has no table %q", t.Name)
		}
		if got.kind != t.Kind || !slices.Equal(got.cols, t.Columns) {
			return fmt.Errorf("schema mismatch: table %q differs between the backup and the database at schema version %d", t.Name, h.SchemaVersion)
		}
	}
	have := map[string]bool{}
	for _, s := range seqs {
		have[s] = true
	}
	for _, s := range h.Sequences {
		if !have[s.Name] {
			return fmt.Errorf("schema mismatch: the database has no sequence %q", s.Name)
		}
	}
	return nil
}

func sortedNames(ts []tableInfo) []string {
	n := make([]string, len(ts))
	for i, t := range ts {
		n[i] = t.name
	}
	sort.Strings(n)
	return n
}
