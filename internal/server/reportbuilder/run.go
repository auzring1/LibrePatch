package reportbuilder

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/internal/server/groups"
)

// Limits that keep one report, and one saved definition, small.
const (
	MaxColumns   = 40
	MaxFilters   = 20
	MaxValueLen  = 200
	MaxSites     = 200
	queryTimeout = 30 * time.Second
)

// Filter compares one column with a value. Op depends on the column's kind (see Ops).
type Filter struct {
	Column string `json:"column"`
	Op     string `json:"op"`
	Value  string `json:"value,omitempty"`
}

// Sort orders the rows by one of the shown columns.
type Sort struct {
	Column string `json:"column"`
	Desc   bool   `json:"desc,omitempty"`
}

// Spec is a whole report definition. Everything in it is checked by Validate before any SQL is built.
type Spec struct {
	Dataset string      `json:"dataset"`
	Columns []string    `json:"columns"`
	Filters []Filter    `json:"filters,omitempty"`
	SiteIDs []uuid.UUID `json:"site_ids,omitempty"`
	GroupID *uuid.UUID  `json:"group_id,omitempty"`
	Sort    *Sort       `json:"sort,omitempty"`
}

// SpecError is a problem with the definition the person sent; its text is written for them.
type SpecError struct{ Msg string }

func (e *SpecError) Error() string { return e.Msg }

func bad(format string, a ...any) error { return &SpecError{Msg: fmt.Sprintf(format, a...)} }

// Ops lists the comparisons a kind of column offers.
func Ops(k Kind) []string {
	switch k {
	case KNumber:
		return []string{"eq", "ne", "gt", "ge", "lt", "le", "is_empty", "not_empty"}
	case KBool:
		return []string{"is"}
	case KTime:
		return []string{"within_days", "older_than_days", "before", "after", "is_empty", "not_empty"}
	}
	return []string{"contains", "not_contains", "eq", "ne", "starts_with", "is_empty", "not_empty"}
}

func hasOp(k Kind, op string) bool {
	for _, o := range Ops(k) {
		if o == op {
			return true
		}
	}
	return false
}

// needsValue reports whether the comparison takes a value.
func needsValue(op string) bool { return op != "is_empty" && op != "not_empty" }

// Validate checks the definition against the dataset and returns it cleaned (columns de-duplicated, the default
// sort filled in). The returned dataset is the one the spec names.
func (sp Spec) Validate(windowsUpdates bool) (Spec, *Dataset, error) {
	ds, ok := DatasetByID(sp.Dataset)
	if !ok {
		return sp, nil, bad("Unknown kind of data %q.", sp.Dataset)
	}
	if ds.NeedsWindowsUpdates && !windowsUpdates {
		return sp, nil, bad("Windows updates are switched off for this organization, so patch data is not available.")
	}
	if len(sp.Columns) == 0 {
		return sp, nil, bad("Choose at least one column.")
	}
	if len(sp.Columns) > MaxColumns {
		return sp, nil, bad("A report can have at most %d columns.", MaxColumns)
	}
	seen := map[string]bool{}
	var cols []string
	for _, id := range sp.Columns {
		if _, ok := ds.Column(id); !ok {
			return sp, nil, bad("%q is not a column of %s.", id, ds.Label)
		}
		if !seen[id] {
			seen[id] = true
			cols = append(cols, id)
		}
	}
	sp.Columns = cols
	if len(sp.Filters) > MaxFilters {
		return sp, nil, bad("A report can have at most %d filters.", MaxFilters)
	}
	for _, f := range sp.Filters {
		c, ok := ds.Column(f.Column)
		if !ok {
			return sp, nil, bad("%q is not a column of %s.", f.Column, ds.Label)
		}
		if !hasOp(c.Kind, f.Op) {
			return sp, nil, bad("The filter on %s cannot use %q.", c.Label, f.Op)
		}
		if len(f.Value) > MaxValueLen {
			return sp, nil, bad("The filter value for %s is too long.", c.Label)
		}
		if needsValue(f.Op) {
			if _, err := filterArg(c, f); err != nil {
				return sp, nil, err
			}
		}
	}
	if len(sp.SiteIDs) > MaxSites {
		return sp, nil, bad("Too many sites chosen.")
	}
	if sp.Sort == nil || sp.Sort.Column == "" {
		def := ds.DefaultSort
		if !seen[def] {
			def = cols[0]
		}
		sp.Sort = &Sort{Column: def, Desc: ds.DefaultDesc && def == ds.DefaultSort}
	} else if !seen[sp.Sort.Column] {
		return sp, nil, bad("Sort by a column that is shown in the report.")
	}
	return sp, ds, nil
}

// filterArg checks a filter's value and returns what to bind.
func filterArg(c *Column, f Filter) (any, error) {
	v := strings.TrimSpace(f.Value)
	switch c.Kind {
	case KNumber:
		n, err := strconv.ParseFloat(v, 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || math.Abs(n) > 1e15 {
			return nil, bad("%s needs a number.", c.Label)
		}
		return strconv.FormatFloat(n, 'f', -1, 64), nil
	case KBool:
		if v != "true" && v != "false" {
			return nil, bad("%s needs yes or no.", c.Label)
		}
		return v == "true", nil
	case KTime:
		if f.Op == "within_days" || f.Op == "older_than_days" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 36500 {
				return nil, bad("%s needs a number of days.", c.Label)
			}
			return int32(n), nil // #nosec G115 -- bounded above
		}
		if _, err := time.Parse("2006-01-02", v); err != nil {
			return nil, bad("%s needs a date like 2026-01-31.", c.Label)
		}
		return v, nil
	}
	if v == "" {
		return nil, bad("%s needs a value (or choose \"is empty\").", c.Label)
	}
	return v, nil
}

// Result is the rows of a report. Every cell is already text, written the way the CSV and the PDF show it.
type Result struct {
	Columns   []ColumnInfo `json:"columns"`
	Rows      [][]string   `json:"rows"`
	Total     int64        `json:"total"`
	Truncated bool         `json:"truncated"`
}

// ColumnInfo describes a shown column.
type ColumnInfo struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  Kind   `json:"kind"`
	Width int    `json:"width"`
}

func selectExpr(c *Column) string {
	switch c.Kind {
	case KBool:
		return "CASE WHEN (" + c.expr + ") THEN 'Yes' ELSE 'No' END"
	case KTime:
		return "COALESCE(to_char((" + c.expr + ") AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI'), '')"
	}
	return "COALESCE((" + c.expr + ")::text, '')"
}

type query struct {
	args []any
}

func (q *query) bind(v any) string {
	q.args = append(q.args, v)
	return "$" + strconv.Itoa(len(q.args))
}

func filterSQL(q *query, c *Column, f Filter, arg any) string {
	e := "(" + c.expr + ")"
	switch c.Kind {
	case KNumber:
		switch f.Op {
		case "is_empty":
			return e + " IS NULL"
		case "not_empty":
			return e + " IS NOT NULL"
		}
		op := map[string]string{"eq": "=", "ne": "<>", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}[f.Op]
		return e + " " + op + " " + q.bind(arg) + "::numeric"
	case KBool:
		if arg.(bool) {
			return e + " IS TRUE"
		}
		return e + " IS NOT TRUE"
	case KTime:
		switch f.Op {
		case "is_empty":
			return e + " IS NULL"
		case "not_empty":
			return e + " IS NOT NULL"
		case "within_days":
			return e + " >= now() - make_interval(days => " + q.bind(arg) + "::int)"
		case "older_than_days":
			return "(" + e + " IS NULL OR " + e + " < now() - make_interval(days => " + q.bind(arg) + "::int))"
		case "before":
			return e + " < " + q.bind(arg) + "::date"
		default: // after
			return e + " >= " + q.bind(arg) + "::date + 1"
		}
	}
	txt := "lower(COALESCE(" + e + "::text, ''))"
	switch f.Op {
	case "is_empty":
		return txt + " = ''"
	case "not_empty":
		return txt + " <> ''"
	case "eq":
		return txt + " = lower(" + q.bind(arg) + "::text)"
	case "ne":
		return txt + " <> lower(" + q.bind(arg) + "::text)"
	case "starts_with":
		p := q.bind(arg)
		return "left(" + txt + ", length(" + p + "::text)) = lower(" + p + "::text)"
	case "not_contains":
		return "strpos(" + txt + ", lower(" + q.bind(arg) + "::text)) = 0"
	default: // contains
		return "strpos(" + txt + ", lower(" + q.bind(arg) + "::text)) > 0"
	}
}

// Run reads the report. group is the already-loaded filter of Spec.GroupID (the caller checks the group belongs to
// the organization). limit caps the rows returned; Result.Total is always the full count.
func Run(ctx context.Context, pool *pgxpool.Pool, org uuid.UUID, sp Spec, group *groups.Node, windowsUpdates bool, limit int) (*Result, error) {
	sp, ds, err := sp.Validate(windowsUpdates)
	if err != nil {
		return nil, err
	}
	q := &query{}
	orgArg := q.bind(org) // $1, which the group filter compiler relies on
	where := []string{"d.org_id = " + orgArg, "d.status = 'active'"}
	if ds.where != "" {
		where = append(where, ds.where)
	}
	if len(sp.SiteIDs) > 0 {
		where = append(where, "d.site_id = ANY("+q.bind(sp.SiteIDs)+"::uuid[])")
	}
	if group != nil {
		c, err := groups.Compile(group, orgArg, len(q.args)+1)
		if err != nil {
			return nil, bad("The chosen group's rules can no longer be used: %v", err)
		}
		q.args = append(q.args, c.Args...)
		where = append(where, "("+c.SQL+")")
	}
	var having []string
	for _, f := range sp.Filters {
		c, _ := ds.Column(f.Column)
		var arg any
		if needsValue(f.Op) {
			if arg, err = filterArg(c, f); err != nil {
				return nil, err
			}
		}
		cond := filterSQL(q, c, f, arg)
		if c.agg {
			having = append(having, cond)
		} else {
			where = append(where, cond)
		}
	}
	core := " FROM " + ds.from + " WHERE " + strings.Join(where, " AND ")
	if ds.groupBy != "" {
		core += " GROUP BY " + ds.groupBy
	}
	if len(having) > 0 {
		core += " HAVING " + strings.Join(having, " AND ")
	}

	sel := make([]string, len(sp.Columns))
	info := make([]ColumnInfo, len(sp.Columns))
	for i, id := range sp.Columns {
		c, _ := ds.Column(id)
		sel[i] = selectExpr(c)
		info[i] = ColumnInfo{ID: c.ID, Label: c.Label, Kind: c.Kind, Width: c.width}
	}
	sc, _ := ds.Column(sp.Sort.Column)
	dir := "ASC"
	if sp.Sort.Desc {
		dir = "DESC"
	}
	order := " ORDER BY (" + sc.expr + ") " + dir + " NULLS LAST, 1"
	if ds.groupBy == "" {
		order += ", d.id"
	}
	if limit <= 0 {
		limit = 1000
	}
	res := &Result{Columns: info, Rows: [][]string{}}
	err = readOnly(ctx, pool, func(tx pgx.Tx) error {
		// The SQL text is assembled only from the allow-listed expressions in datasets.go and numbered placeholders;
		// the person's values are bound arguments (see TestNoValueReachesTheSQLText).
		// nosemgrep: no-sql-string-building
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM (SELECT 1"+core+") q", q.args...).Scan(&res.Total); err != nil { // #nosec G202
			return err
		}
		// nosemgrep: no-sql-string-building
		rows, err := tx.Query(ctx, "SELECT "+strings.Join(sel, ", ")+core+order+" LIMIT "+strconv.Itoa(limit), q.args...) // #nosec G202
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			cells := make([]string, len(sel))
			ptrs := make([]any, len(sel))
			for i := range cells {
				ptrs[i] = &cells[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				return err
			}
			res.Rows = append(res.Rows, cells)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	res.Truncated = res.Total > int64(len(res.Rows))
	return res, nil
}

func readOnly(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout+5*time.Second)
	defer cancel()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", queryTimeout.Milliseconds())); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// IsSpecError reports whether err is a problem with the definition (a 400) rather than the server (a 500).
func IsSpecError(err error) bool {
	var se *SpecError
	return errors.As(err, &se)
}
