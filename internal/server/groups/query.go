package groups

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// queryTimeout bounds one evaluation so an expensive filter cannot tie up the database.
const queryTimeout = 10 * time.Second

// Member is a device matched by a group filter.
type Member struct {
	ID            uuid.UUID  `json:"id"`
	Hostname      string     `json:"hostname"`
	Chassis       string     `json:"chassis"`
	Manufacturer  string     `json:"manufacturer"`
	Model         string     `json:"model"`
	OSCaption     string     `json:"os_caption"`
	OSBuild       string     `json:"os_build"`
	Online        bool       `json:"online"`
	LastSeenAt    *time.Time `json:"last_seen_at"`
	SoftwareCount int32      `json:"software_count"`
}

// Evaluate returns the active devices of org matching the filter (page and
// total). The generated SQL is parameterized; see Compile.
func Evaluate(ctx context.Context, pool *pgxpool.Pool, org uuid.UUID, f *Node, limit, offset int32) ([]Member, int64, error) {
	c, err := Compile(f, "$1", 2)
	if err != nil {
		return nil, 0, err
	}
	where := "d.org_id = $1 AND d.status = 'active' AND " + c.SQL
	args := append([]any{org}, c.Args...)

	var members []Member
	var total int64
	err = readOnly(ctx, pool, func(tx pgx.Tx) error {
		// `where` is built only from the filter compiler's allow-listed fragments and
		// $n placeholders; no user text reaches the SQL string (see Compile and its tests).
		// nosemgrep: no-sql-string-building
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM devices d WHERE "+where, args...).Scan(&total); err != nil { // #nosec G202
			return err
		}
		n := len(args)
		// nosemgrep: no-sql-string-building
		rows, err := tx.Query(ctx, fmt.Sprintf(`SELECT d.id, d.hostname, d.chassis, d.manufacturer, d.model, d.os_caption,
			d.os_build, d.online, d.last_seen_at, d.software_count
			FROM devices d WHERE %s ORDER BY lower(d.hostname), d.id LIMIT $%d OFFSET $%d`, where, n+1, n+2), // #nosec G201
			append(args, limit, offset)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m Member
			if err := rows.Scan(&m.ID, &m.Hostname, &m.Chassis, &m.Manufacturer, &m.Model, &m.OSCaption, &m.OSBuild,
				&m.Online, &m.LastSeenAt, &m.SoftwareCount); err != nil {
				return err
			}
			members = append(members, m)
		}
		return rows.Err()
	})
	return members, total, err
}

// readOnly runs f in a read-only transaction with a statement timeout.
func readOnly(ctx context.Context, pool *pgxpool.Pool, f func(pgx.Tx) error) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// set_config(..., true) is SET LOCAL with a bound parameter, so the SQL stays constant.
	if _, err := tx.Exec(ctx, "SELECT set_config('statement_timeout', $1, true)", strconv.FormatInt(queryTimeout.Milliseconds(), 10)); err != nil {
		return err
	}
	return f(tx)
}
