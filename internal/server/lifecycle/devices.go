package lifecycle

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Row is one active device and the lifecycle of its operating system.
type Row struct {
	DeviceID uuid.UUID
	Hostname string
	// OS is what the device reports ("Windows 11 Pro"), Version its feature version ("24H2"), Build "26100".
	OS       string
	Version  string
	Build    int
	Edition  string
	LastSeen *time.Time
	Info
}

// List returns every active device of the organization with its lifecycle, soonest end first (devices whose end is
// not known last), then by name.
func List(ctx context.Context, pool *pgxpool.Pool, org uuid.UUID, now time.Time, warnDays int) ([]Row, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, hostname, os_caption, os_build_num, COALESCE(hardware->>'os_edition', ''),
		       COALESCE(hardware->>'os_display_version', ''), last_seen_at
		FROM devices WHERE org_id = $1 AND status = 'active'`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.DeviceID, &r.Hostname, &r.OS, &r.Build, &r.Edition, &r.Version, &r.LastSeen); err != nil {
			return nil, err
		}
		r.Info = Lookup(r.OS, r.Edition, r.Build, now, warnDays)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortRows(out)
	return out, nil
}

// Summary counts devices by status.
type Summary struct {
	Supported, EndingSoon, Unsupported, Unknown int
}

// Summarize counts the rows by status.
func Summarize(rows []Row) Summary {
	var s Summary
	for _, r := range rows {
		switch r.Status {
		case Supported:
			s.Supported++
		case EndingSoon:
			s.EndingSoon++
		case Unsupported:
			s.Unsupported++
		default:
			s.Unknown++
		}
	}
	return s
}
