// Package dashboard keeps the history behind the console dashboard's patch-compliance chart: an hourly snapshot,
// per site, of how many devices are compliant, non-compliant or unknown (decision D94).
package dashboard

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/gen/dbq"
)

// StaleAfter is how old a device's last Windows Update scan may be before its compliance is "unknown".
const StaleAfter = 7 * 24 * time.Hour

// Retention is how long snapshots are kept.
const Retention = 400 * 24 * time.Hour

// Compliance states, as the reports use them.
const (
	Compliant    = "compliant"
	NonCompliant = "non_compliant"
	Unknown      = "unknown"
)

// State classifies one device from the compliance report.
func State(r dbq.ComplianceReportRow, now time.Time) string {
	if r.ApprovedMissing > 0 || r.CriticalMissing > 0 || r.FailedUpdates > 0 {
		return NonCompliant
	}
	if r.WuScannedAt == nil || now.Sub(*r.WuScannedAt) > StaleAfter {
		return Unknown
	}
	return Compliant
}

// Service writes the snapshots.
type Service struct {
	Pool *pgxpool.Pool
	Log  *slog.Logger
	Now  func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Date converts a time to the calendar day (UTC) that snapshots are keyed by.
func Date(t time.Time) pgtype.Date {
	u := t.UTC()
	return pgtype.Date{Time: time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC), Valid: true}
}

// Snapshot records today's compliance of every site of the organization. Calling it again the same day
// overwrites the row, so the last call of a day is that day's closing state.
func (s *Service) Snapshot(ctx context.Context, org uuid.UUID) error {
	q := dbq.New(s.Pool)
	rows, err := q.ComplianceReport(ctx, org)
	if err != nil {
		return err
	}
	now := s.now()
	type counts struct{ c, n, u int32 }
	bySite := map[uuid.UUID]*counts{}
	for _, r := range rows {
		c := bySite[r.SiteID]
		if c == nil {
			c = &counts{}
			bySite[r.SiteID] = c
		}
		switch State(r, now) {
		case Compliant:
			c.c++
		case NonCompliant:
			c.n++
		default:
			c.u++
		}
	}
	for site, c := range bySite {
		if err := q.UpsertComplianceSnapshot(ctx, dbq.UpsertComplianceSnapshotParams{OrgID: org, SiteID: site, TakenOn: Date(now), Compliant: c.c, NonCompliant: c.n, Unknown: c.u, TakenAt: now}); err != nil {
			return err
		}
	}
	return nil
}

// Tick snapshots every organization. The server calls it once an hour.
func (s *Service) Tick(ctx context.Context) {
	q := dbq.New(s.Pool)
	orgs, err := q.ListSnapshotOrgs(ctx)
	if err != nil {
		s.log().Error("compliance snapshot", "err", err)
		return
	}
	for _, o := range orgs {
		if ctx.Err() != nil {
			return
		}
		if err := s.Snapshot(ctx, o); err != nil {
			s.log().Error("compliance snapshot", "org", o, "err", err)
		}
	}
}

// Prune drops snapshots older than the retention period.
func (s *Service) Prune(ctx context.Context) {
	if _, err := dbq.New(s.Pool).PruneComplianceSnapshots(ctx, Date(s.now().Add(-Retention))); err != nil {
		s.log().Error("prune compliance snapshots", "err", err)
	}
}
