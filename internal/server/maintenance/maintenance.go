// Package maintenance applies the retention and clean-up settings (Settings > Data and retention, Device defaults):
// old finished jobs, software change history, compliance snapshots and notification deliveries are deleted, and revoked devices that have
// not been seen for the configured time are removed. It runs once a day and writes what it did to the audit log. The
// audit log itself is append-only and is never pruned.
package maintenance

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/dashboard"
	"github.com/auzring1/librepatch/internal/server/settings"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/shared/ptr"
)

// Service runs the clean-up.
type Service struct {
	Pool     *pgxpool.Pool
	Settings *settings.Service
	Log      *slog.Logger
	Now      func() time.Time
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

// Result says what a run removed.
type Result struct {
	Jobs, Snapshots, Notifications, Devices, SoftwareHistory int64
}

// Run applies every retention setting once for the organization.
func (s *Service) Run(ctx context.Context, org uuid.UUID) (Result, error) {
	var res Result
	q := dbq.New(s.Pool)
	now := s.now()
	data := s.Settings.Values(ctx, org, "data")
	if days := data.Int("job_history_days"); days > 0 {
		n, err := q.PruneFinishedJobs(ctx, dbq.PruneFinishedJobsParams{OrgID: org, FinishedAt: ptr.Of(now.AddDate(0, 0, -days))})
		if err != nil {
			return res, err
		}
		res.Jobs = n
	}
	if days := data.Int("software_history_days"); days > 0 {
		n, err := s.pruneSoftwareHistory(ctx, org, now.AddDate(0, 0, -days))
		res.SoftwareHistory = n
		if err != nil {
			return res, err
		}
	}
	if days := data.Int("compliance_history_days"); days > 0 {
		n, err := q.PruneComplianceSnapshots(ctx, dashboard.Date(now.AddDate(0, 0, -days)))
		if err != nil {
			return res, err
		}
		res.Snapshots = n
	}
	if days := data.Int("notification_log_days"); days > 0 {
		n, err := q.PruneNotificationLog(ctx, now.AddDate(0, 0, -days))
		if err != nil {
			return res, err
		}
		res.Notifications = n
		_, _ = q.PruneReportRuns(ctx, now.AddDate(0, 0, -days)) // the history of scheduled reports follows the same limit
	}
	if days := s.Settings.Values(ctx, org, "devices").Int("stale_cleanup_days"); days > 0 {
		n, err := s.deleteStale(ctx, org, now.AddDate(0, 0, -days), days)
		if err != nil {
			return res, err
		}
		res.Devices = n
	}
	if res != (Result{}) {
		err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, _ *dbq.Queries) error {
			_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &org, ActorType: audit.ActorSystem, ActorID: "maintenance", Action: "maintenance.retention",
				TargetType: "settings", TargetIDs: []string{"data"}, Outcome: audit.Success,
				Details: map[string]any{"jobs": res.Jobs, "compliance_snapshots": res.Snapshots, "notifications": res.Notifications, "devices": res.Devices,
					"software_history": res.SoftwareHistory}}, now)
			return err
		})
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

// pruneSoftwareHistory deletes the organization's software change history older than before, 20,000 rows at a time
// (at most 250 batches, so a run always ends; the rest follows the next day).
func (s *Service) pruneSoftwareHistory(ctx context.Context, org uuid.UUID, before time.Time) (int64, error) {
	q := dbq.New(s.Pool)
	var total int64
	for range 250 {
		n, err := q.PruneSoftwareHistory(ctx, dbq.PruneSoftwareHistoryParams{OrgID: org, Before: before})
		total += n
		if err != nil || n < 20000 {
			return total, err
		}
	}
	return total, nil
}

// deleteStale removes revoked or retired devices not seen since before cutoff (never an active one).
func (s *Service) deleteStale(ctx context.Context, org uuid.UUID, cutoff time.Time, days int) (int64, error) {
	q := dbq.New(s.Pool)
	rows, err := q.ListStaleDevices(ctx, dbq.ListStaleDevicesParams{OrgID: org, LastSeenAt: &cutoff})
	if err != nil {
		return 0, err
	}
	var n int64
	for _, d := range rows {
		err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
			if err := q.DeleteDeviceCerts(ctx, d.ID); err != nil {
				return err
			}
			if err := q.ClearReplacesDevice(ctx, &d.ID); err != nil {
				return err
			}
			k, err := q.DeleteDevice(ctx, dbq.DeleteDeviceParams{ID: d.ID, OrgID: org})
			if err != nil || k == 0 {
				return err
			}
			n++
			_, err = audit.Write(ctx, tx, audit.Entry{OrgID: &org, ActorType: audit.ActorSystem, ActorID: "maintenance", Action: "device.delete",
				TargetType: "device", TargetIDs: []string{d.ID.String()}, Outcome: audit.Success,
				Details: map[string]any{"hostname": d.Hostname, "reason": "stale_cleanup", "days": days}}, s.now())
			return err
		})
		if err != nil {
			s.log().Error("stale device cleanup", "device", d.ID, "err", err)
		}
	}
	return n, nil
}

// Tick runs the clean-up for the organization (called once a day).
func (s *Service) Tick(ctx context.Context) {
	org, err := s.Settings.Org(ctx)
	if err != nil {
		return
	}
	if _, err := s.Run(ctx, org); err != nil {
		s.log().Error("retention", "err", err)
	}
}
