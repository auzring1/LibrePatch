// Package updates is the Windows Update side of the server: the update catalog built from device
// scans, approvals and auto-approval rules, rings with success thresholds, and the jobs that
// install, hide and scan (docs/ARCHITECTURE.md §6, §9).
package updates

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/events"
)

// Errors the API maps to HTTP statuses.
var (
	ErrInvalid  = errors.New("updates: invalid request")
	ErrNotFound = errors.New("updates: not found")
	ErrConflict = errors.New("updates: conflict")
	ErrOffline  = errors.New("updates: the device is offline")
	// ErrDisabled: Windows updates are switched off for the organization (Settings > Update defaults).
	ErrDisabled = errors.New("updates: Windows updates are switched off")
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Actor is who asked for something (for audit).
type Actor struct {
	Org  uuid.UUID
	User uuid.UUID
	IP   string
}

// Service owns the update catalog and its scheduling.
type Service struct {
	// OnHold, if set, is told when a ring raises a hold (the notification hook).
	OnHold func(ctx context.Context, org uuid.UUID, title, ring, reason string)

	// Enabled, if set, says whether Windows update management is switched on for an organization. Nil means on.
	Enabled func(ctx context.Context, org uuid.UUID) bool

	Pool   *pgxpool.Pool
	Deploy *deploy.Service
	Events *events.Broker
	Log    *slog.Logger
	Now    func() time.Time

	mu    sync.Mutex
	rings map[uuid.UUID]ringCache // membership of a ring's groups, refreshed every few minutes
}

type ringCache struct {
	at      time.Time
	version time.Time // the ring's updated_at when it was resolved
	members map[uuid.UUID]bool
}

// On reports whether Windows update management is switched on for the organization. When it is off nothing here scans,
// approves, schedules or installs, and what devices report about Windows updates is discarded.
func (s *Service) On(ctx context.Context, org uuid.UUID) bool {
	return s.Enabled == nil || s.Enabled(ctx, org)
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

func (s *Service) publish(org uuid.UUID, device uuid.UUID) {
	if s.Events != nil {
		s.Events.Publish(org, events.Event{Type: events.UpdatesUpdated, DeviceID: device})
	}
}

// Limits.
const (
	maxUpdatesPerSnapshot = 1000
	maxJobsPerTick        = 500
	maxUpdatesPerJob      = 50
	maxAutoFailures       = 3
	retryFailedAfter      = 24 * time.Hour
	jobLifetime           = 7 * 24 * time.Hour
	ringCacheTTL          = 5 * time.Minute
)

// Compile-time check that the hook has the shape deploy expects.
