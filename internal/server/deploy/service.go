// Package deploy plans deployments into per-device jobs, signs and dispatches
// them, and tracks their results (docs/ARCHITECTURE.md §5-6).
package deploy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/catalog"
	"github.com/auzring1/librepatch/internal/server/events"
	"github.com/auzring1/librepatch/internal/server/pki"
	"github.com/auzring1/librepatch/internal/server/wingetindex"
	"github.com/auzring1/librepatch/internal/shared/envelope"
	"github.com/auzring1/librepatch/internal/shared/pkix"
)

// Dispatcher delivers a signed envelope to a connected device.
type Dispatcher interface {
	// Offer sends se to the device's live stream; false if it is not connected.
	Offer(deviceID uuid.UUID, se *agentv1.SignedEnvelope) bool
}

// Service owns deployments and jobs.
type Service struct {
	Pool       *pgxpool.Pool
	Authority  func() *pki.Authority
	Dispatcher Dispatcher
	Events     *events.Broker
	Log        *slog.Logger
	Now        func() time.Time
	// Winget is the winget community index (installed programs the catalog does not know are matched against it) and
	// Overlay the curated notes about well-known packages (which update themselves, which were tested). Both optional.
	Winget  *wingetindex.Service
	Overlay *catalog.Overlay

	// PeerCache tells whether the organization shares downloaded installers between computers (D126). nil = no.
	PeerCache func(ctx context.Context, org uuid.UUID) bool

	// AfterTerminal, if set, runs once when a job reaches a final state (Windows Update bookkeeping).
	AfterTerminal func(ctx context.Context, j dbq.Job, status string, u *agentv1.JobUpdate)

	bg sync.WaitGroup // background dispatches started by Create
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

// Errors the API maps to HTTP statuses.
var (
	ErrInvalid      = errors.New("deploy: invalid request")
	ErrNoTargets    = errors.New("deploy: no active devices match the targets")
	ErrUnverified   = errors.New("deploy: package is not verified; confirm to deploy it")
	ErrExcluded     = errors.New("deploy: package is excluded by an administrator")
	ErrSelfUpdating = errors.New("deploy: package updates itself")
	ErrNotRetryable = errors.New("deploy: only failed, expired, rejected or cancelled jobs can be retried")
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// signAndOffer signs the stored job body for dispatch and offers it to the
// device. It reports whether the device received it.
func (s *Service) signAndOffer(ctx context.Context, j dbq.Job) bool {
	auth := s.Authority()
	if auth == nil || s.Dispatcher == nil {
		return false
	}
	var env agentv1.JobEnvelope
	if err := proto.Unmarshal(j.Body, &env); err != nil {
		s.log().Error("stored job body is corrupt", "job", j.ID, "err", err)
		return false
	}
	if in := env.GetInstall(); in != nil && in.Installer != nil && s.PeerCache != nil && s.PeerCache(ctx, j.OrgID) {
		if peers := s.peerSources(ctx, j, in); len(peers) > 0 {
			in.Installer.Sources = append(peers, in.Installer.Sources...)
		}
	}
	now := s.now()
	env.IssuedAt = now.Add(-time.Minute).Unix() // tolerate small clock differences on the device
	// A job that is due now must not wait for a device whose clock runs behind ours: the agent holds a job until its own
	// clock reaches "not before", so a server clock a few minutes ahead of the PC would delay every "run now" action by
	// that long. Move it back by the skew the device already tolerates for issued_at.
	if env.NotBefore <= now.Unix() {
		env.NotBefore = now.Add(-envelope.ClockSkew).Unix()
	}
	env.Nonce = make([]byte, 16)
	_, _ = rand.Read(env.Nonce)
	key, ok := auth.JobSigning.Key.(ed25519.PrivateKey)
	if !ok {
		s.log().Error("job-signing key is not Ed25519")
		return false
	}
	se, err := envelope.Sign(key, pkix.KeyID(auth.JobSigning.Cert), &env)
	if err != nil {
		s.log().Error("sign job", "job", j.ID, "err", err)
		return false
	}
	if !s.Dispatcher.Offer(j.DeviceID, se) {
		return false
	}
	raw, _ := proto.Marshal(se)
	q := dbq.New(s.Pool)
	if err := q.MarkJobSent(ctx, dbq.MarkJobSentParams{ID: j.ID, Envelope: raw, SentAt: &now}); err != nil {
		s.log().Error("mark job sent", "job", j.ID, "err", err)
	}
	return true
}

// Dispatch offers every pending job of a device (called when it connects and
// whenever new jobs are created for a connected device), and cancellations the
// agent may not have seen.
func (s *Service) Dispatch(ctx context.Context, deviceID uuid.UUID) {
	q := dbq.New(s.Pool)
	jobs, err := q.ListDispatchableJobs(ctx, deviceID)
	if err != nil {
		s.log().Error("list dispatchable jobs", "device", deviceID, "err", err)
		return
	}
	for _, j := range jobs {
		if !s.signAndOffer(ctx, j) {
			return // not connected, or no CA yet
		}
	}
	pending, err := q.ListCancelPending(ctx, deviceID)
	if err != nil {
		return
	}
	for _, id := range pending {
		j, err := q.GetJobForDevice(ctx, dbq.GetJobForDeviceParams{ID: id, DeviceID: deviceID})
		if err != nil {
			continue
		}
		s.offerCancel(j)
	}
}

// offerCancel tells the device to drop a job it may still hold.
func (s *Service) offerCancel(j dbq.Job) {
	auth := s.Authority()
	if auth == nil || s.Dispatcher == nil {
		return
	}
	now := s.now()
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	id, _ := uuid.NewV7()
	env := &agentv1.JobEnvelope{Version: 1, JobId: id.String(), OrgId: j.OrgID.String(), DeviceId: j.DeviceID.String(),
		Type: agentv1.JobType_JOB_TYPE_CANCEL, IssuedAt: now.Add(-time.Minute).Unix(), NotBefore: now.Unix(),
		ExpiresAt: now.Add(7 * 24 * time.Hour).Unix(), Nonce: nonce, Attempt: 1,
		Body: &agentv1.JobEnvelope_Cancel{Cancel: &agentv1.CancelBody{JobId: j.ID.String()}}}
	key, ok := auth.JobSigning.Key.(ed25519.PrivateKey)
	if !ok {
		return
	}
	if se, err := envelope.Sign(key, pkix.KeyID(auth.JobSigning.Cert), env); err == nil {
		s.Dispatcher.Offer(j.DeviceID, se)
	}
}

func (s *Service) publish(org uuid.UUID, typ string, device, job, dep uuid.UUID) {
	if s.Events != nil {
		s.Events.Publish(org, events.Event{Type: typ, DeviceID: device, JobID: job, DeploymentID: dep})
	}
}

// reidentify gives a stored job body a new job ID, attempt and validity.
func reidentify(body []byte, id uuid.UUID, attempt uint32, notBefore, expires time.Time) ([]byte, error) {
	var env agentv1.JobEnvelope
	if err := proto.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	env.JobId, env.Attempt, env.NotBefore, env.ExpiresAt = id.String(), attempt, notBefore.Unix(), expires.Unix()
	return proto.MarshalOptions{Deterministic: true}.Marshal(&env)
}

// Wait blocks until background dispatches started by Create have finished (used by tests).
func (s *Service) Wait() { s.bg.Wait() }
