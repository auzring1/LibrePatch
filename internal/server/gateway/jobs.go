package gateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/shared/release"
)

const contentChunk = 256 << 10

// handleJobUpdate records a progress or result report and acknowledges it. An
// update for a job that is not this device's is ignored (and audited) but still
// acknowledged so the agent's outbox drains.
func (g *Gateway) handleJobUpdate(ctx context.Context, c *conn, dev dbq.Device, u *agentv1.JobUpdate) error {
	if !g.invAllowed(c) {
		g.securityAudit(ctx, dev, "job_update_rate_limit")
		return status.Error(codes.ResourceExhausted, "job update rate limit")
	}
	if g.deploy != nil {
		switch err := g.deploy.ApplyUpdate(ctx, dev, u); {
		case err == nil:
		case errors.Is(err, deploy.ErrUnknownJob):
			g.securityAudit(ctx, dev, "job_update_for_unknown_job")
		case errors.Is(err, deploy.ErrInvalid):
			g.securityAudit(ctx, dev, "invalid_job_update")
		default:
			g.log.Error("apply job update", "device", dev.ID, "err", err)
			return status.Error(codes.Internal, "internal error") // the agent re-sends from its outbox after reconnecting
		}
	}
	return c.send(&agentv1.ConnectResponse{Msg: &agentv1.ConnectResponse_Ack{Ack: &agentv1.Ack{Seq: u.Seq}}})
}

// fetchLimiter bounds concurrent content downloads per device.
type fetchLimiter struct {
	mu  sync.Mutex
	max int
	n   map[uuid.UUID]int
}

func newFetchLimiter(max int) *fetchLimiter { return &fetchLimiter{max: max, n: map[uuid.UUID]int{}} }

func (l *fetchLimiter) acquire(id uuid.UUID) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n[id] >= l.max {
		return false
	}
	l.n[id]++
	return true
}

func (l *fetchLimiter) release(id uuid.UUID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n[id]--; l.n[id] <= 0 {
		delete(l.n, id)
	}
}

// FetchContent streams stored installer content to a device that holds a live
// job referencing that exact hash. Devices cannot enumerate or fetch anything else.
func (g *Gateway) FetchContent(req *agentv1.FetchContentRequest, stream agentv1.AgentChannelService_FetchContentServer) error {
	ctx := stream.Context()
	ident := identFrom(ctx)
	if ident == nil {
		return status.Error(codes.Unauthenticated, "no identity")
	}
	if g.content == nil {
		return status.Error(codes.NotFound, "content storage is not configured")
	}
	if !g.fetching.acquire(ident.DeviceID) {
		return status.Error(codes.ResourceExhausted, "too many downloads in progress")
	}
	defer g.fetching.release(ident.DeviceID)
	jobID, err := uuid.Parse(req.JobId)
	if err != nil || len(req.Sha256) != 32 {
		return status.Error(codes.InvalidArgument, "bad request")
	}
	q := dbq.New(g.pool)
	job, err := q.GetJobForDevice(ctx, dbq.GetJobForDeviceParams{ID: jobID, DeviceID: ident.DeviceID})
	if err != nil {
		return status.Error(codes.NotFound, "no such job")
	}
	switch job.Status {
	case "queued", "sent", "accepted", "waiting", "running":
	default:
		return status.Error(codes.FailedPrecondition, "the job is not active")
	}
	if !g.now().Before(job.ExpiresAt) {
		return status.Error(codes.FailedPrecondition, "the job has expired")
	}
	var env agentv1.JobEnvelope
	if err := proto.Unmarshal(job.Body, &env); err != nil {
		return status.Error(codes.PermissionDenied, "that content is not part of this job")
	}
	switch {
	case env.GetInstall() != nil && env.GetInstall().Installer != nil && bytes.Equal(env.GetInstall().Installer.Sha256, req.Sha256):
		hasServer := false
		for _, s := range env.GetInstall().Installer.Sources {
			if s.Kind == agentv1.ContentSourceKind_CONTENT_SOURCE_KIND_SERVER {
				hasServer = true
			}
		}
		if !hasServer {
			return status.Error(codes.PermissionDenied, "the job does not use server content")
		}
	case env.GetAgentUpdate() != nil:
		// The agent binary named by the (vendor-signed) manifest inside this job.
		m, err := release.ParseUnverified(env.GetAgentUpdate().Manifest)
		if err != nil || !bytes.Equal(m.SHA256Bytes(), req.Sha256) {
			g.securityAudit(ctx, dbq.Device{ID: ident.DeviceID, OrgID: job.OrgID}, "content_request_not_matching_job")
			return status.Error(codes.PermissionDenied, "that content is not part of this job")
		}
	default:
		g.securityAudit(ctx, dbq.Device{ID: ident.DeviceID, OrgID: job.OrgID}, "content_request_not_matching_job")
		return status.Error(codes.PermissionDenied, "that content is not part of this job")
	}
	f, size, err := g.content.Open(job.OrgID, req.Sha256)
	if err != nil {
		return status.Error(codes.NotFound, "content not found")
	}
	defer f.Close()
	if req.Offset > uint64(size) { // #nosec G115 -- size is non-negative
		return status.Error(codes.OutOfRange, "offset beyond the end of the content")
	}
	if _, err := f.Seek(int64(req.Offset), io.SeekStart); err != nil { // #nosec G115 -- bounded by size above
		return status.Error(codes.Internal, "seek failed")
	}
	buf := make([]byte, contentChunk)
	first := true
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			ch := &agentv1.FetchContentResponse{Data: buf[:n]}
			if first {
				ch.TotalSize = uint64(size) // #nosec G115 -- non-negative
				first = false
			}
			if err := stream.Send(ch); err != nil {
				return err
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return status.Error(codes.Internal, "read failed")
		}
	}
}
