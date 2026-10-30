package deploy

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/events"
	"github.com/auzring1/librepatch/internal/server/store"
	"google.golang.org/protobuf/proto"
)

// ErrAlreadyRevoked: the device is already revoked or retired.
var ErrAlreadyRevoked = errors.New("deploy: the device is already revoked or retired")

// agentUninstallExpiry is how long an "uninstall the agent, then revoke" request waits for the device to come online. After that
// the request is dropped and the device stays as it was; the administrator can revoke it without the uninstall.
const agentUninstallExpiry = 30 * 24 * time.Hour

// stuckUninstallAfter is how long an agent that is uninstalling itself may stay silent before the server takes the job as done: an
// agent that removed itself cannot say so.
const stuckUninstallAfter = 10 * time.Minute

// RevokeDevice revokes a device and its certificates (the device can never connect again) and records who did it. by is nil for
// the server's own follow-up. OnRevoked cuts the live connection afterwards.
func (s *Service) RevokeDevice(ctx context.Context, org uuid.UUID, by *uuid.UUID, device uuid.UUID, reason, ip string, extra map[string]any) error {
	d, err := dbq.New(s.Pool).GetDeviceInOrg(ctx, dbq.GetDeviceInOrgParams{ID: device, OrgID: org})
	if err != nil {
		return ErrNotActive
	}
	now := s.now()
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		n, err := q.RevokeDevice(ctx, dbq.RevokeDeviceParams{ID: device, OrgID: org, StatusReason: reason, RevokedBy: by, RevokedAt: &now})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrAlreadyRevoked
		}
		if err := q.RevokeDeviceCerts(ctx, dbq.RevokeDeviceCertsParams{DeviceID: device, RevokedAt: &now, RevokeReason: reason}); err != nil {
			return err
		}
		details := map[string]any{"hostname": d.Hostname, "reason": reason}
		for k, v := range extra {
			details[k] = v
		}
		e := audit.Entry{OrgID: &org, ActorType: audit.ActorSystem, ActorID: "server", ActorIP: ip, Action: "device.revoke", TargetType: "device",
			TargetIDs: []string{device.String()}, Outcome: audit.Success, Details: details}
		if by != nil {
			e.ActorType, e.ActorID = audit.ActorUser, by.String()
		}
		_, err = audit.Write(ctx, tx, e, now)
		return err
	})
	if err != nil {
		return err
	}
	if s.OnRevoked != nil {
		s.OnRevoked(org, device)
	}
	if s.Events != nil {
		s.Events.Publish(org, events.Event{Type: events.DeviceUpdated, DeviceID: device})
	}
	return nil
}

// RequestRevokeWithUninstall tells the agent to uninstall itself and revokes the device once it has. The device is not revoked yet:
// a revoked device cannot connect, so it could no longer be told anything. An offline device gets the job when it comes online
// (for up to 30 days). The device page shows the request as pending, and "Revoke now" skips the uninstall.
func (s *Service) RequestRevokeWithUninstall(ctx context.Context, org, user, device uuid.UUID, ip, reason string) (uuid.UUID, error) {
	d, err := s.activeDevice(ctx, org, device)
	if err != nil {
		return uuid.Nil, err
	}
	q := dbq.New(s.Pool)
	if id, err := q.OpenAgentUninstall(ctx, device); err == nil {
		return id, nil // already asked
	}
	now := s.now()
	j, err := s.newJob(org, device, "", agentv1.JobType_JOB_TYPE_AGENT_UNINSTALL, "agent_uninstall", "Uninstall the agent, then revoke the device",
		&agentv1.AgentUninstallBody{Reason: reason, RequestedBy: user.String()}, now, now.Add(agentUninstallExpiry))
	if err != nil {
		return uuid.Nil, err
	}
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.InsertJob(ctx, j); err != nil {
			return err
		}
		_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &org, ActorType: audit.ActorUser, ActorID: user.String(), ActorIP: ip,
			Action: "device.revoke_requested", TargetType: "device", TargetIDs: []string{device.String()}, Outcome: audit.Success,
			Details: map[string]any{"hostname": d.Hostname, "reason": reason, "uninstall_agent": true, "online": d.Online}}, now)
		return err
	})
	if err != nil {
		return uuid.Nil, err
	}
	s.publish(org, "job.updated", device, j.ID, uuid.Nil)
	s.dispatchAsync(device)
	return j.ID, nil
}

// CancelPendingUninstall drops an "uninstall, then revoke" request that is still waiting (used before revoking right away).
func (s *Service) CancelPendingUninstall(ctx context.Context, org, user, device uuid.UUID, ip string) error {
	id, err := dbq.New(s.Pool).OpenAgentUninstall(ctx, device)
	if err != nil {
		return nil // nothing pending
	}
	return s.CancelJob(ctx, org, user, id, ip)
}

// finishUninstallRevoke revokes the device whose agent uninstalled itself, under the name of the administrator who asked.
func (s *Service) finishUninstallRevoke(ctx context.Context, org, device uuid.UUID, body []byte) {
	var env agentv1.JobEnvelope
	_ = proto.Unmarshal(body, &env)
	b := env.GetAgentUninstall()
	var by *uuid.UUID
	if u, err := uuid.Parse(b.GetRequestedBy()); err == nil {
		by = &u
	}
	reason := b.GetReason()
	if reason == "" {
		reason = "revoked by administrator"
	}
	err := s.RevokeDevice(ctx, org, by, device, reason+" (the agent uninstalled itself)", "", map[string]any{"agent_uninstalled": true})
	if err != nil && !errors.Is(err, ErrAlreadyRevoked) {
		s.log().Error("revoke after agent uninstall", "device", device, "err", err)
	}
}

// sweepAgentUninstalls revokes the devices whose agent has been uninstalling itself for a while without saying it is done.
func (s *Service) sweepAgentUninstalls(ctx context.Context) {
	rows, err := dbq.New(s.Pool).ListStuckAgentUninstalls(ctx, ptrTime(s.now().Add(-stuckUninstallAfter)))
	if err != nil {
		return
	}
	for _, r := range rows {
		s.finishUninstallRevoke(ctx, r.OrgID, r.DeviceID, r.Body)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
