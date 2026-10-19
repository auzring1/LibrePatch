package gateway

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/events"
	"github.com/auzring1/librepatch/internal/server/pki"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/shared/ptr"
)

const helloTimeout = 30 * time.Second

// Connect is the persistent agent stream.
func (g *Gateway) Connect(stream agentv1.AgentChannelService_ConnectServer) error {
	ctx := stream.Context()
	ident := identFrom(ctx)
	if ident == nil {
		return status.Error(codes.Unauthenticated, "no identity")
	}
	q := dbq.New(g.pool)
	dev, err := q.GetDevice(ctx, ident.DeviceID)
	if err != nil {
		return status.Error(codes.Unauthenticated, "unknown device")
	}

	// First message must be Hello for this device.
	helloCh := make(chan *agentv1.ConnectRequest, 1)
	errCh := make(chan error, 1)
	go func() {
		m, err := stream.Recv()
		if err != nil {
			errCh <- err
			return
		}
		helloCh <- m
	}()
	var hello *agentv1.Hello
	select {
	case m := <-helloCh:
		hello = m.GetHello()
	case err := <-errCh:
		return err
	case <-time.After(helloTimeout):
		return status.Error(codes.DeadlineExceeded, "hello timeout")
	}
	if hello == nil || hello.DeviceId != ident.DeviceID.String() {
		g.securityAudit(ctx, dev, "hello_identity_mismatch")
		return status.Error(codes.PermissionDenied, "hello must identify the certificate's device")
	}

	ip := peerIP(ctx)
	c := newConn(dev.ID, ident.Serial, ip, stream)
	if prev := g.hub.register(c); prev != nil {
		g.log.Warn("device connected again; closing previous stream", "device", dev.ID, "prev_ip", prev.remote, "ip", ip)
		prev.close("superseded by a newer connection")
	}
	now := g.now()
	agentVersion := cleanField(hello.AgentVersion, 64)
	if err := q.SetDeviceOnline(ctx, dbq.SetDeviceOnlineParams{ID: dev.ID, Online: true, LastIp: ip, LastSeenAt: &now, AgentVersion: agentVersion}); err != nil {
		g.log.Error("set online", "err", err)
	}
	// A device using a renewed certificate retires its older ones.
	_ = q.RevokeSupersededCerts(ctx, dbq.RevokeSupersededCertsParams{DeviceID: dev.ID, Serial: ident.Serial,
		RevokedAt: &now, NotAfter: ident.Cert.NotAfter})
	g.events.Publish(dev.OrgID, events.Event{Type: events.DeviceOnline, DeviceID: dev.ID})
	g.log.Info("agent connected", "device", dev.ID, "ip", ip, "version", agentVersion)

	defer func() {
		if g.hub.unregister(c) {
			_ = dbq.New(g.pool).SetDeviceOffline(context.Background(), dbq.SetDeviceOfflineParams{ID: dev.ID, LastSeenAt: ptr.Of(g.now())})
			g.events.Publish(dev.OrgID, events.Event{Type: events.DeviceOffline, DeviceID: dev.ID})
		}
		g.log.Info("agent disconnected", "device", dev.ID)
	}()

	ack := &agentv1.HelloAck{
		ServerTime:         now.Unix(),
		JobSigningCertsDer: [][]byte{g.authority.JobSigning.Cert.Raw},
		HeartbeatIntervalS: uint32(g.cfg.HeartbeatInterval.Seconds()),
		RenewCertificate:   renewDue(ident, g.cfg.DeviceCertLifetime, now),
	}
	if dev.HardwareRev < 0 || hello.Revs["hardware"] != uint64(dev.HardwareRev) { // #nosec G115 -- negative values handled first
		ack.ResyncSections = append(ack.ResyncSections, agentv1.InventorySection_INVENTORY_SECTION_HARDWARE)
	}
	// A revision the server does not hold (restored backup, wiped agent state,
	// lost acknowledgement) means that section must be sent in full.
	if dev.SoftwareRev < 0 || hello.Revs["software"] != uint64(dev.SoftwareRev) { // #nosec G115 -- negative values handled first
		ack.ResyncSections = append(ack.ResyncSections, agentv1.InventorySection_INVENTORY_SECTION_SOFTWARE)
	}
	if dev.UsersRev < 0 || hello.Revs["users"] != uint64(dev.UsersRev) { // #nosec G115 -- negative values handled first
		ack.ResyncSections = append(ack.ResyncSections, agentv1.InventorySection_INVENTORY_SECTION_USERS)
	}
	if rev, ok := hello.Revs["wu"]; ok && (dev.WuRev < 0 || rev != uint64(dev.WuRev)) { // #nosec G115 -- negative values handled first
		ack.ResyncSections = append(ack.ResyncSections, agentv1.InventorySection_INVENTORY_SECTION_WU)
	}
	if err := c.send(&agentv1.ConnectResponse{Msg: &agentv1.ConnectResponse_HelloAck{HelloAck: ack}}); err != nil {
		return err
	}

	// Hand over jobs queued for this device while it was offline.
	if g.deploy != nil {
		go g.deploy.Dispatch(context.WithoutCancel(ctx), dev.ID)
	}

	// Receive loop in a goroutine so a kill (revocation) ends the stream promptly.
	msgs := make(chan *agentv1.ConnectRequest)
	go func() {
		defer close(msgs)
		for {
			m, err := stream.Recv()
			if err != nil {
				if !errors.Is(err, io.EOF) && status.Code(err) != codes.Canceled {
					select {
					case errCh <- err:
					default:
					}
				}
				return
			}
			select {
			case msgs <- m:
			case <-ctx.Done():
				return
			}
		}
	}()
	for {
		select {
		case reason := <-c.kill:
			_ = c.send(&agentv1.ConnectResponse{Msg: &agentv1.ConnectResponse_GoAway{GoAway: &agentv1.GoAway{
				RetryAfterS: goAwayRetry(reason), Reason: reason}}})
			return status.Error(codes.Unavailable, reason)
		case m, ok := <-msgs:
			if !ok {
				return nil
			}
			if err := g.handle(ctx, c, dev, m); err != nil {
				g.log.Warn("agent message rejected", "device", dev.ID, "err", err)
				return err
			}
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return nil
		}
	}
}

func goAwayRetry(reason string) uint32 {
	if reason == "server shutting down" {
		return 15
	}
	return 3600
}

func renewDue(ident *pki.DeviceIdentity, lifetime time.Duration, now time.Time) bool {
	return ident.Cert.NotAfter.Sub(now) < lifetime/3
}

// restartPending is what the console, the filters and the compliance report call "restart pending": what the agent
// says Windows needs, plus files queued for deletion at the next boot when the organization's device defaults say they
// count. Those are housekeeping by installers and updaters and recur daily, so by default they do not.
func (g *Gateway) restartPending(ctx context.Context, org uuid.UUID, pending, queuedDeletes bool) bool {
	if pending {
		return true
	}
	if !queuedDeletes || g.settings == nil {
		return false
	}
	return g.settings.Peek(ctx, org, "devices").Bool("queued_deletes_need_restart")
}

func (g *Gateway) handle(ctx context.Context, c *conn, dev dbq.Device, m *agentv1.ConnectRequest) error {
	q := dbq.New(g.pool)
	now := g.now()
	switch msg := m.Msg.(type) {
	case *agentv1.ConnectRequest_Heartbeat:
		// Over the per-device limit a heartbeat is ignored, not answered with an error: a flood is the
		// device's problem, and last_seen is already fresh (SECURITY.md T-DEV-3).
		if !g.hbDevice.Allow(c.deviceID.String()) {
			return nil
		}
		hb := msg.Heartbeat
		if err := q.UpdateDeviceHeartbeat(ctx, dbq.UpdateDeviceHeartbeatParams{ID: dev.ID, LastSeenAt: &now,
			UptimeS: clampI64(hb.UptimeS), PendingReboot: g.restartPending(ctx, dev.OrgID, hb.PendingReboot, hb.QueuedFileDeletes), LoggedOnUser: cleanField(hb.LoggedOnUser, 256)}); err != nil {
			return err
		}
		g.events.Publish(dev.OrgID, events.Event{Type: events.DeviceUpdated, DeviceID: dev.ID})
	case *agentv1.ConnectRequest_Inventory:
		inv := msg.Inventory
		if inv.Section != agentv1.InventorySection_INVENTORY_SECTION_HARDWARE {
			return g.handleInventory(ctx, c, dev, inv)
		}
		if inv.GetHardware() == nil {
			return status.Error(codes.InvalidArgument, "hardware report without body")
		}
		if !g.hbDevice.Allow(c.deviceID.String()) {
			return status.Error(codes.ResourceExhausted, "hardware report rate limit")
		}
		hw := inv.GetHardware()
		if err := validateHardware(hw); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		j, err := protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}.Marshal(hw)
		if err != nil {
			return err
		}
		osBuild := ""
		if hw.OsBuild > 0 {
			osBuild = itoa(hw.OsBuild)
			if hw.OsUbr > 0 {
				osBuild += "." + itoa(hw.OsUbr)
			}
		}
		if _, err := q.UpdateDeviceHardware(ctx, dbq.UpdateDeviceHardwareParams{ID: dev.ID, Hardware: j,
			HardwareRev: clampI64(inv.Rev), HardwareUpdatedAt: &now, Hostname: cleanField(hw.Hostname, 255),
			OsCaption: cleanField(hw.OsCaption, 256), OsBuild: osBuild, Arch: cleanField(hw.Arch, 32),
			Serial: cleanField(hw.Serial, 128), PendingReboot: g.restartPending(ctx, dev.OrgID, hw.PendingReboot, hw.QueuedFileDeleteCount > 0)}); err != nil {
			return err
		}
		if err := c.send(&agentv1.ConnectResponse{Msg: &agentv1.ConnectResponse_Ack{Ack: &agentv1.Ack{Seq: inv.Seq}}}); err != nil {
			return err
		}
		g.events.Publish(dev.OrgID, events.Event{Type: events.DeviceUpdated, DeviceID: dev.ID})
	case *agentv1.ConnectRequest_JobUpdate:
		return g.handleJobUpdate(ctx, c, dev, msg.JobUpdate)
	case *agentv1.ConnectRequest_SecurityEvent:
		ev := msg.SecurityEvent
		// Each event is an audit row taking the global chain lock: acknowledge but do not record a flood.
		if !g.secDevice.Allow(c.deviceID.String()) {
			g.log.Debug("security events rate limited", "device", dev.ID)
			return c.send(&agentv1.ConnectResponse{Msg: &agentv1.ConnectResponse_Ack{Ack: &agentv1.Ack{Seq: ev.Seq}}})
		}
		_ = audit.Log(ctx, g.pool, audit.Entry{OrgID: &dev.OrgID, ActorType: audit.ActorDevice, ActorID: dev.ID.String(),
			ActorIP: c.remote, Action: "agent.security_event", TargetType: "device", TargetIDs: []string{dev.ID.String()},
			Outcome: audit.Denied, Details: map[string]any{"kind": ev.Kind.String(), "detail": cleanField(ev.Detail, 1024)}})
		g.log.Warn("agent security event", "device", dev.ID, "kind", ev.Kind.String())
		return c.send(&agentv1.ConnectResponse{Msg: &agentv1.ConnectResponse_Ack{Ack: &agentv1.Ack{Seq: ev.Seq}}})
	case *agentv1.ConnectRequest_Hello:
		return status.Error(codes.InvalidArgument, "duplicate hello")
	default:
		return status.Error(codes.InvalidArgument, "unknown message")
	}
	return nil
}

// RenewCertificate issues a new client certificate for a fresh device key.
func (g *Gateway) RenewCertificate(ctx context.Context, req *agentv1.RenewCertificateRequest) (*agentv1.RenewCertificateResponse, error) {
	ident := identFrom(ctx)
	if ident == nil {
		return nil, status.Error(codes.Unauthenticated, "no identity")
	}
	if !g.renewDevice.Allow(ident.DeviceID.String()) {
		return nil, status.Error(codes.ResourceExhausted, "renewal rate limit")
	}
	now := g.now()
	var der []byte
	var orgID uuid.UUID
	err := store.Tx(ctx, g.pool, func(tx pgx.Tx, q *dbq.Queries) error {
		d, err := q.GetDevice(ctx, ident.DeviceID)
		if err != nil || d.Status != "active" {
			return errRejected
		}
		orgID = d.OrgID
		if der, err = g.issue(ctx, q, d.ID, req.CsrDer); err != nil {
			return status.Error(codes.InvalidArgument, "invalid CSR")
		}
		_, err = audit.Write(ctx, tx, audit.Entry{OrgID: &d.OrgID, ActorType: audit.ActorDevice, ActorID: d.ID.String(),
			ActorIP: peerIP(ctx), Action: "device.certificate_renew", TargetType: "device", TargetIDs: []string{d.ID.String()},
			Outcome: audit.Success, Details: map[string]any{"previous_serial": ident.Serial, "was_expired": ident.Expired}}, now)
		return err
	})
	if err != nil {
		if s, ok := status.FromError(err); ok {
			return nil, s.Err()
		}
		g.log.Error("renew", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	g.events.Publish(orgID, events.Event{Type: events.DeviceUpdated, DeviceID: ident.DeviceID})
	return &agentv1.RenewCertificateResponse{ClientCertDer: der, IssuingCaDer: g.authority.Issuing.Cert.Raw}, nil
}

func (g *Gateway) securityAudit(ctx context.Context, dev dbq.Device, reason string) {
	_ = audit.Log(ctx, g.pool, audit.Entry{OrgID: &dev.OrgID, ActorType: audit.ActorDevice, ActorID: dev.ID.String(),
		ActorIP: peerIP(ctx), Action: "gateway.protocol_violation", TargetType: "device", TargetIDs: []string{dev.ID.String()},
		Outcome: audit.Denied, Details: map[string]any{"reason": reason}})
}
