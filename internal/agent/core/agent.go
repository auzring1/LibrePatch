// Package core is the platform-independent agent: enrollment, the persistent
// mTLS stream, heartbeats, inventory reporting and certificate renewal.
package core

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/config"
	"github.com/auzring1/librepatch/internal/agent/hardware"
	"github.com/auzring1/librepatch/internal/agent/inventory"
	"github.com/auzring1/librepatch/internal/agent/jobs"
	"github.com/auzring1/librepatch/internal/agent/keystore"
	"github.com/auzring1/librepatch/internal/agent/store"
	"github.com/auzring1/librepatch/internal/shared/envelope"
	"github.com/auzring1/librepatch/internal/shared/pkix"
	"github.com/auzring1/librepatch/internal/shared/text"
)

const (
	// KeyPrefix is the default CNG key-name prefix; generation N is KeyPrefix+N.
	KeyPrefix          = brand.KeyPrefix
	maxMsg             = 4 << 20
	fullHeartbeatEvery = 30 * time.Minute
	hardwareEvery      = 6 * time.Hour
	// startupFastRetryFor and startupFastRetryMax: how long after the service starts reconnect attempts are capped, and
	// the cap.
	startupFastRetryFor = 10 * time.Minute
	startupFastRetryMax = 15 * time.Second
	healthyResetAfter   = 10 * time.Minute
	// recvBuffer bounds the server messages (acknowledgements, resync requests) queued while the stream loop is
	// busy; the receiver itself never waits for the loop to read a job offer.
	recvBuffer = 256
)

// Agent is one running agent instance.
type Agent struct {
	Cfg     *config.Config
	CfgPath string
	DataDir string
	Store   *store.Store
	Keys    keystore.Provider
	HW      hardware.Collector
	// Inv reports software and user inventory; nil disables it.
	Inv *inventory.Manager
	// Jobs runs verified jobs; nil disables job execution (jobs are then rejected).
	Jobs *jobs.Engine
	// Changes delivers raw change notifications (registry watcher); may be nil.
	Changes <-chan struct{}
	Log     *slog.Logger
	Version string
	// KeyPrefix overrides the device key name prefix (tests use unique ones).
	KeyPrefix string
	// Tunables (overridable in tests).
	BackoffBase, BackoffMax time.Duration
	PendingPoll             time.Duration
	Now                     func() time.Time
	// InvQuiet is the debounce period after a change notification (default 30s);
	// ReconcileEvery is the safety-net full rescan interval (default 24h).
	InvQuiet, ReconcileEvery time.Duration

	outKick chan struct{} // wakes the stream loop to send queued outbox messages
	invNow  chan struct{} // requests an immediate software rescan
	wuKick  chan struct{} // a new Windows Update snapshot is waiting to be sent
	sentMu  sync.Mutex
	sent    map[uint64]bool // outbox entries already sent on the current stream
	// offerMu serializes job-offer handling: offers are processed on the receive path of the current stream, and the
	// previous stream's receiver may still be finishing one while a new stream starts.
	offerMu sync.Mutex
	clMu    sync.Mutex
	client  agentv1.AgentChannelServiceClient // current connection, for content downloads

	bootID      string
	clockOffset atomic.Int64 // nanoseconds; written on connect, read by the job engine's clock
	lastHB      *agentv1.Heartbeat
	lastHBSent  time.Time
	hwPending   *pendingReport
	wuPending   *pendingReport
	wuMu        sync.Mutex
	wuSnap      *agentv1.WuInventory
	wuRev       uint64
}

func (a *Agent) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Agent) keyPrefix() string {
	if a.KeyPrefix != "" {
		return a.KeyPrefix
	}
	return KeyPrefix
}

func (a *Agent) status(state, msg, deviceID string) {
	WriteStatus(a.DataDir, Status{State: state, Message: msg, DeviceID: deviceID, Server: a.Cfg.Server, Version: a.Version})
}

// Run blocks until ctx is cancelled, enrolling first if necessary.
func (a *Agent) Run(ctx context.Context) error {
	if a.BackoffBase == 0 {
		a.BackoffBase = time.Second
	}
	if a.BackoffMax == 0 {
		a.BackoffMax = 5 * time.Minute
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	a.bootID = hex.EncodeToString(b)
	a.outKick, a.invNow, a.wuKick = make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{}, 1)
	a.startJobs(ctx)
	a.status("starting", "", "")
	// For the first minutes after the service starts (usually a computer that is still starting up, with no network yet)
	// retries stay short, so the device shows as online soon after its network does.
	bo := &Backoff{Base: a.BackoffBase, Max: a.BackoffMax, Start: a.now(), FastFor: startupFastRetryFor, FastMax: startupFastRetryMax}
	for ctx.Err() == nil {
		id, err := a.Store.Identity()
		if err != nil {
			return fmt.Errorf("read identity: %w", err)
		}
		var wait time.Duration
		switch {
		case id == nil:
			wait, err = a.enroll(ctx)
		case id.Status == "pending":
			wait, err = a.pollApproval(ctx, id)
		case id.Status == "rejected":
			a.status("rejected", "Enrollment was rejected or the device was revoked. Reinstall with a new token.", id.DeviceID)
			wait = 6 * time.Hour
		default:
			var healthy time.Duration
			healthy, wait, err = a.session(ctx, id)
			if healthy >= healthyResetAfter {
				bo.Reset()
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			if wait == 0 {
				wait = bo.Next()
			}
			a.Log.Warn("agent cycle failed; retrying", "err", err, "retry_in", wait.Round(time.Second))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
	return nil
}

// enroll performs first contact. Returns how long to wait before the next step.
func (a *Agent) enroll(ctx context.Context) (time.Duration, error) {
	if a.Cfg.EnrollmentToken == "" {
		a.status("error", "Not enrolled and no enrollment token is configured. Reinstall with --token.", "")
		return time.Hour, errors.New("no enrollment token")
	}
	a.status("enrolling", "", "")
	// Create the device key first; reuse a key created by an interrupted attempt.
	keyName := a.keyPrefix() + "1"
	key, err := a.Keys.Open(keyName)
	provider := "existing"
	if errors.Is(err, keystore.ErrNotFound) {
		key, provider, err = a.Keys.Create(keyName)
	}
	if err != nil {
		a.status("error", "Could not create the device key: "+err.Error(), "")
		return 0, fmt.Errorf("device key: %w", err)
	}
	a.Log.Info("device key ready", "provider", provider)
	csr, err := keystore.CSR(key)
	if err != nil {
		return 0, err
	}
	hw, _ := a.HW.Collect(ctx)
	if hw == nil {
		hw = &agentv1.HardwareInventory{}
	}
	tc, err := pinnedTLS(a.Cfg.Server, a.Cfg.RootPin)
	if err != nil {
		return 0, err
	}
	conn, err := a.dial(tc)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	resp, err := agentv1.NewEnrollmentServiceClient(conn).Enroll(cctx, &agentv1.EnrollRequest{
		Token: a.Cfg.EnrollmentToken, CsrDer: csr, Hostname: hw.Hostname, SmbiosUuid: hw.SmbiosUuid,
		Serial: hw.Serial, OsBuild: strconv.FormatUint(uint64(hw.OsBuild), 10), Arch: hw.Arch, AgentVersion: a.Version,
	})
	if err != nil {
		if status.Code(err) == codes.PermissionDenied {
			a.status("error", "The server rejected the enrollment token (expired, revoked or used up). Create a new token and reinstall.", "")
			return time.Hour, err
		}
		if status.Code(err) == codes.FailedPrecondition {
			// The server understood the request but will not enroll this device. Say so plainly: the
			// installer prints this message. Retry slowly, an administrator may change something meanwhile.
			a.status("error", "The server refused to enroll this device: "+status.Convert(err).Message(), "")
			return jitter(15*time.Minute, 5*time.Minute), err
		}
		a.status("error", "Enrollment failed: "+err.Error(), "")
		return 0, err
	}
	return a.applyEnrollResult(resp.GetResult(), keyName)
}

func (a *Agent) applyEnrollResult(r *agentv1.EnrollResult, keyName string) (time.Duration, error) {
	if r == nil {
		return 0, errors.New("empty enrollment result")
	}
	// The root delivered by the server must match our pin.
	var rootDER []byte
	if len(r.RootCaDer) > 0 {
		root, err := x509.ParseCertificate(r.RootCaDer)
		if err != nil || pkix.SPKIPin(root) != a.Cfg.RootPin {
			return time.Hour, errors.New("server sent a root CA that does not match the pin")
		}
		rootDER = r.RootCaDer
	}
	id, _ := a.Store.Identity()
	if id == nil {
		id = &store.Identity{KeyName: keyName, KeyGen: 1}
	}
	id.DeviceID, id.OrgID = r.DeviceId, r.OrgId
	if rootDER != nil {
		id.RootDER = rootDER
	}
	if len(r.IssuingCaDer) > 0 {
		id.IssuingDER = r.IssuingCaDer
	}
	if len(r.JobSigningCertsDer) > 0 {
		id.SigningDER = r.JobSigningCertsDer
	}
	switch r.Status {
	case agentv1.EnrollStatus_ENROLL_STATUS_APPROVED:
		if _, err := x509.ParseCertificate(r.ClientCertDer); err != nil {
			return 0, fmt.Errorf("invalid client certificate: %w", err)
		}
		id.Status, id.Ticket, id.CertDER = "active", "", r.ClientCertDer
	case agentv1.EnrollStatus_ENROLL_STATUS_PENDING:
		id.Status, id.Ticket = "pending", r.Ticket
	case agentv1.EnrollStatus_ENROLL_STATUS_REJECTED:
		id.Status, id.Ticket = "rejected", ""
	default:
		return 0, errors.New("unknown enrollment status")
	}
	if err := a.Store.SaveIdentity(id); err != nil {
		return 0, err
	}
	// The token is single-purpose: erase it once the server has our identity.
	if a.Cfg.EnrollmentToken != "" {
		a.Cfg.EnrollmentToken = ""
		if a.CfgPath != "" {
			if err := config.Save(a.CfgPath, a.Cfg); err != nil {
				a.Log.Error("could not erase enrollment token from config", "err", err)
			}
		}
	}
	switch id.Status {
	case "active":
		a.Log.Info("enrolled", "device_id", id.DeviceID)
		a.status("connecting", "", id.DeviceID)
		return 0, nil
	case "pending":
		a.Log.Info("enrollment pending administrator approval", "device_id", id.DeviceID)
		a.status("pending_approval", "Waiting for an administrator to approve this device in the console.", id.DeviceID)
		return a.pendingWait(r.RetryAfterS), nil
	default:
		a.status("rejected", "Enrollment was rejected.", id.DeviceID)
		return 6 * time.Hour, nil
	}
}

func (a *Agent) pendingWait(serverHint uint32) time.Duration {
	d := a.PendingPoll
	if d == 0 {
		d = time.Duration(serverHint) * time.Second
		if d < 15*time.Second || d > time.Hour {
			d = 60 * time.Second
		}
	}
	return jitter(d, d/3)
}

func (a *Agent) pollApproval(ctx context.Context, id *store.Identity) (time.Duration, error) {
	a.status("pending_approval", "Waiting for an administrator to approve this device in the console.", id.DeviceID)
	tc, err := pinnedTLS(a.Cfg.Server, a.Cfg.RootPin)
	if err != nil {
		return 0, err
	}
	conn, err := a.dial(tc)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := agentv1.NewEnrollmentServiceClient(conn).EnrollStatus(cctx, &agentv1.EnrollStatusRequest{Ticket: id.Ticket})
	if err != nil {
		if status.Code(err) == codes.PermissionDenied {
			id.Status, id.Ticket = "rejected", ""
			_ = a.Store.SaveIdentity(id)
			return 0, nil
		}
		return a.pendingWait(0), err
	}
	return a.applyEnrollResult(resp.GetResult(), id.KeyName)
}

func (a *Agent) dial(tc *tls.Config) (*grpc.ClientConn, error) {
	return grpc.NewClient("passthrough:///"+a.Cfg.Server, DialOptions(tc)...)
}

// DialOptions are the gRPC client options of the real agent (TLS credentials, keepalive, message
// limits). The load generator uses them so its connections behave like the agent's.
func DialOptions(tc *tls.Config) []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tc)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 90 * time.Second, Timeout: 20 * time.Second, PermitWithoutStream: true}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMsg), grpc.MaxCallSendMsgSize(maxMsg)),
	}
}

// goAway carries the server's retry hint out of a session.
type goAway struct {
	reason string
}

func (g *goAway) Error() string { return "server closed the stream: " + g.reason }

// session runs one connected stream. It returns how long it was healthy and,
// if the server asked, how long to wait before reconnecting.
func (a *Agent) session(ctx context.Context, id *store.Identity) (time.Duration, time.Duration, error) {
	a.status("connecting", "", id.DeviceID)
	root, err := x509.ParseCertificate(id.RootDER)
	if err != nil || pkix.SPKIPin(root) != a.Cfg.RootPin {
		return 0, time.Hour, errors.New("stored root CA does not match the configured pin")
	}
	cert, err := x509.ParseCertificate(id.CertDER)
	if err != nil {
		return 0, time.Hour, fmt.Errorf("stored certificate: %w", err)
	}
	key, err := a.Keys.Open(id.KeyName)
	if err != nil {
		return 0, time.Hour, fmt.Errorf("open device key %s: %w", id.KeyName, err)
	}
	tc, err := mutualTLS(a.Cfg.Server, root, id.CertDER, id.IssuingDER, key)
	if err != nil {
		return 0, 0, err
	}
	conn, err := a.dial(tc)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = conn.Close() }()
	client := agentv1.NewAgentChannelServiceClient(conn)
	a.setClient(client)
	defer a.setClient(nil)

	// Expired certificate inside the grace period: renew first.
	if a.now().After(cert.NotAfter) {
		if err := a.renew(ctx, client, id); err != nil {
			return 0, 0, fmt.Errorf("renew expired certificate: %w", err)
		}
		return 0, time.Second, nil
	}

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := client.Connect(sctx)
	if err != nil {
		return 0, 0, err
	}
	revs := map[string]uint64{"hardware": a.Store.GetUint("hw_rev")}
	caps := []string{"hardware"}
	if a.Jobs != nil {
		revs["wu"] = a.Store.GetUint("wu_rev")
		caps = append(caps, "wu/v1")
	}
	if a.Inv != nil {
		a.Inv.ResetPending() // acknowledgements of the previous stream can never arrive
		revs["software"], revs["users"] = a.Inv.SoftwareRev(), a.Inv.UsersRev()
		caps = append(caps, "software", "users")
	}
	if a.Jobs != nil {
		caps = append(caps, "jobs/v1")
	}
	a.hwPending, a.wuPending = nil, nil
	if err := stream.Send(&agentv1.ConnectRequest{Msg: &agentv1.ConnectRequest_Hello{Hello: &agentv1.Hello{
		DeviceId: id.DeviceID, AgentVersion: a.Version, BootId: a.bootID, Capabilities: caps,
		Revs: revs, OutboxPending: uint32(a.Store.OutboxLen()), // #nosec G115
		CertNotAfter: cert.NotAfter.Unix(),
	}}}); err != nil {
		return 0, 0, err
	}
	first, err := stream.Recv()
	if err != nil {
		return 0, a.retryHint(err), err
	}
	ack := first.GetHelloAck()
	if ack == nil {
		if ga := first.GetGoAway(); ga != nil {
			return 0, jitter(time.Duration(ga.RetryAfterS)*time.Second, 30*time.Second), &goAway{reason: ga.Reason}
		}
		return 0, 0, errors.New("expected HelloAck")
	}
	start := a.now()
	off := time.Unix(ack.ServerTime, 0).Sub(start)
	a.clockOffset.Store(int64(off))
	if d := off; d > 5*time.Minute || d < -5*time.Minute {
		a.Log.Warn("local clock differs from server", "offset", d.Round(time.Second))
	}
	a.acceptSigningCerts(ctx, stream, id, root, ack.JobSigningCertsDer)

	// Read the stream from now on, before the first hardware and software inventory (which can take many seconds on
	// a PC that has just started). Job offers are verified and handed to the job engine right here, so a command that
	// arrives while the agent is busy with inventory is accepted at once; every other message waits for the loop below.
	msgs := make(chan *agentv1.ConnectResponse, recvBuffer)
	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			if offer := m.GetJobOffer(); offer != nil {
				a.handleJobOffer(stream, id, root, offer)
				continue
			}
			select {
			case msgs <- m:
			case <-sctx.Done():
				return
			}
		}
	}()
	a.Log.Info("connected", "server", a.Cfg.Server, "device_id", id.DeviceID)
	a.status("connected", "", id.DeviceID)
	if a.Jobs != nil {
		a.Jobs.SelfUpdateHealthy() // a freshly updated agent proves itself by completing this handshake
	}

	if ack.RenewCertificate || a.renewDue(cert) {
		if err := a.renew(ctx, client, id); err != nil {
			a.Log.Error("certificate renewal failed; will retry", "err", err)
		} else {
			// Reconnect promptly with the new certificate.
			return a.now().Sub(start), time.Second, nil
		}
	}

	// Resend anything still queued (security events) from previous sessions.
	if err := a.flushOutbox(stream); err != nil {
		return 0, 0, err
	}
	forceHW, forceWU := false, false
	var invOpt inventory.SyncOptions
	for _, sec := range ack.ResyncSections {
		switch sec {
		case agentv1.InventorySection_INVENTORY_SECTION_HARDWARE:
			forceHW = true
		case agentv1.InventorySection_INVENTORY_SECTION_SOFTWARE:
			invOpt.FullSoftware = true
		case agentv1.InventorySection_INVENTORY_SECTION_USERS:
			invOpt.FullUsers = true
		case agentv1.InventorySection_INVENTORY_SECTION_WU:
			forceWU = true
		}
	}
	if a.hwPending, err = a.sendHardware(ctx, stream, forceHW); err != nil {
		return a.now().Sub(start), 0, err
	}
	if wp, err := a.sendWU(stream, forceWU); err != nil {
		return a.now().Sub(start), 0, err
	} else if wp != nil {
		a.wuPending = wp
	}
	invDirty := false
	runInv := func(o inventory.SyncOptions) error { return a.syncInventory(ctx, stream, o, &invDirty) }
	if err := runInv(invOpt); err != nil {
		return a.now().Sub(start), 0, err
	}

	hbEvery := time.Duration(ack.HeartbeatIntervalS) * time.Second
	if hbEvery < 10*time.Second || hbEvery > time.Hour {
		hbEvery = 5 * time.Minute
	}
	hbTick := time.NewTicker(hbEvery)
	defer hbTick.Stop()
	hwTick := time.NewTicker(hardwareEvery)
	defer hwTick.Stop()
	// Renewal is checked on its own timer, scaled to the certificate lifetime.
	renewEvery := min(max(pkix.Lifetime(cert)/10, time.Second), time.Hour)
	renewTick := time.NewTicker(renewEvery)
	defer renewTick.Stop()
	// Change notifications are debounced; the daily reconcile is a safety net.
	invTrig := a.startInventoryTriggers(sctx)
	reconcile := a.ReconcileEvery
	if reconcile <= 0 {
		reconcile = 24 * time.Hour
	}
	reconcileTick := time.NewTicker(jitter(reconcile, reconcile/12))
	defer reconcileTick.Stop()
	if err := a.sendHeartbeat(ctx, stream, true); err != nil {
		return a.now().Sub(start), 0, err
	}

	for {
		select {
		case <-ctx.Done():
			_ = stream.CloseSend()
			return a.now().Sub(start), 0, nil
		case err := <-recvErr:
			return a.now().Sub(start), a.retryHint(err), err
		case <-hbTick.C:
			if err := a.sendHeartbeat(ctx, stream, false); err != nil {
				return a.now().Sub(start), 0, err
			}
		case <-a.outKick:
			if err := a.sendQueued(stream); err != nil {
				return a.now().Sub(start), 0, err
			}
		case <-a.wuKick:
			if wp, err := a.sendWU(stream, false); err != nil {
				return a.now().Sub(start), 0, err
			} else if wp != nil {
				a.wuPending = wp
			}
		case <-a.invNow:
			// A refresh (console button, or after an install): software and users, hardware if it
			// changed, and a heartbeat with the current uptime, reboot state and signed-in user.
			if err := runInv(inventory.SyncOptions{}); err != nil {
				return a.now().Sub(start), 0, err
			}
			if hw, err := a.sendHardware(ctx, stream, false); err != nil {
				return a.now().Sub(start), 0, err
			} else if hw != nil {
				a.hwPending = hw
			}
			if err := a.sendHeartbeat(ctx, stream, true); err != nil {
				return a.now().Sub(start), 0, err
			}
		case <-renewTick.C:
			if a.renewDue(cert) {
				if err := a.renew(ctx, client, id); err != nil {
					a.Log.Error("certificate renewal failed; will retry", "err", err)
				} else {
					return a.now().Sub(start), time.Second, nil
				}
			}
		case <-hwTick.C:
			if a.hwPending, err = a.sendHardware(ctx, stream, false); err != nil {
				return a.now().Sub(start), 0, err
			}
		case <-invTrig:
			if err := runInv(inventory.SyncOptions{}); err != nil {
				return a.now().Sub(start), 0, err
			}
		case <-reconcileTick.C:
			if err := runInv(inventory.SyncOptions{}); err != nil {
				return a.now().Sub(start), 0, err
			}
		case m := <-msgs:
			switch msg := m.Msg.(type) {
			case *agentv1.ConnectResponse_Ack:
				a.handleAck(msg.Ack.Seq)
				if invDirty && a.Inv != nil && !a.Inv.Busy() {
					invDirty = false
					if err := runInv(inventory.SyncOptions{}); err != nil {
						return a.now().Sub(start), 0, err
					}
				}
			case *agentv1.ConnectResponse_GoAway:
				a.Log.Info("server asked us to disconnect", "reason", msg.GoAway.Reason, "retry_after_s", msg.GoAway.RetryAfterS)
				if msg.GoAway.Reason == "revoked" {
					id.Status = "rejected"
					_ = a.Store.SaveIdentity(id)
					a.status("rejected", "This device was revoked by an administrator.", id.DeviceID)
				}
				return a.now().Sub(start), jitter(time.Duration(msg.GoAway.RetryAfterS)*time.Second, 30*time.Second), &goAway{reason: msg.GoAway.Reason}
			case *agentv1.ConnectResponse_Resync:
				switch msg.Resync.Section {
				case agentv1.InventorySection_INVENTORY_SECTION_HARDWARE:
					if a.hwPending, err = a.sendHardware(ctx, stream, true); err != nil {
						return a.now().Sub(start), 0, err
					}
				case agentv1.InventorySection_INVENTORY_SECTION_WU:
					if wp, err := a.sendWU(stream, true); err != nil {
						return a.now().Sub(start), 0, err
					} else if wp != nil {
						a.wuPending = wp
					}
				case agentv1.InventorySection_INVENTORY_SECTION_SOFTWARE:
					// The server refused the report it will never acknowledge: drop it, then send everything.
					if a.Inv != nil {
						a.Inv.ResetPending()
					}
					if err := runInv(inventory.SyncOptions{FullSoftware: true}); err != nil {
						return a.now().Sub(start), 0, err
					}
				case agentv1.InventorySection_INVENTORY_SECTION_USERS:
					if a.Inv != nil {
						a.Inv.ResetPending()
					}
					if err := runInv(inventory.SyncOptions{FullUsers: true}); err != nil {
						return a.now().Sub(start), 0, err
					}
				}
			}
		}
	}
}

// retryHint maps stream errors to reconnect delays; auth failures back off long.
func (a *Agent) retryHint(err error) time.Duration {
	switch status.Code(err) {
	case codes.Unauthenticated, codes.PermissionDenied:
		return jitter(10*time.Minute, 5*time.Minute)
	}
	return 0
}

// serverNow is local time corrected by the offset measured at HelloAck, so a
// wrong local clock cannot cause renewal loops or missed renewals.
func (a *Agent) serverNow() time.Time { return a.now().Add(time.Duration(a.clockOffset.Load())) }

func (a *Agent) renewDue(cert *x509.Certificate) bool {
	return cert.NotAfter.Sub(a.serverNow()) < pkix.Lifetime(cert)/3
}

// renew creates a NEW key, gets it certified, then switches over.
func (a *Agent) renew(ctx context.Context, client agentv1.AgentChannelServiceClient, id *store.Identity) error {
	gen := id.KeyGen + 1
	name := a.keyPrefix() + strconv.Itoa(gen)
	key, provider, err := a.Keys.Create(name)
	if err != nil {
		return err
	}
	csr, err := keystore.CSR(key)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := client.RenewCertificate(cctx, &agentv1.RenewCertificateRequest{CsrDer: csr})
	if err != nil {
		_ = a.Keys.Delete(name)
		return err
	}
	cert, err := x509.ParseCertificate(resp.ClientCertDer)
	pub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if err != nil || !ok || !pub.Equal(key.Public()) {
		_ = a.Keys.Delete(name)
		return errors.New("renewed certificate does not match the new key")
	}
	oldName := id.KeyName
	id.KeyName, id.KeyGen, id.CertDER = name, gen, resp.ClientCertDer
	if len(resp.IssuingCaDer) > 0 {
		id.IssuingDER = resp.IssuingCaDer
	}
	if err := a.Store.SaveIdentity(id); err != nil {
		return err
	}
	if err := a.Keys.Delete(oldName); err != nil {
		a.Log.Warn("could not delete old device key", "key", oldName, "err", err)
	}
	a.Log.Info("certificate renewed", "not_after", cert.NotAfter, "key_provider", provider)
	return nil
}

// acceptSigningCerts stores job-signing certs that chain directly to our root.
func (a *Agent) acceptSigningCerts(ctx context.Context, stream agentv1.AgentChannelService_ConnectClient, id *store.Identity, root *x509.Certificate, ders [][]byte) {
	var good [][]byte
	for _, d := range ders {
		c, err := x509.ParseCertificate(d)
		if err == nil {
			err = pkix.VerifyJobSigningCert(root, c, a.serverNow())
		}
		if err != nil {
			a.securityEvent(stream, agentv1.SecurityEventKind_SECURITY_EVENT_KIND_BAD_SIGNING_CERT, err.Error())
			continue
		}
		good = append(good, d)
	}
	if len(good) > 0 && !equalDERs(good, id.SigningDER) {
		id.SigningDER = good
		if err := a.Store.SaveIdentity(id); err != nil {
			a.Log.Error("store signing certs", "err", err)
		}
	}
	_ = ctx
}

func equalDERs(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// handleJobOffer verifies an envelope and hands it to the job engine. An offer
// for a job the engine already holds is not a replay: the server simply never
// saw our acknowledgement, so the engine reports the current state again.
func (a *Agent) handleJobOffer(stream agentv1.AgentChannelService_ConnectClient, id *store.Identity, root *x509.Certificate, se *agentv1.SignedEnvelope) {
	a.offerMu.Lock()
	defer a.offerMu.Unlock()
	var certs []*x509.Certificate
	for _, d := range id.SigningDER {
		if c, err := x509.ParseCertificate(d); err == nil {
			certs = append(certs, c)
		}
	}
	v := &envelope.Verifier{Root: root, DeviceID: id.DeviceID, OrgID: id.OrgID, SigningCerts: certs,
		Ledger: store.Ledger{S: a.Store}, Now: a.serverNow}
	env, err := v.Open(se)
	if err != nil {
		if errors.Is(err, envelope.ErrReplay) && env != nil && a.Jobs != nil && a.Store.JobGet(env.JobId) != nil {
			a.Jobs.Accept(se, env)
			return
		}
		kind := agentv1.SecurityEventKind_SECURITY_EVENT_KIND_BAD_SIGNATURE
		switch {
		case errors.Is(err, envelope.ErrWrongDevice):
			kind = agentv1.SecurityEventKind_SECURITY_EVENT_KIND_WRONG_DEVICE
		case errors.Is(err, envelope.ErrReplay):
			kind = agentv1.SecurityEventKind_SECURITY_EVENT_KIND_REPLAY
		case errors.Is(err, envelope.ErrExpired):
			kind = agentv1.SecurityEventKind_SECURITY_EVENT_KIND_EXPIRED
		}
		a.Log.Warn("rejected job envelope", "err", err)
		a.securityEvent(stream, kind, err.Error())
		return
	}
	_ = a.Store.LedgerRecord(env.JobId, time.Unix(env.ExpiresAt, 0))
	if a.Jobs == nil {
		a.Log.Info("verified job envelope but this agent has no job engine", "job_id", env.JobId, "type", env.Type.String())
		return
	}
	a.Log.Info("job accepted", "job_id", env.JobId, "type", env.Type.String())
	a.Jobs.Accept(se, env)
}

// securityEvent queues an event in the outbox; the stream loop sends it. (It
// may be called from the job engine's goroutine, so it never touches the stream.)
func (a *Agent) securityEvent(_ agentv1.AgentChannelService_ConnectClient, kind agentv1.SecurityEventKind, detail string) {
	seq, err := a.Store.NextSeq()
	if err != nil {
		return
	}
	a.queue(seq, &agentv1.ConnectRequest{Msg: &agentv1.ConnectRequest_SecurityEvent{SecurityEvent: &agentv1.SecurityEvent{Seq: seq, Kind: kind, Detail: text.Truncate(detail, 1000)}}})
}

// queue persists a message in the outbox and wakes the stream loop.
func (a *Agent) queue(seq uint64, msg *agentv1.ConnectRequest) {
	if b, err := proto.Marshal(msg); err == nil {
		_ = a.Store.OutboxPut(seq, b)
	}
	select {
	case a.outKick <- struct{}{}:
	default:
	}
}

// reportJob implements jobs.Reporter: updates are durable (outbox) and
// delivered with acknowledgements, surviving disconnects and restarts.
func (a *Agent) reportJob(u *agentv1.JobUpdate) {
	seq, err := a.Store.NextSeq()
	if err != nil {
		return
	}
	u.Seq = seq
	a.queue(seq, &agentv1.ConnectRequest{Msg: &agentv1.ConnectRequest_JobUpdate{JobUpdate: u}})
}

type jobReporter struct{ a *Agent }

func (r jobReporter) Report(u *agentv1.JobUpdate) { r.a.reportJob(u) }

// flushOutbox sends everything queued, once per stream.
func (a *Agent) flushOutbox(stream agentv1.AgentChannelService_ConnectClient) error {
	a.sentMu.Lock()
	a.sent = map[uint64]bool{}
	a.sentMu.Unlock()
	return a.sendQueued(stream)
}

// sendQueued sends outbox entries not yet sent on this stream.
func (a *Agent) sendQueued(stream agentv1.AgentChannelService_ConnectClient) error {
	m, order, err := a.Store.OutboxAll()
	if err != nil {
		return err
	}
	a.sentMu.Lock()
	defer a.sentMu.Unlock()
	if a.sent == nil {
		a.sent = map[uint64]bool{}
	}
	for _, seq := range order {
		if a.sent[seq] {
			continue
		}
		var msg agentv1.ConnectRequest
		if proto.Unmarshal(m[seq], &msg) != nil {
			_ = a.Store.OutboxAck(seq)
			continue
		}
		if err := stream.Send(&msg); err != nil {
			return err
		}
		a.sent[seq] = true
	}
	return nil
}

func (a *Agent) setClient(c agentv1.AgentChannelServiceClient) {
	a.clMu.Lock()
	a.client = c
	a.clMu.Unlock()
}

func (a *Agent) getClient() agentv1.AgentChannelServiceClient {
	a.clMu.Lock()
	defer a.clMu.Unlock()
	return a.client
}

// startJobs wires the engine to the agent and runs it for the agent's lifetime;
// it keeps working (queued jobs, windows, retries) while the server is unreachable.
func (a *Agent) startJobs(ctx context.Context) {
	if a.Jobs == nil {
		return
	}
	a.Jobs.Report = jobReporter{a}
	a.Jobs.Now = a.serverNow
	if a.Jobs.Trust == nil {
		a.Jobs.Trust = func() ([]byte, [][]byte, string, string) {
			id, err := a.Store.Identity()
			if err != nil || id == nil {
				return nil, nil, "", ""
			}
			return id.RootDER, id.SigningDER, id.DeviceID, id.OrgID
		}
	}
	a.Jobs.Security = func(k agentv1.SecurityEventKind, d string) { a.securityEvent(nil, k, d) }
	a.Jobs.WUReport = a.queueWU
	if a.Jobs.DataDir == "" {
		a.Jobs.DataDir = a.DataDir
	}
	if a.Jobs.Version == "" {
		a.Jobs.Version = a.Version
	}
	if a.Jobs.WUScanEvery == 0 {
		a.Jobs.WUScanEvery = 24 * time.Hour
	}
	a.Jobs.InventoryNow = func() {
		select {
		case a.invNow <- struct{}{}:
		default:
		}
	}
	if len(a.Jobs.Allowed) == 0 && len(a.Cfg.AllowedJobs) > 0 {
		a.Jobs.Allowed = map[string]bool{}
		for _, n := range a.Cfg.AllowedJobs {
			a.Jobs.Allowed[n] = true
		}
	}
	if a.Jobs.Fetch == nil {
		a.Jobs.Fetch = &jobs.MultiFetcher{Server: a.fetchFromServer}
	}
	go a.Jobs.Run(ctx)
}

// fetchFromServer streams stored content over the mTLS channel (FetchContent).
func (a *Agent) fetchFromServer(ctx context.Context, jobID string, sha []byte) (io.ReadCloser, error) {
	c := a.getClient()
	if c == nil {
		return nil, errors.New("not connected to the server")
	}
	st, err := c.FetchContent(ctx, &agentv1.FetchContentRequest{Sha256: sha, JobId: jobID})
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	go func() {
		for {
			ch, err := st.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				}
				_ = pw.CloseWithError(err)
				return
			}
			if _, err := pw.Write(ch.Data); err != nil {
				return
			}
		}
	}()
	return pr, nil
}

type pendingReport struct {
	seq uint64
	rev uint64
	fp  []byte
	gen uint64 // Windows Update snapshots: the snapshot generation that was sent
}

// sendHardware collects inventory and sends it if it changed (or forced).
func (a *Agent) sendHardware(ctx context.Context, stream agentv1.AgentChannelService_ConnectClient, force bool) (*pendingReport, error) {
	hw, err := a.HW.Collect(ctx)
	if err != nil || hw == nil {
		a.Log.Warn("hardware inventory failed", "err", err)
		return nil, nil
	}
	fp := hardware.Fingerprint(hw)
	if !force && bytes.Equal(fp, a.Store.GetMeta("hw_fp")) {
		return nil, nil
	}
	seq, err := a.Store.NextSeq()
	if err != nil {
		return nil, err
	}
	rev := a.Store.GetUint("hw_rev") + 1
	if err := stream.Send(&agentv1.ConnectRequest{Msg: &agentv1.ConnectRequest_Inventory{Inventory: &agentv1.InventoryReport{
		Seq: seq, Section: agentv1.InventorySection_INVENTORY_SECTION_HARDWARE, Rev: rev,
		Body: &agentv1.InventoryReport_Hardware{Hardware: hw}}}}); err != nil {
		return nil, err
	}
	a.Log.Info("hardware inventory sent", "rev", rev)
	return &pendingReport{seq: seq, rev: rev, fp: fp}, nil
}

func (a *Agent) handleAck(seq uint64) {
	if a.Inv != nil && a.Inv.Ack(seq) {
		return
	}
	if wp := a.wuPending; wp != nil && wp.seq == seq {
		_ = a.Store.SetUint("wu_rev", wp.rev)
		_ = a.Store.SetUint("wu_sent", wp.gen)
		a.wuPending = nil
		return
	}
	if hw := a.hwPending; hw != nil && hw.seq == seq {
		_ = a.Store.SetUint("hw_rev", hw.rev)
		_ = a.Store.SetMeta("hw_fp", hw.fp)
		a.hwPending = nil
		return
	}
	_ = a.Store.OutboxAck(seq)
}

// syncInventory runs one software/users sync. ErrBusy (a report is still
// awaiting its acknowledgement) is not an error: the sync is repeated once the
// acknowledgement arrives. Scan failures are logged, not fatal to the stream.
func (a *Agent) syncInventory(ctx context.Context, stream agentv1.AgentChannelService_ConnectClient, opt inventory.SyncOptions, dirty *bool) error {
	if a.Inv == nil {
		return nil
	}
	err := a.Inv.Sync(ctx, stream, opt)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, inventory.ErrBusy):
		*dirty = true
		return nil
	case ctx.Err() != nil:
		return nil
	}
	if status.Code(err) != codes.Unknown { // gRPC send failure: the stream is gone
		return err
	}
	a.Log.Warn("inventory sync failed", "err", err)
	return nil
}

// startInventoryTriggers debounces raw change notifications into one trigger.
func (a *Agent) startInventoryTriggers(ctx context.Context) <-chan struct{} {
	trig := make(chan struct{}, 1)
	if a.Changes == nil || a.Inv == nil {
		return trig
	}
	quiet := a.InvQuiet
	if quiet <= 0 {
		quiet = 30 * time.Second
	}
	go func() {
		d := inventory.Debouncer{Quiet: quiet}
		for d.Wait(ctx, a.Changes) {
			select {
			case trig <- struct{}{}:
			default:
			}
		}
	}()
	return trig
}

// sendHeartbeat sends only when something changed or 30 minutes elapsed.
func (a *Agent) sendHeartbeat(ctx context.Context, stream agentv1.AgentChannelService_ConnectClient, force bool) error {
	hb, err := a.HW.Heartbeat(ctx)
	if err != nil || hb == nil {
		return nil
	}
	changed := a.lastHB == nil || a.lastHB.PendingReboot != hb.PendingReboot || a.lastHB.QueuedFileDeletes != hb.QueuedFileDeletes || a.lastHB.LoggedOnUser != hb.LoggedOnUser
	if !force && !changed && a.now().Sub(a.lastHBSent) < fullHeartbeatEvery {
		return nil
	}
	if err := stream.Send(&agentv1.ConnectRequest{Msg: &agentv1.ConnectRequest_Heartbeat{Heartbeat: hb}}); err != nil {
		return err
	}
	a.lastHB, a.lastHBSent = hb, a.now()
	return nil
}

// queueWU keeps the newest Windows Update snapshot (also on disk, so a restart does not lose an
// unsent one) and wakes the stream loop to send it.
func (a *Agent) queueWU(s *agentv1.WuInventory) {
	a.wuMu.Lock()
	a.wuSnap = s
	a.wuMu.Unlock()
	if b, err := proto.Marshal(s); err == nil {
		_ = a.Store.SetMeta("wu_snapshot", b)
	}
	_ = a.Store.SetUint("wu_gen", a.Store.GetUint("wu_gen")+1) // which snapshot generation is waiting to be sent
	select {
	case a.wuKick <- struct{}{}:
	default:
	}
}

// currentWU returns the newest snapshot, loading the stored one after a restart.
func (a *Agent) currentWU() *agentv1.WuInventory {
	a.wuMu.Lock()
	defer a.wuMu.Unlock()
	if a.wuSnap == nil {
		var s agentv1.WuInventory
		if b := a.Store.GetMeta("wu_snapshot"); len(b) > 0 && proto.Unmarshal(b, &s) == nil {
			a.wuSnap = &s
		}
	}
	return a.wuSnap
}

// sendWU sends the Windows Update snapshot if it has not been acknowledged yet (or when forced by
// the server's resync request). Snapshots are full, so the server simply replaces what it had.
func (a *Agent) sendWU(stream agentv1.AgentChannelService_ConnectClient, force bool) (*pendingReport, error) {
	snap := a.currentWU()
	if snap == nil {
		return nil, nil
	}
	gen := a.Store.GetUint("wu_gen")
	if !force && gen <= a.Store.GetUint("wu_sent") {
		return nil, nil
	}
	seq, err := a.Store.NextSeq()
	if err != nil {
		return nil, err
	}
	if a.wuRev == 0 {
		a.wuRev = a.Store.GetUint("wu_rev")
	}
	a.wuRev++
	if err := stream.Send(&agentv1.ConnectRequest{Msg: &agentv1.ConnectRequest_Inventory{Inventory: &agentv1.InventoryReport{
		Seq: seq, Section: agentv1.InventorySection_INVENTORY_SECTION_WU, Rev: a.wuRev,
		Body: &agentv1.InventoryReport_Wu{Wu: snap}, Truncated: snap.Truncated}}}); err != nil {
		return nil, err
	}
	a.Log.Info("windows update snapshot sent", "updates", len(snap.Updates), "rev", a.wuRev)
	return &pendingReport{seq: seq, rev: a.wuRev, gen: gen}, nil
}
