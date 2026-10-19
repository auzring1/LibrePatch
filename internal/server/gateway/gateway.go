// Package gateway is the agent-facing gRPC endpoint. It terminates mTLS
// itself (never behind a proxy) and enforces device identity, revocation
// and per-device limits. See docs/PROTOCOL.md.
package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/server/catalog"
	"github.com/auzring1/librepatch/internal/server/config"
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/events"
	"github.com/auzring1/librepatch/internal/server/inventory"
	"github.com/auzring1/librepatch/internal/server/kek"
	"github.com/auzring1/librepatch/internal/server/pki"
	"github.com/auzring1/librepatch/internal/server/updates"
)

// MaxMessageBytes bounds every gRPC message (PROTOCOL §1).
const MaxMessageBytes = 4 << 20

// connReadBuffer is the per-connection read buffer of the agent listener (gRPC's default is 32 KiB).
const connReadBuffer = 4 << 10

// Gateway serves EnrollmentService and AgentChannelService.
type Gateway struct {
	agentv1.UnimplementedEnrollmentServiceServer
	agentv1.UnimplementedAgentChannelServiceServer

	cfg       *config.Config
	pool      *pgxpool.Pool
	sealer    *kek.Sealer
	authority *pki.Authority
	events    *events.Broker
	hub       *Hub
	log       *slog.Logger
	now       func() time.Time

	gwCert atomic.Pointer[tls.Certificate]

	enrollIP    *auth.Limiter
	enrollToken *auth.Limiter
	enrollGate  gate // bounds enrollment transactions in flight (see gate.go)
	statusIP    *auth.Limiter
	renewDevice *auth.Limiter
	invDevice   *auth.Limiter
	hbDevice    *auth.Limiter // heartbeats and hardware reports
	secDevice   *auth.Limiter // security events (each one is an audit row)
	inv         *inventory.Service
	deploy      *deploy.Service
	updates     *updates.Service
	content     *catalog.Store
	fetching    *fetchLimiter
}

// Options configure a Gateway.
type Options struct {
	Config    *config.Config
	Pool      *pgxpool.Pool
	Sealer    *kek.Sealer
	Authority *pki.Authority
	Events    *events.Broker
	Hub       *Hub
	Log       *slog.Logger
	Now       func() time.Time
	// Deploy handles job updates and dispatch; Content serves uploaded installers.
	Deploy  *deploy.Service
	Content *catalog.Store
	// Updates stores Windows Update snapshots from devices.
	Updates *updates.Service
}

// New creates a gateway; call RefreshCertificate before Serve.
func New(o Options) *Gateway {
	now := o.Now
	if now == nil {
		now = time.Now
	}
	perIP := rateOr(o.Config.EnrollRatePerIP, config.DefaultEnrollRatePerIP)
	perToken := rateOr(o.Config.EnrollRatePerToken, config.DefaultEnrollRatePerToken)
	return &Gateway{cfg: o.Config, pool: o.Pool, sealer: o.Sealer, authority: o.Authority, events: o.Events,
		hub: o.Hub, log: o.Log, now: now,
		enrollIP:    auth.NewLimiter(perIP, time.Minute, perIP),
		enrollToken: auth.NewLimiter(perToken, time.Minute, perToken),
		enrollGate:  newGate(maxEnrollTx),
		statusIP:    auth.NewLimiter(30, time.Minute, 30),
		renewDevice: auth.NewLimiter(5, time.Hour, 5),
		// A full snapshot is up to ~100 chunks in a burst; steady state is a few per minute.
		invDevice: auth.NewLimiter(120, time.Minute, 450),
		hbDevice:  auth.NewLimiter(30, time.Minute, 30),
		secDevice: auth.NewLimiter(6, time.Minute, 6),
		inv:       &inventory.Service{Pool: o.Pool, Now: now},
		deploy:    o.Deploy, updates: o.Updates, content: o.Content, fetching: newFetchLimiter(2),
	}
}

// maxEnrollTx is how many enrollment transactions may run at once (a quarter of the 32-connection pool).
const maxEnrollTx = 8

// rateOr returns n, or def when n is unset (tests build a Config by hand).
func rateOr(n, def int) int {
	if n <= 0 {
		return def
	}
	return n
}

// RefreshCertificate loads or (re-)issues the gateway TLS certificate.
func (g *Gateway) RefreshCertificate(ctx context.Context) error {
	kp, err := pki.EnsureGatewayCert(ctx, g.pool, g.sealer, g.authority, g.cfg.GatewaySANs, g.now())
	if err != nil {
		return err
	}
	g.gwCert.Store(&tls.Certificate{
		Certificate: [][]byte{kp.Cert.Raw, g.authority.Issuing.Cert.Raw, g.authority.Root.Raw},
		PrivateKey:  kp.Key,
		Leaf:        kp.Cert,
	})
	return nil
}

// TLSConfig is TLS 1.3-only. Client certificates are requested (not
// required, so enrollment works) and verified by verifyConnection, which
// also checks revocation in the database on every handshake.
func (g *Gateway) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ClientAuth: tls.RequestClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c := g.gwCert.Load(); c != nil {
				return c, nil
			}
			return nil, errors.New("gateway certificate not loaded")
		},
		VerifyConnection: g.verifyConnection,
	}
}

func (g *Gateway) verifyConnection(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return nil // anonymous: only Enrollment RPCs will be allowed
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := g.checkIdentity(ctx, cs)
	return err
}

// checkIdentity verifies the client chain and the database state of the cert and device.
func (g *Gateway) checkIdentity(ctx context.Context, cs tls.ConnectionState) (*pki.DeviceIdentity, error) {
	if len(cs.PeerCertificates) == 0 {
		return nil, errNoCert
	}
	ident, err := g.authority.VerifyDeviceCert(cs.PeerCertificates[0], g.now(), g.cfg.DeviceRenewGrace)
	if err != nil {
		return nil, fmt.Errorf("client certificate rejected: %w", err)
	}
	c, err := dbq.New(g.pool).CheckDeviceCert(ctx, ident.Serial)
	if err != nil {
		return nil, errors.New("client certificate unknown")
	}
	if c.CertRevokedAt != nil || c.CertDeviceID != ident.DeviceID {
		return nil, errors.New("client certificate revoked")
	}
	if c.DeviceStatus != "active" {
		return nil, errors.New("device is not active")
	}
	return ident, nil
}

var errNoCert = errors.New("client certificate required")

type identKey struct{}

// authInterceptor enforces per-method identity requirements.
func (g *Gateway) streamAuth(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	if info.FullMethod != agentv1.AgentChannelService_Connect_FullMethodName &&
		info.FullMethod != agentv1.AgentChannelService_FetchContent_FullMethodName {
		return status.Error(codes.PermissionDenied, "method not allowed")
	}
	ident, err := g.identityFromCtx(ss.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	if ident.Expired {
		return status.Error(codes.Unauthenticated, "certificate expired; call RenewCertificate")
	}
	return h(srv, &identStream{ServerStream: ss, ctx: context.WithValue(ss.Context(), identKey{}, ident)})
}

func (g *Gateway) unaryAuth(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	switch info.FullMethod {
	case agentv1.EnrollmentService_Enroll_FullMethodName, agentv1.EnrollmentService_EnrollStatus_FullMethodName:
		return h(ctx, req)
	case agentv1.AgentChannelService_RenewCertificate_FullMethodName:
		ident, err := g.identityFromCtx(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		return h(context.WithValue(ctx, identKey{}, ident), req) // expired-in-grace allowed
	default:
		return nil, status.Error(codes.PermissionDenied, "method not allowed")
	}
}

// identityFromCtx re-checks the peer certificate and database state for
// every stream/call, so a revoked device cannot reuse an open HTTP/2 connection.
func (g *Gateway) identityFromCtx(ctx context.Context) (*pki.DeviceIdentity, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errNoCert
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, errNoCert
	}
	return g.checkIdentity(ctx, ti.State)
}

type identStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *identStream) Context() context.Context { return s.ctx }

func identFrom(ctx context.Context) *pki.DeviceIdentity {
	id, _ := ctx.Value(identKey{}).(*pki.DeviceIdentity)
	return id
}

func peerIP(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		host, _, err := net.SplitHostPort(p.Addr.String())
		if err == nil {
			return host
		}
		return p.Addr.String()
	}
	return ""
}

// NewGRPCServer builds the gRPC server with TLS, limits and keepalive policy.
func (g *Gateway) NewGRPCServer() *grpc.Server {
	s := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(g.TLSConfig())),
		grpc.MaxRecvMsgSize(MaxMessageBytes),
		grpc.MaxSendMsgSize(MaxMessageBytes),
		grpc.MaxConcurrentStreams(16),
		// Idle connections dominate: thousands of agents hold a stream open and say almost nothing. gRPC shares
		// the write buffer between connections already; the 32 KiB read buffer each connection keeps is not.
		grpc.ReadBufferSize(connReadBuffer),
		grpc.ConnectionTimeout(15*time.Second),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 60 * time.Second, PermitWithoutStream: true}),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 2 * time.Minute, Timeout: 20 * time.Second}),
		grpc.ChainUnaryInterceptor(g.unaryAuth),
		grpc.ChainStreamInterceptor(g.streamAuth),
	)
	agentv1.RegisterEnrollmentServiceServer(s, g)
	agentv1.RegisterAgentChannelServiceServer(s, g)
	return s
}

// Serve runs the gateway on lis until ctx ends.
func (g *Gateway) Serve(ctx context.Context, lis net.Listener) error {
	s := g.NewGRPCServer()
	go func() {
		<-ctx.Done()
		// Tell agents to come back later, spreading reconnects (PROTOCOL §7).
		g.hub.mu.Lock()
		for _, c := range g.hub.conns {
			c.close("server shutting down")
		}
		g.hub.mu.Unlock()
		stopped := make(chan struct{})
		go func() { s.GracefulStop(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			s.Stop()
		}
	}()
	go g.certRefresher(ctx)
	return s.Serve(lis)
}

func (g *Gateway) certRefresher(ctx context.Context) {
	t := time.NewTicker(12 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := g.RefreshCertificate(ctx); err != nil {
				g.log.Error("gateway certificate refresh", "err", err)
			}
		}
	}
}

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
