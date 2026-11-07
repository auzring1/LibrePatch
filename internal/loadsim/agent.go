package loadsim

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	mrand "math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/status"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/core"
	"github.com/auzring1/librepatch/internal/agent/inventory"
	"github.com/auzring1/librepatch/internal/shared/envelope"
)

const (
	connectTimeout    = 30 * time.Second // TCP + TLS + HTTP/2 to the gateway
	helloTimeout      = 60 * time.Second // Hello -> HelloAck
	healthyResetAfter = 10 * time.Minute // as the real agent
)

// errDropped marks a session that the load generator ended on purpose (a simulated network loss).
var errDropped = errors.New("connection dropped by the load generator")

// simAgent is one simulated device: a goroutine, a TLS connection while connected and a few
// kilobytes of state. The inventory fixture is shared with every other agent.
type simAgent struct {
	f    *fleet
	idx  int
	host string
	rng  *mrand.Rand // only used by this agent's own goroutine

	ident *Identity
	tc    *tls.Config

	store *memStore
	coll  *collector
	inv   *inventory.Manager
	bo    *core.Backoff
	boot  string

	// Hardware report state (the acknowledged revision).
	hwRev   uint64
	hwAcked bool

	// Jobs: the executed-job ledger and the outbox of job updates not yet acknowledged by the server.
	jobMu  sync.Mutex
	ledger map[string]bool
	outbox []*agentv1.JobUpdate
	kick   chan struct{}
	invNow chan struct{}

	online      atomic.Bool
	onlineEpoch atomic.Int64 // the storm epoch in which the current stream was opened
	dropMu      sync.Mutex
	cancel      context.CancelFunc // ends the current session
	holdOff     atomic.Int64       // unix nanos: do not reconnect before this
}

func newSimAgent(f *fleet, idx int) *simAgent {
	var b [4]byte
	_, _ = rand.Read(b[:])
	st := newMemStore(f.fx.Snapshot)
	coll := &collector{fx: f.fx}
	return &simAgent{
		f: f, idx: idx, host: f.hostName(idx),
		rng:   mrand.New(mrand.NewPCG(uint64(idx)+1, uint64(b[0])<<24|uint64(b[1])<<16|uint64(b[2])<<8|uint64(b[3]))), // #nosec G404 G115 -- jitter; idx is a small non-negative index
		store: st, coll: coll,
		inv:    &inventory.Manager{Collector: coll, Store: st, Log: f.quietLog},
		bo:     &core.Backoff{Base: f.cfg.BackoffBase, Max: f.cfg.BackoffMax},
		boot:   hex.EncodeToString(b[:]),
		ledger: map[string]bool{},
		kick:   make(chan struct{}, 1),
		invNow: make(chan struct{}, 1),
	}
}

// drop ends the current session as if the network had failed. The agent then backs off and reconnects
// exactly as the real agent does; stayAway keeps it offline at least that long (a sleeping laptop).
func (a *simAgent) drop(stayAway time.Duration) {
	if stayAway > 0 {
		a.holdOff.Store(time.Now().Add(stayAway).UnixNano())
	}
	a.dropMu.Lock()
	c := a.cancel
	a.dropMu.Unlock()
	if c != nil {
		c()
	}
}

// run is the agent's life: obtain an identity, then connect, stay connected and reconnect, forever.
func (a *simAgent) run(ctx context.Context) {
	for a.ident == nil && ctx.Err() == nil {
		id, err := a.f.identity(ctx, a)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			w := a.bo.Next()
			if status.Code(err) == codes.ResourceExhausted {
				// The enrollment limiter refills slowly (10 per minute per address by default).
				w = 5*time.Second + time.Duration(a.rng.Int64N(int64(25*time.Second)))
			}
			a.f.count("enroll.retry")
			a.f.log.Debug("enrollment failed; retrying", "agent", a.idx, "err", err, "in", w)
			if !sleep(ctx, w) {
				return
			}
			continue
		}
		a.ident = id
		tc, err := core.MutualTLS(a.f.server, a.f.trust().root, id.CertDER, a.f.trust().issuingDER, id.Key)
		if err != nil {
			a.f.log.Error("tls config", "agent", a.idx, "err", err)
			return
		}
		a.tc = tc
		a.bo.Reset()
	}
	for ctx.Err() == nil {
		healthy, wait, err := a.session(ctx)
		if healthy >= healthyResetAfter {
			a.bo.Reset()
		}
		if c := classify(err); err != nil && healthy > 0 && c != "dropped" && c != "canceled" {
			// How old a stream was when it failed on its own: a cluster of equal ages points at a timer.
			a.f.hist("failed_session_age").Record(healthy)
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil && wait == 0 {
			wait = a.bo.Next()
		}
		if ho := time.Until(time.Unix(0, a.holdOff.Load())); ho > wait {
			wait = ho
		}
		if !sleep(ctx, wait) {
			return
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func jitterDur(r *mrand.Rand, d time.Duration, frac float64) time.Duration {
	if frac <= 0 {
		return d
	}
	span := float64(d) * frac
	return d + time.Duration((r.Float64()*2-1)*span)
}

// classify turns a connection or stream error into a short, stable counter name.
func classify(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, errDropped) {
		return "dropped"
	}
	switch status.Code(err) {
	case codes.ResourceExhausted:
		return "rate_limited"
	case codes.Unauthenticated:
		return "unauthenticated"
	case codes.PermissionDenied:
		return "permission_denied"
	case codes.InvalidArgument:
		return "invalid_argument"
	case codes.Internal:
		return "server_internal"
	}
	m := err.Error()
	switch {
	case strings.Contains(m, "connection refused"):
		return "refused"
	case strings.Contains(m, "tls:") || strings.Contains(m, "certificate"):
		return "tls"
	case strings.Contains(m, "i/o timeout") || errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.DeadlineExceeded:
		return "timeout"
	case strings.Contains(m, "connection reset") || strings.Contains(m, "broken pipe"):
		return "reset"
	case strings.Contains(m, "EOF"):
		return "eof"
	case status.Code(err) == codes.Unavailable:
		return "unavailable"
	case errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled:
		return "canceled"
	}
	return "other"
}

type goAwayErr struct{ reason string }

func (g *goAwayErr) Error() string { return "server closed the stream: " + g.reason }

// session is one connection: dial, Hello, inventory, then the event loop. It returns how long the
// stream was healthy and, when the server asked for it, how long to wait before reconnecting.
func (a *simAgent) session(parent context.Context) (healthy, wait time.Duration, err error) {
	f := a.f
	sctx, cancel := context.WithCancelCause(parent) // NOSONAR: cancel is called in the deferred function below, and by drop
	a.dropMu.Lock()
	a.cancel = func() { cancel(errDropped) }
	a.dropMu.Unlock()
	defer func() {
		cancel(nil)
		a.dropMu.Lock()
		a.cancel = nil
		a.dropMu.Unlock()
	}()

	f.count("attempts")
	opts := core.DialOptions(a.tc)
	if f.cfg.ReadBuffer > 0 {
		opts = append(opts, grpc.WithReadBufferSize(f.cfg.ReadBuffer))
	}
	if f.cfg.WriteBuffer > 0 {
		opts = append(opts, grpc.WithWriteBufferSize(f.cfg.WriteBuffer))
	}
	conn, derr := grpc.NewClient("passthrough:///"+f.server, opts...)
	if derr != nil {
		f.count("fail.dial")
		return 0, 0, derr
	}
	defer func() { _ = conn.Close() }()
	client := agentv1.NewAgentChannelServiceClient(conn)

	t0 := time.Now()
	conn.Connect()
	stream, cerr := a.waitConnected(sctx, conn, client, t0)
	if cerr != nil {
		return 0, 0, cerr
	}

	revs := map[string]uint64{"hardware": a.hwRev, "software": a.inv.SoftwareRev(), "users": a.inv.UsersRev()}
	a.inv.ResetPending() // acknowledgements of an earlier stream can never arrive
	a.jobMu.Lock()
	pendingOut := len(a.outbox)
	a.jobMu.Unlock()
	hs := time.Now()
	guard := time.AfterFunc(helloTimeout, func() { cancel(context.DeadlineExceeded) })
	if err := stream.Send(&agentv1.ConnectRequest{Msg: &agentv1.ConnectRequest_Hello{Hello: &agentv1.Hello{
		DeviceId: a.ident.DeviceID, AgentVersion: f.cfg.Version, BootId: a.boot,
		Capabilities: []string{"hardware", "software", "users", "jobs/v1"}, Revs: revs,
		OutboxPending: uint32(pendingOut), // #nosec G115 -- small
		CertNotAfter:  a.ident.Cert.NotAfter.Unix(),
	}}}); err != nil {
		guard.Stop()
		return 0, 0, a.streamErr(sctx, "hello", err)
	}
	first, rerr := stream.Recv()
	guard.Stop()
	if rerr != nil {
		return 0, 0, a.streamErr(sctx, "hello", rerr)
	}
	ack := first.GetHelloAck()
	if ack == nil {
		if ga := first.GetGoAway(); ga != nil {
			f.count("goaway." + sanitize(ga.Reason))
			return 0, goAwayWait(a.rng, ga), &goAwayErr{reason: ga.Reason}
		}
		f.count("fail.no_helloack")
		return 0, 0, errors.New("expected HelloAck")
	}
	f.hist("handshake").Record(time.Since(hs))
	f.acceptSigningCerts(ack.JobSigningCertsDer)
	start := time.Now()
	a.onlineEpoch.Store(f.stormEpoch.Load())
	a.online.Store(true)
	f.connected.Add(1)
	f.count("connected")
	defer func() {
		a.online.Store(false)
		f.connected.Add(-1)
		healthy = time.Since(start)
	}()

	st := &sessionState{a: a, stream: stream, pend: map[uint64]pending{}, sent: map[*agentv1.JobUpdate]bool{}}
	defer func() { f.inflight.Add(-int64(len(st.pend))) }()
	forceHW := false
	var invOpt inventory.SyncOptions
	for _, sec := range ack.ResyncSections {
		switch sec {
		case agentv1.InventorySection_INVENTORY_SECTION_HARDWARE:
			forceHW = true
		case agentv1.InventorySection_INVENTORY_SECTION_SOFTWARE:
			invOpt.FullSoftware = true
		case agentv1.InventorySection_INVENTORY_SECTION_USERS:
			invOpt.FullUsers = true
		}
	}
	if err := st.flushOutbox(); err != nil {
		return 0, 0, a.streamErr(sctx, "send", err)
	}
	if err := st.sendHardware(forceHW); err != nil {
		return 0, 0, a.streamErr(sctx, "send", err)
	}
	if err := st.syncInventory(invOpt); err != nil {
		return 0, 0, a.streamErr(sctx, "send", err)
	}
	if err := st.heartbeat(); err != nil {
		return 0, 0, a.streamErr(sctx, "send", err)
	}

	msgs := make(chan *agentv1.ConnectResponse)
	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case msgs <- m:
			case <-sctx.Done():
				return
			}
		}
	}()

	hb := time.NewTimer(jitterDur(a.rng, f.cfg.Heartbeat, f.cfg.HeartbeatJitter))
	defer hb.Stop()
	var chg <-chan time.Time
	var chgTimer *time.Timer
	if f.cfg.InventoryChangeEvery > 0 {
		chgTimer = time.NewTimer(jitterDur(a.rng, f.cfg.InventoryChangeEvery, 0.5))
		defer chgTimer.Stop()
		chg = chgTimer.C
	}
	dirty := false
	for {
		select {
		case <-sctx.Done():
			return 0, 0, a.streamErr(sctx, "session", context.Cause(sctx))
		case err := <-recvErr:
			return 0, 0, a.streamErr(sctx, "recv", err)
		case <-hb.C:
			if err := st.heartbeat(); err != nil {
				return 0, 0, a.streamErr(sctx, "send", err)
			}
			hb.Reset(jitterDur(a.rng, f.cfg.Heartbeat, f.cfg.HeartbeatJitter))
		case <-chg:
			a.coll.change(f.cfg.InventoryChangeItems, a.rng)
			if err := st.syncInventory(inventory.SyncOptions{}); err != nil {
				return 0, 0, a.streamErr(sctx, "send", err)
			}
			chgTimer.Reset(jitterDur(a.rng, f.cfg.InventoryChangeEvery, 0.5))
		case <-a.kick:
			if err := st.flushOutbox(); err != nil {
				return 0, 0, a.streamErr(sctx, "send", err)
			}
		case <-a.invNow:
			// INVENTORY_FULL job: refresh software and users, hardware if needed, and a heartbeat.
			if err := st.syncInventory(inventory.SyncOptions{}); err != nil {
				return 0, 0, a.streamErr(sctx, "send", err)
			}
			if err := st.sendHardware(false); err != nil {
				return 0, 0, a.streamErr(sctx, "send", err)
			}
			if err := st.heartbeat(); err != nil {
				return 0, 0, a.streamErr(sctx, "send", err)
			}
		case m := <-msgs:
			switch msg := m.Msg.(type) {
			case *agentv1.ConnectResponse_Ack:
				st.onAck(msg.Ack.Seq)
				if dirty && !a.inv.Busy() {
					dirty = false
					if err := st.syncInventory(inventory.SyncOptions{}); err != nil {
						return 0, 0, a.streamErr(sctx, "send", err)
					}
				}
			case *agentv1.ConnectResponse_GoAway:
				f.count("goaway." + sanitize(msg.GoAway.Reason))
				return time.Since(start), goAwayWait(a.rng, msg.GoAway), &goAwayErr{reason: msg.GoAway.Reason}
			case *agentv1.ConnectResponse_Resync:
				f.count("resync")
				a.inv.ResetPending()
				switch msg.Resync.Section {
				case agentv1.InventorySection_INVENTORY_SECTION_HARDWARE:
					err = st.sendHardware(true)
				case agentv1.InventorySection_INVENTORY_SECTION_SOFTWARE:
					err = st.syncInventory(inventory.SyncOptions{FullSoftware: true})
				case agentv1.InventorySection_INVENTORY_SECTION_USERS:
					err = st.syncInventory(inventory.SyncOptions{FullUsers: true})
				}
				if err != nil {
					return 0, 0, a.streamErr(sctx, "send", err)
				}
			case *agentv1.ConnectResponse_JobOffer:
				st.onOffer(msg.JobOffer)
			}
		}
	}
}

// goAwayWait is the real agent's rule: the server's hint plus up to 30 s of jitter.
func goAwayWait(r *mrand.Rand, ga *agentv1.GoAway) time.Duration {
	return time.Duration(ga.RetryAfterS)*time.Second + time.Duration(r.Int64N(int64(30*time.Second)))
}

func sanitize(s string) string {
	s = strings.ToLower(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, s))
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// streamErr counts and returns a stream failure. If the session was cancelled on purpose (a drop, or
// the hello guard timer), the cause is reported instead of the transport's generic error.
func (a *simAgent) streamErr(sctx context.Context, stage string, err error) error {
	if c := context.Cause(sctx); c != nil && (errors.Is(c, errDropped) || errors.Is(c, context.DeadlineExceeded)) {
		err = c
	}
	if c := classify(err); stage == "recv" && c != "dropped" && c != "canceled" && a.f.samples.Add(1) <= 8 {
		a.f.log.Warn("sample of a failed session", "agent", a.idx, "stage", stage, "class", c, "err", err)
	}
	a.f.count("fail." + stage + "." + classify(err))
	return err
}

// waitConnected performs the TCP + TLS + HTTP/2 setup and opens the Connect stream. Connection
// latency is recorded here; a refused or rejected connection is classified for the report.
func (a *simAgent) waitConnected(ctx context.Context, conn *grpc.ClientConn, client agentv1.AgentChannelServiceClient, t0 time.Time) (agentv1.AgentChannelService_ConnectClient, error) {
	f := a.f
	tctx, tcancel := context.WithTimeout(ctx, connectTimeout)
	defer tcancel()
	for {
		s := conn.GetState()
		if s == connectivity.Ready {
			break
		}
		if s == connectivity.TransientFailure || s == connectivity.Shutdown {
			// A non-wait-for-ready RPC fails at once and carries the transport's reason.
			_, err := client.Connect(tctx)
			if err == nil {
				err = errors.New("transient failure")
			}
			f.count("fail.connect." + classify(err))
			return nil, err
		}
		if !conn.WaitForStateChange(tctx, s) {
			err := context.Cause(ctx)
			if err == nil || !errors.Is(err, errDropped) {
				err = context.DeadlineExceeded
			}
			f.count("fail.connect." + classify(err))
			return nil, err
		}
	}
	f.hist("connect").Record(time.Since(t0))
	st := time.Now()
	stream, err := client.Connect(ctx)
	if err != nil {
		f.count("fail.stream." + classify(err))
		return nil, err
	}
	f.hist("stream_open").Record(time.Since(st))
	return stream, nil
}

type pending struct {
	kind string
	at   time.Time
}

// sessionState is the per-stream bookkeeping of one session (used from the session goroutine only).
type sessionState struct {
	a      *simAgent
	stream agentv1.AgentChannelService_ConnectClient
	pend   map[uint64]pending
	sent   map[*agentv1.JobUpdate]bool
	hwSeq  uint64
	hwNext uint64
	snapT  time.Time
}

// Send implements inventory.Sender, noting when each acknowledged report went out.
func (s *sessionState) Send(m *agentv1.ConnectRequest) error {
	if inv := m.GetInventory(); inv != nil {
		now := time.Now()
		switch {
		case inv.GetSoftwareChunk() != nil:
			ch := inv.GetSoftwareChunk()
			if ch.Index == 0 {
				s.snapT = now
			}
			if ch.Index+1 == ch.Total {
				s.track(inv.Seq, "inventory_snapshot", s.snapT)
			}
		case inv.GetSoftwareDelta() != nil:
			s.track(inv.Seq, "inventory_delta", now)
		case inv.GetUsers() != nil:
			s.track(inv.Seq, "inventory_users", now)
		}
	}
	return s.stream.Send(m)
}

func (s *sessionState) syncInventory(o inventory.SyncOptions) error {
	err := s.a.inv.Sync(context.Background(), s, o)
	if errors.Is(err, inventory.ErrBusy) {
		return nil
	}
	return err
}

func (s *sessionState) sendHardware(force bool) error {
	a := s.a
	if a.hwAcked && !force {
		return nil
	}
	seq, _ := a.store.NextSeq()
	s.hwSeq, s.hwNext = seq, a.hwRev+1
	hw := hardwareFor(a.host, a.f.serialOf(a.idx), a.f.uuidOf(a.idx))
	if err := s.stream.Send(&agentv1.ConnectRequest{Msg: &agentv1.ConnectRequest_Inventory{Inventory: &agentv1.InventoryReport{
		Seq: seq, Section: agentv1.InventorySection_INVENTORY_SECTION_HARDWARE, Rev: s.hwNext,
		Body: &agentv1.InventoryReport_Hardware{Hardware: hw}}}}); err != nil {
		return err
	}
	s.track(seq, "hardware", time.Now())
	return nil
}

var heartbeatBase = time.Now()

func (s *sessionState) heartbeat() error {
	t := time.Now()
	err := s.stream.Send(&agentv1.ConnectRequest{Msg: &agentv1.ConnectRequest_Heartbeat{Heartbeat: &agentv1.Heartbeat{
		UptimeS: uint64(time.Since(heartbeatBase).Seconds()) + 3600, LoggedOnUser: `LOADSIM\user`, SystemDriveFreeBytes: 100 << 30}}})
	if err == nil {
		// There is no acknowledgement for a heartbeat; this is how long Send took (flow-control back pressure).
		s.a.f.hist("heartbeat_send").Record(time.Since(t))
		s.a.f.count("heartbeats")
	}
	return err
}

// onAck records a round trip and commits whatever the acknowledgement covers.
func (s *sessionState) onAck(seq uint64) {
	a := s.a
	if p, ok := s.pend[seq]; ok {
		delete(s.pend, seq)
		a.f.inflight.Add(-1)
		a.f.hist("ack_" + p.kind).Record(time.Since(p.at))
	}
	if a.inv.Ack(seq) {
		return
	}
	if seq == s.hwSeq && s.hwSeq != 0 {
		a.hwRev, a.hwAcked = s.hwNext, true
		s.hwSeq = 0
		return
	}
	a.jobMu.Lock()
	for i, u := range a.outbox {
		if u.Seq == seq {
			if u.Result != nil {
				a.f.jobs.Acked(u.JobId, time.Now())
			}
			a.outbox = append(a.outbox[:i], a.outbox[i+1:]...)
			break
		}
	}
	a.jobMu.Unlock()
}

// flushOutbox sends job updates the server has not acknowledged (once per stream).
func (s *sessionState) flushOutbox() error {
	a := s.a
	a.jobMu.Lock()
	todo := make([]*agentv1.JobUpdate, 0, len(a.outbox))
	for _, u := range a.outbox {
		if !s.sent[u] {
			todo = append(todo, u)
		}
	}
	a.jobMu.Unlock()
	for _, u := range todo {
		if err := s.stream.Send(&agentv1.ConnectRequest{Msg: &agentv1.ConnectRequest_JobUpdate{JobUpdate: u}}); err != nil {
			return err
		}
		s.sent[u] = true
		if u.Result != nil {
			a.f.jobs.ResultSent(u.JobId, time.Now())
		}
	}
	return nil
}

// onOffer verifies a signed job with the agent's own verifier (signature before parsing, device and
// organization, validity window, replay ledger), acknowledges it and reports a no-op result.
func (s *sessionState) onOffer(se *agentv1.SignedEnvelope) {
	a, f := s.a, s.a.f
	tr := f.trust()
	a.jobMu.Lock()
	ledger := ledgerFunc(func(id string) (bool, error) { return a.ledger[id], nil })
	a.jobMu.Unlock()
	v := &envelope.Verifier{Root: tr.root, DeviceID: a.ident.DeviceID, OrgID: a.ident.OrgID, SigningCerts: f.signingCerts(),
		Ledger: ledger, Now: time.Now}
	env, err := v.Open(se)
	if err != nil {
		if errors.Is(err, envelope.ErrReplay) && env != nil {
			// The server re-offered a job it has no update for yet: report the state again.
			f.count("job.reoffer")
			a.requeueJob(env.JobId)
			return
		}
		f.count("job.rejected")
		f.log.Warn("job envelope rejected", "agent", a.idx, "err", err)
		seq, _ := a.store.NextSeq()
		_ = s.stream.Send(&agentv1.ConnectRequest{Msg: &agentv1.ConnectRequest_SecurityEvent{SecurityEvent: &agentv1.SecurityEvent{
			Seq: seq, Kind: agentv1.SecurityEventKind_SECURITY_EVENT_KIND_BAD_SIGNATURE, Detail: err.Error()}}})
		return
	}
	now := time.Now()
	a.jobMu.Lock()
	a.ledger[env.JobId] = true
	a.jobMu.Unlock()
	f.jobs.Offered(env.JobId, now)
	f.count("job.accepted." + strings.ToLower(strings.TrimPrefix(env.Type.String(), "JOB_TYPE_")))
	a.queueJobUpdate(&agentv1.JobUpdate{JobId: env.JobId, Attempt: env.Attempt, State: agentv1.JobState_JOB_STATE_ACCEPTED})
	if env.Type == agentv1.JobType_JOB_TYPE_INVENTORY_FULL {
		select {
		case a.invNow <- struct{}{}:
		default:
		}
	}
	jobID, attempt := env.JobId, env.Attempt
	time.AfterFunc(jitterDur(a.rng, f.cfg.JobExecTime, 0.5), func() {
		t := time.Now().Unix()
		a.queueJobUpdate(&agentv1.JobUpdate{JobId: jobID, Attempt: attempt, State: agentv1.JobState_JOB_STATE_SUCCEEDED,
			Result: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, DetectionPassed: true, AlreadySatisfied: true,
				Message: "loadsim: no-op job", StartedAt: t, FinishedAt: t}})
	})
}

type ledgerFunc func(string) (bool, error)

func (l ledgerFunc) Seen(id string) (bool, error) { return l(id) }

// queueJobUpdate numbers an update, keeps it until the server acknowledges it and wakes the stream.
func (a *simAgent) queueJobUpdate(u *agentv1.JobUpdate) {
	u.Seq, _ = a.store.NextSeq()
	a.jobMu.Lock()
	a.outbox = append(a.outbox, u)
	a.jobMu.Unlock()
	select {
	case a.kick <- struct{}{}:
	default:
	}
}

// requeueJob answers a re-offer: the agent already holds the job, so it simply repeats its state.
func (a *simAgent) requeueJob(id string) {
	a.jobMu.Lock()
	var attempt uint32
	pending := false
	for _, u := range a.outbox {
		if u.JobId == id {
			attempt, pending = u.Attempt, true
			break
		}
	}
	a.jobMu.Unlock()
	if pending {
		a.queueJobUpdate(&agentv1.JobUpdate{JobId: id, Attempt: attempt, State: agentv1.JobState_JOB_STATE_ACCEPTED})
		return
	}
	// Already acknowledged and finished: say so again so the server stops offering it.
	a.queueJobUpdate(&agentv1.JobUpdate{JobId: id, State: agentv1.JobState_JOB_STATE_SUCCEEDED,
		Result: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, DetectionPassed: true, AlreadySatisfied: true}})
}

// track remembers when an acknowledged report was sent, to measure the round trip.
func (s *sessionState) track(seq uint64, kind string, at time.Time) {
	s.pend[seq] = pending{kind, at}
	s.a.f.inflight.Add(1)
}
