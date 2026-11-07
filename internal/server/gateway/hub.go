package gateway

import (
	"sync"

	"github.com/google/uuid"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// Hub tracks the live stream of each connected device (one per device).
type Hub struct {
	mu    sync.Mutex
	conns map[uuid.UUID]*conn
}

// NewHub creates an empty hub.
func NewHub() *Hub { return &Hub{conns: make(map[uuid.UUID]*conn)} }

type conn struct {
	deviceID uuid.UUID
	serial   string
	remote   string
	stream   agentv1.AgentChannelService_ConnectServer
	sendMu   sync.Mutex
	kill     chan string
	once     sync.Once
	stage    *chunkStage // only touched by the connection's handler goroutine
}

func newConn(id uuid.UUID, serial, remote string, st agentv1.AgentChannelService_ConnectServer) *conn {
	return &conn{deviceID: id, serial: serial, remote: remote, stream: st, kill: make(chan string, 1)}
}

func (c *conn) send(m *agentv1.ConnectResponse) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.stream.Send(m)
}

// close asks the stream handler to end with a GoAway carrying reason.
func (c *conn) close(reason string) {
	c.once.Do(func() { c.kill <- reason })
}

// register installs c, returning the connection it supersedes (if any).
func (h *Hub) register(c *conn) *conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	prev := h.conns[c.deviceID]
	h.conns[c.deviceID] = c
	return prev
}

// unregister removes c if it is still the current connection.
func (h *Hub) unregister(c *conn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conns[c.deviceID] == c {
		delete(h.conns, c.deviceID)
		return true
	}
	return false
}

// Disconnect ends the device's live stream immediately (e.g. on revocation).
func (h *Hub) Disconnect(deviceID uuid.UUID, reason string) {
	h.mu.Lock()
	c := h.conns[deviceID]
	h.mu.Unlock()
	if c != nil {
		c.close(reason)
	}
}

// Online reports whether a device currently has a live stream.
func (h *Hub) Online(deviceID uuid.UUID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.conns[deviceID]
	return ok
}

// Count returns the number of live streams.
func (h *Hub) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.conns)
}

// Offer sends a signed job envelope to the device's live stream.
func (h *Hub) Offer(deviceID uuid.UUID, se *agentv1.SignedEnvelope) bool {
	h.mu.Lock()
	c := h.conns[deviceID]
	h.mu.Unlock()
	if c == nil {
		return false
	}
	return c.send(&agentv1.ConnectResponse{Msg: &agentv1.ConnectResponse_JobOffer{JobOffer: se}}) == nil
}
