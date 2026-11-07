// Package events is an in-process pub/sub broker feeding Server-Sent Events.
// Events carry identifiers only; clients re-fetch data through the
// authorized REST API, so the stream never leaks data a user cannot read.
package events

import (
	"sync"

	"github.com/google/uuid"
)

// Event types.
const (
	DeviceOnline      = "device.online"
	DeviceOffline     = "device.offline"
	DeviceEnrolled    = "device.enrolled"
	DeviceUpdated     = "device.updated"
	JobUpdated        = "job.updated"
	DeploymentUpdated = "deployment.updated"
	UpdatesUpdated    = "updates.updated"
)

// Event is published to subscribers of an org.
type Event struct {
	Type     string    `json:"type"`
	DeviceID uuid.UUID `json:"device_id"`
	// JobID and DeploymentID are set for job.* and deployment.* events.
	JobID        uuid.UUID `json:"job_id,omitempty"`
	DeploymentID uuid.UUID `json:"deployment_id,omitempty"`
}

// Broker fans out events per organization.
type Broker struct {
	mu   sync.Mutex
	subs map[uuid.UUID]map[chan Event]struct{}
}

// NewBroker creates a broker.
func NewBroker() *Broker { return &Broker{subs: make(map[uuid.UUID]map[chan Event]struct{})} }

// Subscribe returns a channel of events for org and a cancel func.
func (b *Broker) Subscribe(org uuid.UUID) (<-chan Event, func()) {
	ch := make(chan Event, 64)
	b.mu.Lock()
	if b.subs[org] == nil {
		b.subs[org] = make(map[chan Event]struct{})
	}
	b.subs[org][ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		if _, ok := b.subs[org][ch]; ok {
			delete(b.subs[org], ch)
			close(ch)
		}
		b.mu.Unlock()
	}
}

// Publish delivers e to all org subscribers without blocking; slow
// subscribers drop events (they resync on the next one or on reconnect).
func (b *Broker) Publish(org uuid.UUID, e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs[org] {
		select {
		case ch <- e:
		default:
		}
	}
}
