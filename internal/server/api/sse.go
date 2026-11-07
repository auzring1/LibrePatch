package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/server/auth"
)

type sseLimiter struct {
	mu    sync.Mutex
	max   int
	count map[uuid.UUID]int
}

func newSSELimiter(max int) *sseLimiter { return &sseLimiter{max: max, count: map[uuid.UUID]int{}} }

func (l *sseLimiter) acquire(u uuid.UUID) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.count[u] >= l.max {
		return false
	}
	l.count[u]++
	return true
}

func (l *sseLimiter) release(u uuid.UUID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.count[u]--; l.count[u] <= 0 {
		delete(l.count, u)
	}
}

// events streams device events as Server-Sent Events.
func (s *server) events(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	if !s.sse.acquire(p.UserID) {
		writeError(w, http.StatusTooManyRequests, "too_many_streams", "Too many open event streams.")
		return
	}
	defer s.sse.release(p.UserID)
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // long-lived stream
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "retry: 5000\n\n")
	_ = rc.Flush()

	ch, cancel := s.Events.Subscribe(p.OrgID)
	defer cancel()
	// Site-limited callers only get events about devices of their sites (decided once per device).
	var (
		limited bool
		seen    map[uuid.UUID]bool
	)
	scope := func() {
		limited = !p.Access.OrgHas(auth.PermDevicesRead)
		seen = map[uuid.UUID]bool{}
	}
	scope()
	visible := func(device uuid.UUID) bool {
		if !limited {
			return true
		}
		if device == uuid.Nil {
			return false
		}
		v, ok := seen[device]
		if !ok {
			v = s.deviceInScope(r.Context(), p, auth.PermDevicesRead, device)
			seen[device] = v
		}
		return v
	}
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	// Check the caller again every minute: signing out, an expired session, a revoked or expired API token, a disabled
	// account or a withdrawn permission must end the stream, not just stop new ones.
	recheck := time.NewTicker(time.Minute)
	defer recheck.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			if !visible(e.DeviceID) {
				continue
			}
			b, _ := json.Marshal(e)
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, b); err != nil {
				return
			}
			_ = rc.Flush()
		case <-ping.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			_ = rc.Flush()
		case <-recheck.C:
			np, err := s.reauthenticate(r)
			if err != nil || !np.Access.HasAnywhere(auth.PermDevicesRead) {
				return
			}
			p = np
			scope()
		}
	}
}
