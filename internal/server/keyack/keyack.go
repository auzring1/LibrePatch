// Package keyack tracks whether the administrator has saved the master key that the stack generated for itself
// (decision D109). While it is pending, the server keeps the key in memory only to show it once on request.
package keyack

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/masterkey"
)

// ErrNotPending means there is no unacknowledged key to show or confirm.
var ErrNotPending = errors.New("the master key has already been saved")

// State is the acknowledgement state of the master key.
type State struct {
	db  dbq.DBTX
	now func() time.Time

	mu        sync.RWMutex
	pending   bool
	key       []byte
	keyID     string
	generated time.Time
}

// Load reads the state. A stack whose key was supplied by hand has no record and is never pending.
func Load(ctx context.Context, db dbq.DBTX, key []byte) (*State, error) {
	s := &State{db: db, now: time.Now}
	row, err := dbq.New(db).GetMasterKeyAck(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if row.AcknowledgedAt == nil {
		s.pending, s.keyID, s.generated = true, row.KeyID, row.GeneratedAt
		s.key = append([]byte(nil), key...)
	}
	return s, nil
}

// Pending reports whether the key still has to be saved. It is false for a nil State.
func (s *State) Pending() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pending
}

// Key is what the console shows while the key is pending.
type Key struct {
	Grouped     string
	KeyID       string
	GeneratedAt time.Time
}

// View returns the key to show, or ErrNotPending once it has been saved.
func (s *State) View() (Key, error) {
	if s == nil {
		return Key{}, ErrNotPending
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.pending {
		return Key{}, ErrNotPending
	}
	return Key{Grouped: masterkey.Grouped(s.key), KeyID: s.keyID, GeneratedAt: s.generated}, nil
}

// Confirms reports whether the text names the end of the key: the last six hexadecimal digits, which a person only knows
// if they looked at the key they saved.
func (s *State) Confirms(text string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.pending {
		return false
	}
	h := masterkey.Hex(s.key)
	want := h[len(h)-6:]
	got := ""
	for _, r := range text {
		switch {
		case r >= 'A' && r <= 'F':
			got += string(r + 32)
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			got += string(r)
		}
	}
	return got == want
}

// Acknowledge records that user saved the key and releases the copy kept in memory.
func (s *State) Acknowledge(ctx context.Context, user uuid.UUID) error {
	if s == nil {
		return ErrNotPending
	}
	n, err := dbq.New(s.db).AcknowledgeMasterKey(ctx, dbq.AcknowledgeMasterKeyParams{AcknowledgedAt: ptrTime(s.now()), AcknowledgedBy: &user})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotPending
	}
	s.mu.Lock()
	s.pending = false
	for i := range s.key {
		s.key[i] = 0
	}
	s.key = nil
	s.mu.Unlock()
	return nil
}

func ptrTime(t time.Time) *time.Time { return &t }
