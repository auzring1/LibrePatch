// Package store is the agent's transactional local state (bbolt): identity,
// trusted signing certs, the result outbox, the job ledger and inventory revs.
package store

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"
)

var (
	bIdentity = []byte("identity")
	bMeta     = []byte("meta")
	bOutbox   = []byte("outbox")
	bLedger   = []byte("ledger")
	bJobs     = []byte("jobs")
	kIdentity = []byte("identity")
)

// Identity is the enrolled device identity.
type Identity struct {
	DeviceID string `json:"device_id"`
	OrgID    string `json:"org_id"`
	// Status: "pending" (awaiting approval), "active", "rejected".
	Status     string   `json:"status"`
	Ticket     string   `json:"ticket,omitempty"`
	KeyName    string   `json:"key_name"`
	KeyGen     int      `json:"key_gen"`
	CertDER    []byte   `json:"cert_der,omitempty"`
	IssuingDER []byte   `json:"issuing_der,omitempty"`
	RootDER    []byte   `json:"root_der,omitempty"`
	SigningDER [][]byte `json:"signing_der,omitempty"`
}

// Store wraps a bbolt database.
type Store struct{ db *bolt.DB }

// Open opens (and locks) the state file. A second agent instance fails here.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		if errors.Is(err, berrors.ErrTimeout) {
			return nil, errors.New("agent state is locked: another agent instance is running")
		}
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bIdentity, bMeta, bOutbox, bLedger, bJobs} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Identity returns the stored identity, or nil.
func (s *Store) Identity() (*Identity, error) {
	var id *Identity
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bIdentity).Get(kIdentity)
		if v == nil {
			return nil
		}
		id = &Identity{}
		return json.Unmarshal(v, id)
	})
	return id, err
}

// SaveIdentity replaces the identity.
func (s *Store) SaveIdentity(id *Identity) error {
	b, err := json.Marshal(id)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bIdentity).Put(kIdentity, b) })
}

// GetMeta / SetMeta store small values (revisions, hashes).
func (s *Store) GetMeta(key string) []byte {
	var out []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bMeta).Get([]byte(key)); v != nil {
			out = append([]byte(nil), v...)
		}
		return nil
	})
	return out
}

// SetMeta sets a meta value.
func (s *Store) SetMeta(key string, val []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bMeta).Put([]byte(key), val) })
}

// GetUint / SetUint are helpers for counters.
func (s *Store) GetUint(key string) uint64 {
	v := s.GetMeta(key)
	if len(v) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(v)
}

// SetUint stores a counter.
func (s *Store) SetUint(key string, v uint64) error {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return s.SetMeta(key, b[:])
}

// NextSeq returns a new, persisted, monotonically increasing sequence number.
func (s *Store) NextSeq() (uint64, error) {
	var seq uint64
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bMeta)
		if v := b.Get([]byte("seq")); len(v) == 8 {
			seq = binary.BigEndian.Uint64(v)
		}
		seq++
		var out [8]byte
		binary.BigEndian.PutUint64(out[:], seq)
		return b.Put([]byte("seq"), out[:])
	})
	return seq, err
}

// OutboxPut queues a serialized message under seq until acknowledged.
func (s *Store) OutboxPut(seq uint64, msg []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		var k [8]byte
		binary.BigEndian.PutUint64(k[:], seq)
		return tx.Bucket(bOutbox).Put(k[:], msg)
	})
}

// OutboxAck removes the entry for seq.
func (s *Store) OutboxAck(seq uint64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		var k [8]byte
		binary.BigEndian.PutUint64(k[:], seq)
		return tx.Bucket(bOutbox).Delete(k[:])
	})
}

// OutboxAll returns queued messages in seq order.
func (s *Store) OutboxAll() (map[uint64][]byte, []uint64, error) {
	m := map[uint64][]byte{}
	var order []uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bOutbox).ForEach(func(k, v []byte) error {
			seq := binary.BigEndian.Uint64(k)
			m[seq] = append([]byte(nil), v...)
			order = append(order, seq)
			return nil
		})
	})
	return m, order, err
}

// OutboxLen counts queued messages.
func (s *Store) OutboxLen() int {
	n := 0
	_ = s.db.View(func(tx *bolt.Tx) error { n = tx.Bucket(bOutbox).Stats().KeyN; return nil })
	return n
}

// LedgerSeen reports whether a job ID was accepted before (replay protection).
func (s *Store) LedgerSeen(jobID string) (bool, error) {
	seen := false
	err := s.db.View(func(tx *bolt.Tx) error { seen = tx.Bucket(bLedger).Get([]byte(jobID)) != nil; return nil })
	return seen, err
}

// LedgerRecord remembers jobID until expires (+24h, pruned by LedgerPrune).
func (s *Store) LedgerRecord(jobID string, expires time.Time) error {
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], uint64(expires.Add(24*time.Hour).Unix())) // #nosec G115
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bLedger).Put([]byte(jobID), v[:]) })
}

// LedgerPrune removes expired ledger entries.
func (s *Store) LedgerPrune(now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bLedger)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(v) == 8 && int64(binary.BigEndian.Uint64(v)) < now.Unix() { // #nosec G115
				if err := c.Delete(); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// Ledger adapts the store to envelope.Ledger.
type Ledger struct{ S *Store }

// Seen implements envelope.Ledger.
func (l Ledger) Seen(id string) (bool, error) { return l.S.LedgerSeen(id) }

// LoadSnapshot returns the persisted acknowledged snapshot (item key -> hash).
func (s *Store) LoadSnapshot(name string) (map[string][]byte, error) {
	out := map[string][]byte{}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("snap:" + name))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			out[string(k)] = append([]byte(nil), v...)
			return nil
		})
	})
	return out, err
}

// SaveSnapshot atomically replaces the persisted snapshot.
func (s *Store) SaveSnapshot(name string, snap map[string][]byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bn := []byte("snap:" + name)
		if tx.Bucket(bn) != nil {
			if err := tx.DeleteBucket(bn); err != nil {
				return err
			}
		}
		b, err := tx.CreateBucket(bn)
		if err != nil {
			return err
		}
		for k, v := range snap {
			if err := b.Put([]byte(k), v); err != nil {
				return err
			}
		}
		return nil
	})
}

// JobPut stores a job record (opaque bytes owned by the jobs package).
func (s *Store) JobPut(id string, rec []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bJobs).Put([]byte(id), rec) })
}

// JobGet returns a job record, or nil.
func (s *Store) JobGet(id string) []byte {
	var out []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bJobs).Get([]byte(id)); v != nil {
			out = append([]byte(nil), v...)
		}
		return nil
	})
	return out
}

// JobAll returns every job record keyed by job ID.
func (s *Store) JobAll() (map[string][]byte, error) {
	out := map[string][]byte{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bJobs).ForEach(func(k, v []byte) error {
			out[string(k)] = append([]byte(nil), v...)
			return nil
		})
	})
	return out, err
}

// JobDelete removes a job record.
func (s *Store) JobDelete(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bJobs).Delete([]byte(id)) })
}
