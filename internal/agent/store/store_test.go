package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStore(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := Open(p); err == nil {
		t.Fatal("second instance must not open a locked state file")
	}
	if id, _ := s.Identity(); id != nil {
		t.Fatal("expected empty identity")
	}
	if err := s.SaveIdentity(&Identity{DeviceID: "d", Status: "active", KeyGen: 1}); err != nil {
		t.Fatal(err)
	}
	if id, _ := s.Identity(); id == nil || id.DeviceID != "d" {
		t.Fatal("identity not persisted")
	}
	a, _ := s.NextSeq()
	b, _ := s.NextSeq()
	if b != a+1 {
		t.Fatalf("seq not monotonic: %d %d", a, b)
	}
	_ = s.OutboxPut(b, []byte("x"))
	if s.OutboxLen() != 1 {
		t.Fatal("outbox")
	}
	_ = s.OutboxAck(b)
	if s.OutboxLen() != 0 {
		t.Fatal("outbox ack")
	}
	_ = s.LedgerRecord("job-1", time.Now().Add(-48*time.Hour))
	_ = s.LedgerRecord("job-2", time.Now().Add(time.Hour))
	if seen, _ := s.LedgerSeen("job-1"); !seen {
		t.Fatal("ledger")
	}
	_ = s.LedgerPrune(time.Now())
	if seen, _ := s.LedgerSeen("job-1"); seen {
		t.Fatal("expired ledger entry not pruned")
	}
	if seen, _ := s.LedgerSeen("job-2"); !seen {
		t.Fatal("live ledger entry pruned")
	}
}
