package core

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/auzring1/librepatch/internal/server/pki"
	"github.com/auzring1/librepatch/internal/shared/pkix"
)

func TestVerifyPinnedChain(t *testing.T) {
	h, err := pki.NewHierarchy("t", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a := pki.NewAuthority(h.Root.Cert, h.Issuing, h.JobSigning)
	gw, err := a.IssueGatewayCert([]string{"agents.example.com"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	chain := []*x509.Certificate{gw.Cert, h.Issuing.Cert, h.Root.Cert}
	pin := pkix.SPKIPin(h.Root.Cert)
	if root, err := verifyPinnedChain(chain, "agents.example.com", pin); err != nil || !root.Equal(h.Root.Cert) {
		t.Fatalf("valid chain rejected: %v", err)
	}
	if _, err := verifyPinnedChain(chain, "evil.example.com", pin); err == nil {
		t.Fatal("hostname mismatch accepted")
	}
	// An attacker with a different (even valid-looking) CA must fail the pin.
	other, _ := pki.NewHierarchy("evil", time.Now())
	oa := pki.NewAuthority(other.Root.Cert, other.Issuing, other.JobSigning)
	ogw, _ := oa.IssueGatewayCert([]string{"agents.example.com"}, time.Now())
	if _, err := verifyPinnedChain([]*x509.Certificate{ogw.Cert, other.Issuing.Cert, other.Root.Cert}, "agents.example.com", pin); err == nil {
		t.Fatal("chain to a foreign root accepted")
	}
	// Pinned root present but leaf signed by someone else.
	if _, err := verifyPinnedChain([]*x509.Certificate{ogw.Cert, h.Issuing.Cert, h.Root.Cert}, "agents.example.com", pin); err == nil {
		t.Fatal("foreign leaf accepted")
	}
	if _, err := verifyPinnedChain([]*x509.Certificate{gw.Cert}, "agents.example.com", pin); err == nil {
		t.Fatal("incomplete chain accepted")
	}
}

func TestBackoff(t *testing.T) {
	b := &Backoff{Base: time.Second, Max: 10 * time.Second}
	for i := 0; i < 50; i++ {
		if d := b.Next(); d < 0 || d > 10*time.Second {
			t.Fatalf("backoff out of range: %v", d)
		}
	}
	b.Reset()
	if d := b.Next(); d > time.Second {
		t.Fatalf("after reset: %v", d)
	}
}

func TestRenewDueIgnoresBackdate(t *testing.T) {
	now := time.Now()
	// A freshly issued 12 s certificate (backdated 5 min) is not due yet.
	fresh := &x509.Certificate{NotBefore: now.Add(-pkix.CertBackdate), NotAfter: now.Add(12 * time.Second)}
	a := &Agent{Now: func() time.Time { return now }}
	if a.renewDue(fresh) {
		t.Fatal("fresh certificate considered due for renewal")
	}
	a.Now = func() time.Time { return now.Add(9 * time.Second) }
	if !a.renewDue(fresh) {
		t.Fatal("certificate with < 1/3 lifetime left not due")
	}
}
