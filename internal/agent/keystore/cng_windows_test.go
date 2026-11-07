//go:build windows

package keystore

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"
)

// TestCNGKeyLifecycle needs an elevated process (machine keys); CI runners are.
func TestCNGKeyLifecycle(t *testing.T) {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "LibrePatch-UnitTest-" + hex.EncodeToString(b)
	ks := Default("")
	signer, provider, err := ks.Create(name)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = ks.Delete(name) })
	t.Logf("key provider: %s", provider)

	digest := sha256.Sum256([]byte("current"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pub := signer.Public().(*ecdsa.PublicKey)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("signature does not verify")
	}
	// The key must be usable for a CSR (what enrollment does).
	der, err := CSR(signer)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("csr: %v", err)
	}
	reopened, err := ks.Open(name)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !reopened.Public().(*ecdsa.PublicKey).Equal(pub) {
		t.Fatal("reopened key differs")
	}
	if err := ks.Delete(name); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := ks.Open(name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted key still opens: %v", err)
	}
}
