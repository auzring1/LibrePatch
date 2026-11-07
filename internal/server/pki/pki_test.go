package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/server/kek"
	spkix "github.com/auzring1/librepatch/internal/shared/pkix"
)

func newAuthority(t *testing.T) (*Hierarchy, *Authority) {
	t.Helper()
	h, err := NewHierarchy("Test Org", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return h, NewAuthority(h.Root.Cert, h.Issuing, h.JobSigning)
}

func csr(t *testing.T, curve elliptic.Curve) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestDeviceCertIssueAndVerify(t *testing.T) {
	_, a := newAuthority(t)
	id := uuid.New()
	now := time.Now()
	cert, err := a.IssueDeviceCert(csr(t, elliptic.P256()), id, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != id.String() {
		t.Fatalf("CN = %q; CSR subject must be ignored", cert.Subject.CommonName)
	}
	ident, err := a.VerifyDeviceCert(cert, now, 0)
	if err != nil || ident.DeviceID != id || ident.Expired {
		t.Fatalf("verify: %+v %v", ident, err)
	}
	// Expired but within grace -> Expired=true.
	ident, err = a.VerifyDeviceCert(cert, now.Add(2*time.Hour), 24*time.Hour)
	if err != nil || !ident.Expired {
		t.Fatalf("grace verify: %+v %v", ident, err)
	}
	// Past grace -> error.
	if _, err := a.VerifyDeviceCert(cert, now.Add(48*time.Hour), 24*time.Hour); err == nil {
		t.Fatal("expected failure past grace")
	}
}

func TestDeviceCSRMustBeP256(t *testing.T) {
	_, a := newAuthority(t)
	if _, err := a.IssueDeviceCert(csr(t, elliptic.P384()), uuid.New(), time.Hour, time.Now()); err == nil {
		t.Fatal("expected P-384 CSR to be rejected")
	}
	if _, err := a.IssueDeviceCert([]byte("junk"), uuid.New(), time.Hour, time.Now()); err == nil {
		t.Fatal("expected junk CSR to be rejected")
	}
}

func TestForeignCAIsRejected(t *testing.T) {
	_, a := newAuthority(t)
	_, other := newAuthority(t)
	cert, err := other.IssueDeviceCert(csr(t, elliptic.P256()), uuid.New(), time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyDeviceCert(cert, time.Now(), time.Hour); err == nil {
		t.Fatal("certificate from another CA must be rejected")
	}
}

func TestGatewayCertIsNotAClientCert(t *testing.T) {
	_, a := newAuthority(t)
	gw, err := a.IssueGatewayCert([]string{"agents.example.com", "10.0.0.5"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyDeviceCert(gw.Cert, time.Now(), 0); err == nil {
		t.Fatal("gateway (serverAuth) cert must not verify as a device client cert")
	}
	if len(gw.Cert.IPAddresses) != 1 || gw.Cert.DNSNames[0] != "agents.example.com" {
		t.Fatalf("SANs: %v %v", gw.Cert.DNSNames, gw.Cert.IPAddresses)
	}
}

func TestJobSigningCertRules(t *testing.T) {
	h, a := newAuthority(t)
	if err := spkix.VerifyJobSigningCert(h.Root.Cert, h.JobSigning.Cert, time.Now()); err != nil {
		t.Fatalf("legit job-signing cert rejected: %v", err)
	}
	// The issuing CA must not be able to mint a job-signing cert that agents accept.
	pub, _, _ := ed25519GenerateKey()
	tmpl := &x509.Certificate{
		SerialNumber: mustSerial(), Subject: pkix.Name{CommonName: "evil"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asnOID{spkix.OIDJobSigning},
		BasicConstraintsValid: true,
	}
	evil, err := createCert(tmpl, a.Issuing.Cert, pub, a.Issuing.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := spkix.VerifyJobSigningCert(h.Root.Cert, evil, time.Now()); err == nil {
		t.Fatal("job-signing cert issued by the issuing CA must be rejected")
	}
	// Root-issued cert without the EKU is rejected too.
	tmpl.UnknownExtKeyUsage = nil
	noEKU, err := createCert(tmpl, h.Root.Cert, pub, h.Root.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := spkix.VerifyJobSigningCert(h.Root.Cert, noEKU, time.Now()); err == nil {
		t.Fatal("cert without job-signing EKU must be rejected")
	}
}

func TestKeySealing(t *testing.T) {
	h, _ := newAuthority(t)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	s, _ := kek.New(key)
	enc, err := SealWithKEK(s, kek.PurposeIssuingKey, h.Issuing.Key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithKEK(s, kek.PurposeIssuingKey, enc); err != nil {
		t.Fatal(err)
	}
	if _, err := SealWithPassphrase("short", h.Root.Key); err == nil {
		t.Fatal("short passphrase must be rejected")
	}
	renc, err := SealWithPassphrase("correct horse battery staple", h.Root.Key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithPassphrase("wrong passphrase!!!!", renc); err == nil {
		t.Fatal("wrong passphrase must fail")
	}
	k, err := OpenWithPassphrase("correct horse battery staple", renc)
	if err != nil {
		t.Fatal(err)
	}
	if !k.Public().(*ecdsa.PublicKey).Equal(h.Root.Key.Public()) {
		t.Fatal("unsealed root key mismatch")
	}
}
