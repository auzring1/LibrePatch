package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	spkix "github.com/auzring1/librepatch/internal/shared/pkix"
)

type memLedger map[string]bool

func (m memLedger) Seen(id string) (bool, error) { return m[id], nil }

type fixture struct {
	root   *x509.Certificate
	signer *x509.Certificate
	key    ed25519.PrivateKey
}

func newFixture(t testing.TB) fixture {
	t.Helper()
	rk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour * 24),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rder, err := x509.CreateCertificate(rand.Reader, rt, rt, &rk.PublicKey, rk)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rder)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	st := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "jobs"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour * 24),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1OID{spkix.OIDJobSigning}}
	sder, err := x509.CreateCertificate(rand.Reader, st, root, pub, rk)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := x509.ParseCertificate(sder)
	return fixture{root, signer, key}
}

func job(now time.Time) *agentv1.JobEnvelope {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	return &agentv1.JobEnvelope{Version: 1, JobId: "job-1", OrgId: "org", DeviceId: "dev",
		IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Nonce: nonce,
		Type: agentv1.JobType_JOB_TYPE_INVENTORY_FULL,
		Body: &agentv1.JobEnvelope_Inventory{Inventory: &agentv1.InventoryBody{}}}
}

func (f fixture) verifier(l memLedger) *Verifier {
	return &Verifier{Root: f.root, DeviceID: "dev", OrgID: "org", SigningCerts: []*x509.Certificate{f.signer}, Ledger: l}
}

func TestSignVerify(t *testing.T) {
	f := newFixture(t)
	se, err := Sign(f.key, spkix.KeyID(f.signer), job(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	env, err := f.verifier(memLedger{}).Open(se)
	if err != nil {
		t.Fatal(err)
	}
	if env.JobId != "job-1" {
		t.Fatal(env.JobId)
	}
}

func TestVerifyRejections(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	sign := func(e *agentv1.JobEnvelope) *agentv1.SignedEnvelope {
		se, err := Sign(f.key, spkix.KeyID(f.signer), e)
		if err != nil {
			t.Fatal(err)
		}
		return se
	}
	tamper := sign(job(now))
	tamper.Payload[len(tamper.Payload)-1] ^= 0xff

	other := job(now)
	other.DeviceId = "someone-else"

	expired := job(now.Add(-2 * time.Hour))

	tooLong := job(now)
	tooLong.ExpiresAt = now.Add(31 * 24 * time.Hour).Unix()

	unknownKey := sign(job(now))
	unknownKey.KeyId = make([]byte, 32)

	// Same payload re-signed with a key whose cert isn't trusted.
	_, rogue, _ := ed25519.GenerateKey(rand.Reader)
	rogueSigned, _ := Sign(rogue, spkix.KeyID(f.signer), job(now))

	cases := []struct {
		name string
		se   *agentv1.SignedEnvelope
		l    memLedger
		want error
	}{
		{"tampered", tamper, memLedger{}, ErrBadSignature},
		{"rogue key", rogueSigned, memLedger{}, ErrBadSignature},
		{"wrong device", sign(other), memLedger{}, ErrWrongDevice},
		{"expired", sign(expired), memLedger{}, ErrExpired},
		{"lifetime cap", sign(tooLong), memLedger{}, ErrExpired},
		{"unknown key", unknownKey, memLedger{}, ErrUnknownKey},
		{"replay", sign(job(now)), memLedger{"job-1": true}, ErrReplay},
		{"empty", &agentv1.SignedEnvelope{}, memLedger{}, ErrMalformed},
	}
	for _, c := range cases {
		_, err := f.verifier(c.l).Open(c.se)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestRevokedKey(t *testing.T) {
	f := newFixture(t)
	se, _ := Sign(f.key, spkix.KeyID(f.signer), job(time.Now()))
	v := f.verifier(memLedger{})
	v.RevokedKeyIDs = map[string]bool{hexKey(spkix.KeyID(f.signer)): true}
	if _, err := v.Open(se); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("revoked key accepted: %v", err)
	}
}

func TestDomainSeparation(t *testing.T) {
	f := newFixture(t)
	payload, _ := proto.Marshal(job(time.Now()))
	// A signature over the raw payload (no domain prefix) must not verify.
	se := &agentv1.SignedEnvelope{Payload: payload, Signature: ed25519.Sign(f.key, payload), KeyId: spkix.KeyID(f.signer)}
	if _, err := f.verifier(memLedger{}).Open(se); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v", err)
	}
}
