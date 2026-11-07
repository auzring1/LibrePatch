package envelope

import (
	"crypto/ed25519"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	spkix "github.com/auzring1/librepatch/internal/shared/pkix"
)

// FuzzOpenSigned feeds arbitrary payloads that carry a VALID signature, so the parsing and field
// checks after the signature step see hostile input (a compromised server can sign anything).
// Open must never panic, and anything it accepts must satisfy the invariants the engine relies on.
func FuzzOpenSigned(f *testing.F) {
	fx := newFixture(f)
	good, _ := proto.Marshal(job(time.Now()))
	f.Add(good)
	f.Add([]byte{})
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, payload []byte) {
		se := &agentv1.SignedEnvelope{Payload: payload, KeyId: spkix.KeyID(fx.signer)}
		sb, err := signedBytes(payload)
		if err != nil {
			return
		}
		se.Signature = ed25519.Sign(fx.key, sb)
		env, err := fx.verifier(memLedger{}).Open(se)
		if err != nil {
			return
		}
		if env.DeviceId != "dev" || env.OrgId != "org" || env.JobId == "" || len(env.Nonce) < 16 {
			t.Fatalf("accepted an envelope that violates the invariants: %+v", env)
		}
		if env.ExpiresAt-env.IssuedAt > int64(MaxLifetime/time.Second) {
			t.Fatalf("accepted a lifetime over the maximum")
		}
	})
}

// FuzzOpenRaw feeds arbitrary unsigned envelopes: nothing may be accepted, nothing may panic.
func FuzzOpenRaw(f *testing.F) {
	fx := newFixture(f)
	f.Add([]byte("x"), []byte("y"), spkix.KeyID(fx.signer))
	f.Fuzz(func(t *testing.T, payload, sig, keyID []byte) {
		if _, err := fx.verifier(memLedger{}).Open(&agentv1.SignedEnvelope{Payload: payload, Signature: sig, KeyId: keyID}); err == nil {
			t.Fatal("an envelope without a valid signature was accepted")
		}
	})
}
