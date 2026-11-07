// Package envelope signs and verifies job envelopes (docs/PROTOCOL.md §5).
//
// The signature covers the exact serialized payload bytes prefixed with a
// domain separator, and the verifier checks the signature BEFORE parsing.
package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/shared/pkix"
)

const (
	jobDomain = "librepatch/job/v1\x00"
	// MaxLifetime caps expires_at - issued_at so replay ledgers stay bounded.
	MaxLifetime = 30 * 24 * time.Hour
	// ClockSkew tolerated on issued_at.
	ClockSkew = 5 * time.Minute
	// MaxPayload bounds the payload size accepted by verifiers.
	MaxPayload = 1 << 20
)

// Verification errors map to SecurityEvent kinds.
var (
	ErrUnknownKey   = errors.New("envelope: unknown or invalid signing key")
	ErrBadSignature = errors.New("envelope: bad signature")
	ErrMalformed    = errors.New("envelope: malformed payload")
	ErrWrongDevice  = errors.New("envelope: not addressed to this device")
	ErrExpired      = errors.New("envelope: outside validity window")
	ErrReplay       = errors.New("envelope: job already seen")
	ErrUnsupported  = errors.New("envelope: unsupported version or type")
)

// Sign serializes env and signs it with key. keyID identifies the signing cert.
func Sign(key ed25519.PrivateKey, keyID []byte, env *agentv1.JobEnvelope) (*agentv1.SignedEnvelope, error) {
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(env)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxPayload {
		return nil, fmt.Errorf("envelope: payload too large: %d > %d", len(payload), MaxPayload)
	}
	sb, err := signedBytes(payload)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, sb)
	return &agentv1.SignedEnvelope{Payload: payload, Signature: sig, KeyId: append([]byte(nil), keyID...)}, nil
}

func signedBytes(payload []byte) ([]byte, error) {
	maxInt := int(^uint(0) >> 1)
	if len(payload) > maxInt-len(jobDomain) {
		return nil, errors.New("envelope: payload too large")
	}
	b := make([]byte, 0, len(jobDomain)+len(payload))
	b = append(b, jobDomain...)
	return append(b, payload...), nil
}

// Ledger remembers job IDs to prevent replay.
type Ledger interface {
	// Seen reports whether jobID was accepted before.
	Seen(jobID string) (bool, error)
}

// Verifier checks envelopes for one device.
type Verifier struct {
	Root     *x509.Certificate
	DeviceID string
	OrgID    string
	// SigningCerts are candidate job-signing certificates (from enrollment/HelloAck).
	SigningCerts []*x509.Certificate
	// RevokedKeyIDs are hex key IDs revoked by root-signed statements.
	RevokedKeyIDs map[string]bool
	Ledger        Ledger
	Now           func() time.Time
}

// Open verifies se and returns the parsed envelope. Order follows PROTOCOL §5.
func (v *Verifier) Open(se *agentv1.SignedEnvelope) (*agentv1.JobEnvelope, error) {
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if se == nil || len(se.Payload) == 0 || len(se.Payload) > MaxPayload {
		return nil, ErrMalformed
	}
	// 1. key_id -> valid signing cert directly under the pinned root.
	var pub ed25519.PublicKey
	for _, c := range v.SigningCerts {
		if !bytes.Equal(pkix.KeyID(c), se.KeyId) {
			continue
		}
		if v.RevokedKeyIDs[hex.EncodeToString(se.KeyId)] {
			return nil, fmt.Errorf("%w: key revoked", ErrUnknownKey)
		}
		if err := pkix.VerifyJobSigningCert(v.Root, c, now); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnknownKey, err)
		}
		pub = c.PublicKey.(ed25519.PublicKey)
		break
	}
	if pub == nil {
		return nil, ErrUnknownKey
	}
	// 2. signature over the raw bytes, before parsing.
	sb, err := signedBytes(se.Payload)
	if err != nil { // cannot happen for a payload within MaxPayload (checked above); refuse rather than guess
		return nil, ErrMalformed
	}
	if !ed25519.Verify(pub, sb, se.Signature) {
		return nil, ErrBadSignature
	}
	// 3. parse + version/type.
	env := &agentv1.JobEnvelope{}
	if err := proto.Unmarshal(se.Payload, env); err != nil {
		return nil, ErrMalformed
	}
	if env.Version != 1 || env.Type == agentv1.JobType_JOB_TYPE_UNSPECIFIED || env.JobId == "" {
		return nil, ErrUnsupported
	}
	// 4. addressed to us.
	if env.DeviceId != v.DeviceID || env.OrgId != v.OrgID {
		return nil, ErrWrongDevice
	}
	// 5. validity window.
	issued := time.Unix(env.IssuedAt, 0)
	expires := time.Unix(env.ExpiresAt, 0)
	if expires.Sub(issued) > MaxLifetime || !expires.After(issued) ||
		now.Before(issued.Add(-ClockSkew)) || now.After(expires) {
		return nil, ErrExpired
	}
	if len(env.Nonce) < 16 {
		return nil, ErrMalformed
	}
	// 6. replay.
	if v.Ledger != nil {
		seen, err := v.Ledger.Seen(env.JobId)
		if err != nil {
			return nil, err
		}
		if seen {
			// The envelope is fully verified at this point; callers that keep their
			// own job records can tell a server re-offer from a replay.
			return env, ErrReplay
		}
	}
	return env, nil
}
