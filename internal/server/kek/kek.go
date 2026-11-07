// Package kek seals and opens secrets at rest with the server key-encryption
// key (AES-256-GCM). Every sealed value is bound to a purpose label via AAD so
// a ciphertext for one purpose cannot be substituted for another.
package kek

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
)

const formatV1 byte = 1

// Purpose labels used across the server. Never reuse a label for a new kind of data.
const (
	PurposeTOTP          = "mfa-totp/v1"
	PurposeSetupTOTP     = "setup-totp/v1"
	PurposeIssuingKey    = "pki-issuing-key/v1"
	PurposeJobSigningKey = "pki-job-signing-key/v1"
	PurposeGatewayKey    = "pki-gateway-key/v1"
)

// Sealer encrypts and decrypts with one master key.
type Sealer struct {
	aead  cipher.AEAD
	keyID [4]byte
}

// New creates a Sealer from a 32-byte key.
func New(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("kek: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte("librepatch/kek-id/v1\x00"), key...))
	s := &Sealer{aead: aead}
	copy(s.keyID[:], sum[:4])
	return s, nil
}

// KeyID is a short fingerprint of the key (8 hex digits). It is safe to show: it lets a person check that the key they hold
// is the one a server generated, without revealing anything about the key.
func (s *Sealer) KeyID() string { return hex.EncodeToString(s.keyID[:]) }

// Seal encrypts plaintext for the given purpose.
// Layout: version(1) || keyID(4) || nonce(12) || ciphertext+tag.
func (s *Sealer) Seal(purpose string, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	baseSize := uint64(1 + 4 + len(nonce) + s.aead.Overhead()) // #nosec G115 -- sum of small non-negative lengths
	totalSize := baseSize + uint64(len(plaintext))
	if totalSize > uint64(math.MaxInt) {
		return nil, errors.New("kek: plaintext too large")
	}

	out := make([]byte, 0, int(totalSize))
	out = append(out, formatV1)
	out = append(out, s.keyID[:]...)
	out = append(out, nonce...)
	return s.aead.Seal(out, nonce, plaintext, s.aad(purpose)), nil
}

// Open decrypts a value produced by Seal for the same purpose.
func (s *Sealer) Open(purpose string, sealed []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(sealed) < 1+4+ns+s.aead.Overhead() || sealed[0] != formatV1 {
		return nil, errors.New("kek: malformed sealed value")
	}
	if [4]byte(sealed[1:5]) != s.keyID {
		return nil, errors.New("kek: value was sealed with a different master key")
	}
	nonce := sealed[5 : 5+ns]
	pt, err := s.aead.Open(nil, nonce, sealed[5+ns:], s.aad(purpose))
	if err != nil {
		return nil, fmt.Errorf("kek: decrypt failed (wrong purpose or tampered data)")
	}
	return pt, nil
}

func (s *Sealer) aad(purpose string) []byte {
	return append([]byte("librepatch/kek/v1\x00"), purpose...)
}
