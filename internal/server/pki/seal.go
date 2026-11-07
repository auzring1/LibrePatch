package pki

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"

	"github.com/auzring1/librepatch/internal/server/kek"
)

// Root-passphrase KDF parameters (argon2id). Root unlocks are rare, so we
// can afford a heavier cost than login hashing.
const (
	rootKDFTime    = 4
	rootKDFMemory  = 128 * 1024 // KiB
	rootKDFThreads = 2
	passFormatV1   = 1
	// MinRootPassphraseLen is enforced at setup.
	MinRootPassphraseLen = 16
)

// SealWithKEK marshals a private key (PKCS#8) and seals it with the KEK.
func SealWithKEK(s *kek.Sealer, purpose string, key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return s.Seal(purpose, der)
}

// OpenWithKEK reverses SealWithKEK.
func OpenWithKEK(s *kek.Sealer, purpose string, sealed []byte) (crypto.Signer, error) {
	der, err := s.Open(purpose, sealed)
	if err != nil {
		return nil, err
	}
	return parseSigner(der)
}

// SealWithPassphrase protects the root key with an owner passphrase.
// Layout: version(1) || salt(16) || nonce(12) || ciphertext.
func SealWithPassphrase(passphrase string, key crypto.Signer) ([]byte, error) {
	if len(passphrase) < MinRootPassphraseLen {
		return nil, fmt.Errorf("root passphrase must be at least %d characters", MinRootPassphraseLen)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	aead, err := passAEAD(passphrase, salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{passFormatV1}, salt...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, der, []byte("librepatch/root-key/v1")), nil
}

// OpenWithPassphrase unlocks the root key.
func OpenWithPassphrase(passphrase string, sealed []byte) (crypto.Signer, error) {
	if len(sealed) < 1+16+12+16 || sealed[0] != passFormatV1 {
		return nil, errors.New("malformed sealed root key")
	}
	aead, err := passAEAD(passphrase, sealed[1:17])
	if err != nil {
		return nil, err
	}
	der, err := aead.Open(nil, sealed[17:29], sealed[29:], []byte("librepatch/root-key/v1"))
	if err != nil {
		return nil, errors.New("wrong root passphrase")
	}
	return parseSigner(der)
}

func passAEAD(passphrase string, salt []byte) (cipher.AEAD, error) {
	k := argon2.IDKey([]byte(passphrase), salt, rootKDFTime, rootKDFMemory, rootKDFThreads, 32)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func parseSigner(der []byte) (crypto.Signer, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("key is not a signer")
	}
	return s, nil
}
