// Package keystore manages the device's private key. On Windows the key lives
// in CNG (TPM-backed when available, otherwise a non-exportable software
// machine key) and never exists in agent memory. Other platforms use a 0600
// PEM file and are for development and integration tests only.
package keystore

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
)

// ErrNotFound means the named key does not exist.
var ErrNotFound = errors.New("key not found")

// Provider creates and opens ECDSA P-256 signing keys by name.
type Provider interface {
	// Create makes a new non-exportable key. It returns the provider used
	// (e.g. "tpm" or "software") so it can be recorded.
	Create(name string) (crypto.Signer, string, error)
	Open(name string) (crypto.Signer, error)
	Delete(name string) error
}

// CSR builds a PKCS#10 request for key. The subject is ignored by the
// server (it assigns the device ID), so it is left minimal.
func CSR(key crypto.Signer) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "librepatch-agent"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
}
