// Package pkix holds certificate conventions shared by the server and agent.
package pkix

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// OIDJobSigning is the extended key usage that marks a job-signing certificate.
//
// PLACEHOLDER: 1.3.6.1.4.1.32473 is IANA's documentation enterprise number
// (RFC 5612). It must be replaced with our registered PEN before release
// (docs/DECISIONS.md O4). Agents will accept both during a transition.
var OIDJobSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 7231, 1, 1}

// CertBackdate is how far NotBefore is set in the past on every certificate
// we issue, to tolerate clock skew. Lifetime computations must subtract it.
const CertBackdate = 5 * time.Minute

// Lifetime returns the intended validity period of a certificate we issued.
func Lifetime(c *x509.Certificate) time.Duration {
	return c.NotAfter.Sub(c.NotBefore) - CertBackdate
}

// DeviceURIPrefix is the URI SAN prefix carrying the device ID.
const DeviceURIPrefix = "urn:librepatch:device:"

// SPKIPin returns "sha256/<base64>" of the certificate's SubjectPublicKeyInfo.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256/" + base64.StdEncoding.EncodeToString(sum[:])
}

// KeyID is SHA-256 of the certificate's SubjectPublicKeyInfo.
func KeyID(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return sum[:]
}

// DeviceIDFromCert extracts the device UUID from the URI SAN.
func DeviceIDFromCert(cert *x509.Certificate) (uuid.UUID, error) {
	var found []uuid.UUID
	for _, u := range cert.URIs {
		s := u.String()
		if strings.HasPrefix(s, DeviceURIPrefix) {
			id, err := uuid.Parse(strings.TrimPrefix(s, DeviceURIPrefix))
			if err != nil {
				return uuid.Nil, fmt.Errorf("device URI SAN is not a UUID: %w", err)
			}
			found = append(found, id)
		}
	}
	if len(found) != 1 {
		return uuid.Nil, fmt.Errorf("certificate must carry exactly one device URI SAN, found %d", len(found))
	}
	if cert.Subject.CommonName != found[0].String() {
		return uuid.Nil, errors.New("certificate CN does not match device URI SAN")
	}
	return found[0], nil
}

// DeviceURI returns the URI SAN for a device.
func DeviceURI(id uuid.UUID) *url.URL {
	u, _ := url.Parse(DeviceURIPrefix + id.String())
	return u
}

// VerifyJobSigningCert checks that cert is a valid job-signing certificate
// issued DIRECTLY by root: correct EKU, Ed25519 key, not a CA, in validity.
func VerifyJobSigningCert(root, cert *x509.Certificate, now time.Time) error {
	if err := cert.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("job-signing cert not issued by pinned root: %w", err)
	}
	if string(cert.RawIssuer) != string(root.RawSubject) {
		return errors.New("job-signing cert issuer does not match root subject")
	}
	if cert.IsCA {
		return errors.New("job-signing cert must not be a CA")
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		return errors.New("job-signing cert must carry an Ed25519 key")
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return errors.New("job-signing cert is outside its validity period")
	}
	hasEKU := false
	for _, o := range cert.UnknownExtKeyUsage {
		if o.Equal(OIDJobSigning) {
			hasEKU = true
		}
	}
	if !hasEKU {
		return errors.New("job-signing cert lacks the job-signing EKU")
	}
	return nil
}

// CheckDeviceCSR validates a device CSR: self-signature and ECDSA P-256 key.
func CheckDeviceCSR(der []byte) (*x509.CertificateRequest, error) {
	if len(der) == 0 || len(der) > 4096 {
		return nil, errors.New("CSR missing or too large")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature: %w", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("CSR key must be ECDSA P-256")
	}
	return csr, nil
}
