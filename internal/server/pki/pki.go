// Package pki implements the internal certificate authority:
//
//	Root CA (P-384, 20y)            key sealed with the owner passphrase
//	 ├── Issuing CA (P-384, 5y)     key sealed with the server KEK
//	 │    ├── gateway server cert   key sealed with the server KEK
//	 │    └── device client certs   keys live on devices (CSR)
//	 └── Job-signing (Ed25519, 2y)  key sealed with the server KEK
//
// See docs/PROTOCOL.md §2.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"math/big"
	"net"
	"time"

	"github.com/google/uuid"

	spkix "github.com/auzring1/librepatch/internal/shared/pkix"
)

const (
	rootLifetime       = 20 * 365 * 24 * time.Hour
	issuingLifetime    = 5 * 365 * 24 * time.Hour
	jobSigningLifetime = 2 * 365 * 24 * time.Hour
	// GatewayLifetime is the gateway TLS certificate lifetime.
	GatewayLifetime = 90 * 24 * time.Hour
	backdate        = spkix.CertBackdate
)

// KeyPair is a certificate plus its private key.
type KeyPair struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// Hierarchy is the result of first-run CA creation.
type Hierarchy struct {
	Root       KeyPair
	Issuing    KeyPair
	JobSigning KeyPair
}

// NewHierarchy creates the root, issuing and job-signing material.
func NewHierarchy(orgName string, now time.Time) (*Hierarchy, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          mustSerial(),
		Subject:               pkix.Name{CommonName: brand.Name + " Root CA", Organization: []string{orgName}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(rootLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	root, err := createCert(rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("root: %w", err)
	}

	issKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	issTmpl := &x509.Certificate{
		SerialNumber:          mustSerial(),
		Subject:               pkix.Name{CommonName: brand.Name + " Issuing CA", Organization: []string{orgName}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(issuingLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		// EKU constraint: the issuing CA can never vouch for job-signing.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	issuing, err := createCert(issTmpl, root, &issKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("issuing: %w", err)
	}

	jobPub, jobKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	jobTmpl := &x509.Certificate{
		SerialNumber:          mustSerial(),
		Subject:               pkix.Name{CommonName: brand.Name + " Job Signing", Organization: []string{orgName}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(jobSigningLifetime),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asnOID{spkix.OIDJobSigning},
	}
	jobCert, err := createCert(jobTmpl, root, jobPub, rootKey)
	if err != nil {
		return nil, fmt.Errorf("job signing: %w", err)
	}
	return &Hierarchy{
		Root:       KeyPair{root, rootKey},
		Issuing:    KeyPair{issuing, issKey},
		JobSigning: KeyPair{jobCert, jobKey},
	}, nil
}

// Authority is the online CA used at runtime (no root key).
type Authority struct {
	Root       *x509.Certificate
	Issuing    KeyPair
	JobSigning KeyPair

	rootPool  *x509.CertPool
	interPool *x509.CertPool
}

// NewAuthority builds a runtime authority.
func NewAuthority(root *x509.Certificate, issuing, jobSigning KeyPair) *Authority {
	rp := x509.NewCertPool()
	rp.AddCert(root)
	ip := x509.NewCertPool()
	ip.AddCert(issuing.Cert)
	return &Authority{Root: root, Issuing: issuing, JobSigning: jobSigning, rootPool: rp, interPool: ip}
}

// IssueDeviceCert signs a device client certificate from a validated CSR.
func (a *Authority) IssueDeviceCert(csrDER []byte, deviceID uuid.UUID, lifetime time.Duration, now time.Time) (*x509.Certificate, error) {
	csr, err := spkix.CheckDeviceCSR(csrDER)
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(lifetime)
	if notAfter.After(a.Issuing.Cert.NotAfter) {
		notAfter = a.Issuing.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          mustSerial(),
		Subject:               pkix.Name{CommonName: deviceID.String(), Organization: []string{brand.Name + " device"}},
		URIs:                  []*urlURL{spkix.DeviceURI(deviceID)},
		NotBefore:             now.Add(-backdate),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	return createCert(tmpl, a.Issuing.Cert, csr.PublicKey, a.Issuing.Key)
}

// IssueGatewayCert creates a fresh gateway server key and certificate.
func (a *Authority) IssueGatewayCert(sans []string, now time.Time) (KeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          mustSerial(),
		Subject:               pkix.Name{CommonName: brand.Name + " Agent Gateway"},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(GatewayLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		}
	}
	if len(tmpl.DNSNames)+len(tmpl.IPAddresses) == 0 {
		return KeyPair{}, errors.New("gateway certificate needs at least one SAN")
	}
	cert, err := createCert(tmpl, a.Issuing.Cert, &key.PublicKey, a.Issuing.Key)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{cert, key}, nil
}

// DeviceIdentity is the result of verifying a client certificate.
type DeviceIdentity struct {
	DeviceID uuid.UUID
	Serial   string
	Cert     *x509.Certificate
	// Expired is true when the certificate is past NotAfter but inside the
	// renewal grace period; such identities may only call RenewCertificate.
	Expired bool
}

// VerifyDeviceCert verifies a client certificate chain against our CA.
// If the only problem is expiry within grace, it returns Expired=true.
func (a *Authority) VerifyDeviceCert(leaf *x509.Certificate, now time.Time, grace time.Duration) (*DeviceIdentity, error) {
	opts := x509.VerifyOptions{
		Roots:         a.rootPool,
		Intermediates: a.interPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime:   now,
	}
	expired := false
	if _, err := leaf.Verify(opts); err != nil {
		if now.After(leaf.NotAfter) && now.Before(leaf.NotAfter.Add(grace)) {
			opts.CurrentTime = leaf.NotAfter.Add(-time.Second)
			if _, err2 := leaf.Verify(opts); err2 != nil {
				return nil, err2
			}
			expired = true
		} else {
			return nil, err
		}
	}
	if leaf.IsCA {
		return nil, errors.New("client certificate must not be a CA")
	}
	id, err := spkix.DeviceIDFromCert(leaf)
	if err != nil {
		return nil, err
	}
	return &DeviceIdentity{DeviceID: id, Serial: SerialHex(leaf), Cert: leaf, Expired: expired}, nil
}

// SerialHex returns the lowercase hex serial used as the device_certs key.
func SerialHex(c *x509.Certificate) string { return fmt.Sprintf("%x", c.SerialNumber) }

// PublicKeySHA256 hashes a certificate's SPKI.
func PublicKeySHA256(c *x509.Certificate) []byte {
	s := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return s[:]
}

func createCert(tmpl, parent *x509.Certificate, pub any, signer crypto.Signer) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func mustSerial() *big.Int {
	// 128-bit positive serial (RFC 5280 allows up to 20 octets).
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		panic(fmt.Sprintf("pki: entropy failure: %v", err))
	}
	return n.Add(n, big.NewInt(1))
}
