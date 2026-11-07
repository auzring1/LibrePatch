package peercache

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/auzring1/librepatch/internal/shared/pkix"
)

// verifyPeer checks that a peer's certificate chain ends in this installation's root and belongs to a device. Both ends
// present their device certificate (client authentication only), so the usual server-certificate checks are replaced by this.
func verifyPeer(chain []*x509.Certificate, root *x509.Certificate, now time.Time) error {
	if len(chain) == 0 {
		return errors.New("peercache: the peer sent no certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("peercache: peer certificate: %w", err)
	}
	if _, err := pkix.DeviceIDFromCert(chain[0]); err != nil {
		return errors.New("peercache: the peer's certificate is not a device certificate")
	}
	return nil
}

func keyPair(cert, issuing []byte, key crypto.Signer) tls.Certificate {
	chain := [][]byte{cert}
	if len(issuing) > 0 {
		chain = append(chain, issuing)
	}
	return tls.Certificate{Certificate: chain, PrivateKey: key}
}

// ServerTLS is the listener's configuration: it presents the device certificate and demands one from the client.
func ServerTLS(root *x509.Certificate, cert, issuing []byte, key crypto.Signer) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{keyPair(cert, issuing, key)},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			chain, err := parse(raw)
			if err != nil {
				return err
			}
			return verifyPeer(chain, root, time.Now())
		},
	}
}

// ClientTLS is the configuration for asking a peer: the server's certificate must be a device certificate of this installation.
func ClientTLS(root *x509.Certificate, cert, issuing []byte, key crypto.Signer) *tls.Config {
	// The same pinned-root pattern as internal/agent/core/tls.go: the standard check is replaced, not dropped.
	// nosemgrep: no-insecure-tls
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{keyPair(cert, issuing, key)},
		// There is no host name to check: peers are reached by address. The chain check below replaces the standard one.
		InsecureSkipVerify: true, // #nosec G402 -- replaced by verifyPeer in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPeer(cs.PeerCertificates, root, time.Now())
		},
	}
}

func parse(raw [][]byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, r := range raw {
		c, err := x509.ParseCertificate(r)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}
