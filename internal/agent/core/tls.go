package core

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	"github.com/auzring1/librepatch/internal/shared/pkix"
)

// pinnedTLS is used before enrollment: the agent has only the root SPKI pin
// from the enrollment string. The server's chain must end in a root whose
// SPKI matches the pin, and the leaf must be valid for the dialed host.
func pinnedTLS(server, pin string) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ServerName: host,
		// Standard verification cannot be used before we know the root;
		// VerifyConnection performs the complete check below.
		InsecureSkipVerify: true, // #nosec G402 -- replaced by pinned verification in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			_, err := verifyPinnedChain(cs.PeerCertificates, host, pin)
			return err
		},
	}, nil
}

// verifyPinnedChain returns the pinned root after full chain + hostname verification.
func verifyPinnedChain(chain []*x509.Certificate, host, pin string) (*x509.Certificate, error) {
	if len(chain) < 2 {
		return nil, errors.New("server sent an incomplete certificate chain")
	}
	var root *x509.Certificate
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		if pkix.SPKIPin(c) == pin {
			root = c
		} else {
			inter.AddCert(c)
		}
	}
	if root == nil {
		return nil, errors.New("server certificate chain does not match the pinned root CA (wrong server or interception)")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := chain[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, fmt.Errorf("server certificate: %w", err)
	}
	return root, nil
}

// mutualTLS is used after enrollment: standard verification against the
// stored root plus our client certificate.
func mutualTLS(server string, root *x509.Certificate, cert, issuing []byte, key crypto.Signer) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	chain := [][]byte{cert}
	if len(issuing) > 0 {
		chain = append(chain, issuing)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		ServerName:   host,
		RootCAs:      pool,
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}},
	}, nil
}

// PinnedTLS and MutualTLS expose the agent's (unchanged) trust logic to tools that
// speak the real protocol without the full agent, such as cmd/librepatch-loadsim. They do not relax anything.
func PinnedTLS(server, pin string) (*tls.Config, error) { return pinnedTLS(server, pin) }

// MutualTLS is mutualTLS for tools; see PinnedTLS.
func MutualTLS(server string, root *x509.Certificate, cert, issuing []byte, key crypto.Signer) (*tls.Config, error) {
	return mutualTLS(server, root, cert, issuing, key)
}
