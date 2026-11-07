package pki

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/kek"
)

// ErrNotInitialized means first-run setup has not created the CA yet.
var ErrNotInitialized = errors.New("pki: not initialized (first-run setup pending)")

// SaveHierarchy persists freshly created CA material inside tx.
func SaveHierarchy(ctx context.Context, q *dbq.Queries, s *kek.Sealer, h *Hierarchy, rootPassphrase string) error {
	rootEnc, err := SealWithPassphrase(rootPassphrase, h.Root.Key)
	if err != nil {
		return err
	}
	issEnc, err := SealWithKEK(s, kek.PurposeIssuingKey, h.Issuing.Key)
	if err != nil {
		return err
	}
	jobEnc, err := SealWithKEK(s, kek.PurposeJobSigningKey, h.JobSigning.Key)
	if err != nil {
		return err
	}
	for _, m := range []struct {
		kind, prot string
		cert       *x509.Certificate
		enc        []byte
	}{
		{"root", "passphrase", h.Root.Cert, rootEnc},
		{"issuing", "kek", h.Issuing.Cert, issEnc},
		{"job_signing", "kek", h.JobSigning.Cert, jobEnc},
	} {
		if err := q.InsertPKIMaterial(ctx, dbq.InsertPKIMaterialParams{
			ID: uuid.New(), Kind: m.kind, CertDer: m.cert.Raw, KeyEnc: m.enc,
			KeyProtection: m.prot, NotAfter: m.cert.NotAfter,
		}); err != nil {
			return fmt.Errorf("store %s: %w", m.kind, err)
		}
	}
	return nil
}

// LoadAuthority loads the runtime CA (without the root key).
func LoadAuthority(ctx context.Context, q *dbq.Queries, s *kek.Sealer) (*Authority, error) {
	load := func(kind string) (dbq.PkiMaterial, *x509.Certificate, error) {
		m, err := q.GetActivePKI(ctx, kind)
		if errors.Is(err, pgx.ErrNoRows) {
			return m, nil, ErrNotInitialized
		}
		if err != nil {
			return m, nil, err
		}
		c, err := x509.ParseCertificate(m.CertDer)
		return m, c, err
	}
	_, root, err := load("root")
	if err != nil {
		return nil, err
	}
	issM, iss, err := load("issuing")
	if err != nil {
		return nil, err
	}
	jobM, job, err := load("job_signing")
	if err != nil {
		return nil, err
	}
	issKey, err := OpenWithKEK(s, kek.PurposeIssuingKey, issM.KeyEnc)
	if err != nil {
		return nil, fmt.Errorf("unseal issuing key: %w", err)
	}
	jobKey, err := OpenWithKEK(s, kek.PurposeJobSigningKey, jobM.KeyEnc)
	if err != nil {
		return nil, fmt.Errorf("unseal job-signing key: %w", err)
	}
	return NewAuthority(root, KeyPair{iss, issKey}, KeyPair{job, jobKey}), nil
}

// EnsureGatewayCert returns a valid gateway certificate, issuing (and
// persisting) a new one if none exists, it expires within 30 days, or its
// SANs differ from the configured ones.
func EnsureGatewayCert(ctx context.Context, db interface {
	Begin(context.Context) (pgx.Tx, error)
}, s *kek.Sealer, a *Authority, sans []string, now time.Time) (KeyPair, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return KeyPair{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := dbq.New(tx)
	m, err := q.GetActivePKI(ctx, "gateway")
	if err == nil {
		cert, perr := x509.ParseCertificate(m.CertDer)
		if perr == nil && cert.NotAfter.After(now.Add(30*24*time.Hour)) && sameSANs(cert, sans) &&
			cert.CheckSignatureFrom(a.Issuing.Cert) == nil {
			key, kerr := OpenWithKEK(s, kek.PurposeGatewayKey, m.KeyEnc)
			if kerr == nil {
				return KeyPair{cert, key}, tx.Commit(ctx)
			}
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return KeyPair{}, err
	}
	kp, err := a.IssueGatewayCert(sans, now)
	if err != nil {
		return KeyPair{}, err
	}
	enc, err := SealWithKEK(s, kek.PurposeGatewayKey, kp.Key)
	if err != nil {
		return KeyPair{}, err
	}
	if err := q.RetireActivePKI(ctx, dbq.RetireActivePKIParams{Kind: "gateway", RetiredAt: &now}); err != nil {
		return KeyPair{}, err
	}
	if err := q.InsertPKIMaterial(ctx, dbq.InsertPKIMaterialParams{
		ID: uuid.New(), Kind: "gateway", CertDer: kp.Cert.Raw, KeyEnc: enc, KeyProtection: "kek", NotAfter: kp.Cert.NotAfter,
	}); err != nil {
		return KeyPair{}, err
	}
	return kp, tx.Commit(ctx)
}

func sameSANs(c *x509.Certificate, sans []string) bool {
	have := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		have = append(have, ip.String())
	}
	want := append([]string{}, sans...)
	norm := func(l []string) []string {
		for i := range l {
			l[i] = strings.ToLower(l[i])
		}
		slices.Sort(l)
		return slices.Compact(l)
	}
	return slices.Equal(norm(have), norm(want))
}
