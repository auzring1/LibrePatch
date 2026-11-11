// Package release defines the vendor-signed agent release manifest.
//
// The customer's server signs the AGENT_UPDATE job like every other job, but that is not what
// makes a new agent binary trustworthy: the binary is described by a manifest that the VENDOR signed
// with a release key whose public half is compiled into the agent. A compromised customer server
// can therefore choose when to update (and which of the vendor's releases), but it cannot make
// agents run a binary the vendor did not publish (docs/ARCHITECTURE.md §10, docs/THREAT-MODEL.md §9d).
package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"regexp"
	"strings"

	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

// Domain separates release signatures from every other Ed25519 signature in the product.
const Domain = "librepatch/release/v1\x00"

// Product is the only product name a manifest may carry.
const Product = brand.ManifestProduct

// Limits on attacker-influenced input (a manifest arrives inside a job).
const (
	MaxManifestBytes = 8 << 10
	MaxBinaryBytes   = 256 << 20
	MaxNotes         = 1024
)

// PublicKeysHex is the comma-separated list of trusted vendor release public keys (hex Ed25519).
// Release builds set it with
//
//	-ldflags "-X github.com/auzring1/librepatch/internal/shared/release.PublicKeysHex=<hex>[,<hex>]"
//
// A build without a key refuses every update (there is no default key and no "dev" key in the tree).
var PublicKeysHex = ""

// RequireAuthenticode makes a manifest without a pinned Authenticode subject invalid. Release builds
// set it to "true" with -ldflags -X; development builds leave it empty so unsigned test binaries work.
var RequireAuthenticode = ""

// AuthenticodeSubjects is a "|"-separated list of the signer names (certificate CN, as the agent reads it)
// a release may pin. Release builds set it with -ldflags -X. Without it the pinned subject is whatever the
// vendor-signed manifest says, so whoever holds the release key could pin a certificate of their own;
// with it, a stolen release key alone is not enough (the attacker would also need our code-signing
// certificate). Development builds leave it empty (D83).
var AuthenticodeSubjects = ""

// Manifest describes one agent binary. Unknown fields are rejected so a newer vendor cannot
// smuggle meaning past an older agent.
type Manifest struct {
	Format  int    `json:"format"`
	Product string `json:"product"`
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	SHA256  string `json:"sha256"` // hex of the binary
	Size    uint64 `json:"size"`
	// ReleasedAt is unix seconds (informational).
	ReleasedAt int64 `json:"released_at,omitempty"`
	// MinVersion: agents older than this must install an intermediate release first.
	MinVersion string `json:"min_version,omitempty"`
	// RollbackFrom lists versions from which this (older) release may be installed deliberately.
	RollbackFrom []string `json:"rollback_from,omitempty"`
	// AuthenticodeSubject is the certificate subject (CN) the binary must be signed with.
	AuthenticodeSubject string `json:"authenticode_subject,omitempty"`
	Notes               string `json:"notes,omitempty"`
}

// Bundle is the file the vendor publishes next to the binary (.lprel).
type Bundle struct {
	Manifest  []byte `json:"manifest"`
	Signature []byte `json:"signature"`
	KeyID     string `json:"key_id"` // hex
}

var (
	versionRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}([-+][0-9A-Za-z.\-+]{1,40})?$`)
	hexRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// KeyID returns the short identifier of a public key (hex of the first 8 bytes of its SHA-256).
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// ParseKeys parses a comma-separated list of hex public keys.
func ParseKeys(list string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, p := range strings.Split(list, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		b, err := hex.DecodeString(p)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("release: %q is not an Ed25519 public key in hex", abbreviate(p))
		}
		out = append(out, ed25519.PublicKey(b))
	}
	return out, nil
}

func abbreviate(s string) string {
	if len(s) > 12 {
		return s[:12] + "..."
	}
	return s
}

// TrustedKeys returns the keys compiled into this binary.
func TrustedKeys() []ed25519.PublicKey {
	k, err := ParseKeys(PublicKeysHex)
	if err != nil {
		return nil // a malformed build-time key trusts nothing
	}
	return k
}

// Marshal produces the bytes that are signed. The signer keeps these exact bytes.
func Marshal(m *Manifest) ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// Sign signs manifest bytes with a vendor key.
func Sign(priv ed25519.PrivateKey, manifest []byte) []byte {
	return ed25519.Sign(priv, signedBytes(manifest))
}

func signedBytes(manifest []byte) []byte {
	return append([]byte(Domain), manifest...)
}

// SignedBytes returns the exact bytes the release key signs for a manifest (domain prefix + manifest),
// for external signers (KMS/HSM).
func SignedBytes(manifest []byte) []byte { return signedBytes(manifest) }

// Verify checks the signature under one of keys and returns the parsed, validated manifest.
func Verify(keys []ed25519.PublicKey, manifest, sig []byte, keyID string) (*Manifest, error) {
	if len(keys) == 0 {
		return nil, errors.New("release: this build contains no vendor release key, so it cannot accept updates")
	}
	if len(manifest) == 0 || len(manifest) > MaxManifestBytes {
		return nil, errors.New("release: manifest size is out of range")
	}
	var pub ed25519.PublicKey
	for _, k := range keys {
		if keyID == "" || strings.EqualFold(KeyID(k), keyID) {
			if ed25519.Verify(k, signedBytes(manifest), sig) {
				pub = k
				break
			}
		}
	}
	if pub == nil {
		return nil, errors.New("release: the manifest signature does not verify under a trusted vendor key")
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(manifest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("release: bad manifest: %w", err)
	}
	if dec.More() {
		return nil, errors.New("release: trailing data after the manifest")
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	switch {
	case m.Format != 1:
		return fmt.Errorf("release: unsupported manifest format %d", m.Format)
	case m.Product != Product:
		return errors.New("release: not an agent release")
	case !versionRe.MatchString(m.Version) || vercmp.Key(m.Version) == nil:
		return errors.New("release: bad version")
	case m.OS != "windows" && m.OS != "linux":
		return errors.New("release: unsupported operating system")
	case m.Arch != "amd64" && m.Arch != "arm64":
		return errors.New("release: unsupported architecture")
	case !hexRe.MatchString(m.SHA256):
		return errors.New("release: sha256 must be 64 lowercase hex digits")
	case m.Size == 0 || m.Size > MaxBinaryBytes:
		return errors.New("release: size is out of range")
	case len(m.Notes) > MaxNotes:
		return errors.New("release: notes are too long")
	case m.MinVersion != "" && !versionRe.MatchString(m.MinVersion):
		return errors.New("release: bad min_version")
	case len(m.RollbackFrom) > 32:
		return errors.New("release: too many rollback versions")
	case len(m.AuthenticodeSubject) > 256 || strings.ContainsAny(m.AuthenticodeSubject, "\x00\r\n"):
		return errors.New("release: bad authenticode subject")
	}
	for _, v := range m.RollbackFrom {
		if !versionRe.MatchString(v) {
			return errors.New("release: bad rollback version")
		}
	}
	if RequireAuthenticode == "true" && m.AuthenticodeSubject == "" {
		return errors.New("release: this build requires a pinned Authenticode subject")
	}
	if AuthenticodeSubjects != "" {
		ok := false
		for _, allowed := range strings.Split(AuthenticodeSubjects, "|") {
			if allowed != "" && strings.EqualFold(allowed, m.AuthenticodeSubject) {
				ok = true
			}
		}
		if !ok {
			return errors.New("release: the pinned Authenticode subject is not one this build trusts")
		}
	}
	return nil
}

// SHA256Bytes returns the binary hash as bytes.
func (m *Manifest) SHA256Bytes() []byte {
	b, _ := hex.DecodeString(m.SHA256)
	return b
}

// CheckApplicable decides whether a verified manifest may be installed on a machine running
// current for the given platform. It returns nil to proceed, or an error saying why not.
func (m *Manifest) CheckApplicable(current, goos, goarch string) error {
	if m.OS != goos || m.Arch != goarch {
		return fmt.Errorf("release is for %s/%s, this machine is %s/%s", m.OS, m.Arch, goos, goarch)
	}
	c := vercmp.Compare(m.Version, current)
	switch {
	case c == 0:
		return fmt.Errorf("version %s is already running", current)
	case c < 0:
		for _, from := range m.RollbackFrom {
			if vercmp.Compare(from, current) == 0 {
				return nil // a vendor-sanctioned rollback
			}
		}
		return fmt.Errorf("downgrade from %s to %s is not allowed by this release", current, m.Version)
	}
	if m.MinVersion != "" && vercmp.Compare(current, m.MinVersion) < 0 {
		return fmt.Errorf("version %s is too old to update directly; install an intermediate release (at least %s) first", current, m.MinVersion)
	}
	return nil
}

// EncodeBundle serializes a bundle for distribution.
func EncodeBundle(b *Bundle) ([]byte, error) { return json.MarshalIndent(b, "", "  ") }

// DecodeBundle parses a bundle (strictly) without verifying it.
func DecodeBundle(data []byte) (*Bundle, error) {
	if len(data) == 0 || len(data) > 2*MaxManifestBytes {
		return nil, errors.New("release: bundle size is out of range")
	}
	var b Bundle
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("release: bad bundle: %w", err)
	}
	return &b, nil
}

// ParseUnverified parses and validates a manifest WITHOUT checking its signature. Only for code
// that is already trusted to have verified it (the customer server reading a release it stored
// after verification); agents must always use Verify.
func ParseUnverified(manifest []byte) (*Manifest, error) {
	if len(manifest) == 0 || len(manifest) > MaxManifestBytes {
		return nil, errors.New("release: manifest size is out of range")
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(manifest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("release: bad manifest: %w", err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}
