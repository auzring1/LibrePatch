// Package overlay defines the signed catalog overlay: a file in which a person (the owner of a deployment, or a
// community) records what they know about packages that the winget manifests lack or get wrong: the silent install
// arguments that really work, extra detection rules, whether the program updates itself, and a "verified" mark for
// programs they tested. The server layers it under the administrator's own overrides (D122).
//
// An overlay changes what the server tells agents to run, so it is signed: the server accepts a file only if it carries a
// valid Ed25519 signature from a public key the administrator entered for that source. The signature covers the exact
// document bytes (whitespace removed) under its own domain string, so it cannot be mistaken for any other signature in the
// product, and a document cannot be re-labelled as something else.
package overlay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/auzring1/librepatch/internal/shared/installer"
)

// Formats. A newer, incompatible format gets a new number, so an older server refuses it instead of misreading it.
const (
	DocumentFormat = "librepatch-overlay/1"
	BundleFormat   = "librepatch-overlay-bundle/1"
	// Domain separates overlay signatures from every other Ed25519 signature (release manifests use their own).
	Domain = "librepatch/overlay/v1\x00"
)

// Limits on input that arrives from the network or an upload.
const (
	MaxBundleBytes  = 2 << 20
	MaxEntries      = 5000
	MaxNote         = 500
	MaxNameLen      = 100
	MaxIdentifier   = 128
	MaxDetections   = 16
	MaxDetectionRaw = 8 << 10
)

// Entry is what an overlay says about one package, found by its winget (or custom) identifier.
type Entry struct {
	Identifier string `json:"identifier"`
	Note       string `json:"note,omitempty"`
	// SelfUpdating says the program updates itself, so an update deployment leaves it to the vendor's updater (D50). A
	// pointer: absent means the overlay says nothing about it.
	SelfUpdating *bool `json:"self_updating,omitempty"`
	// Verified vouches that the overlay's author tested the package; VerifiedNote says how ("Tested on the Windows 11 image,
	// 2026-10").
	Verified     bool   `json:"verified,omitempty"`
	VerifiedNote string `json:"verified_note,omitempty"`
	// SilentArgs replace the manifest's silent switches (an administrator's own override still wins).
	SilentArgs []string `json:"silent_args,omitempty"`
	// ExtraDetection is a list of detection rules (the same shape as the package override's), added to the manifest's.
	ExtraDetection json.RawMessage `json:"extra_detection,omitempty"`
	// Processes are the image names (for example "chrome.exe") of the programs an update replaces. A deployment that asks
	// people to close the program, or waits for them to, needs them (D124).
	Processes []string `json:"processes,omitempty"`
}

// Document is the content of an overlay.
type Document struct {
	Format string `json:"format"`
	// Name is what the overlay calls itself ("Clinic IT overlay").
	Name string `json:"name"`
	// Version only ever goes up: a server refuses to replace a document with an older one (a rollback).
	Version  int64   `json:"version"`
	IssuedAt string  `json:"issued_at"` // RFC 3339, informational
	Packages []Entry `json:"packages"`
}

// Bundle is the signed file (extension .lpov).
type Bundle struct {
	Format string `json:"format"`
	// Overlay is the document, exactly as signed.
	Overlay json.RawMessage `json:"overlay"`
	// KeyID is the first 16 hex characters of the SHA-256 of the public key: a label to tell keys apart, not a trust anchor.
	KeyID string `json:"key_id"`
	// Signature is the Ed25519 signature, base64, over Domain + the compacted Overlay bytes.
	Signature string `json:"signature"`
}

// Errors.
var (
	ErrFormat    = errors.New("overlay: not a LibrePatch overlay file")
	ErrSignature = errors.New("overlay: the signature does not match the key you entered")
	ErrInvalid   = errors.New("overlay: invalid document")
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// KeyID labels a public key.
func KeyID(pub ed25519.PublicKey) string {
	s := sha256.Sum256(pub)
	return hex.EncodeToString(s[:8])
}

// ParsePublicKey reads a hex Ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("a public key is 64 hexadecimal characters")
	}
	return ed25519.PublicKey(b), nil
}

func signedBytes(doc []byte) ([]byte, error) {
	var c bytes.Buffer
	if err := json.Compact(&c, doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	return append([]byte(Domain), c.Bytes()...), nil
}

// Sign signs a document (as JSON) with a private key and returns the bundle. The document is validated first, so a file
// that a server would refuse is never signed.
func Sign(priv ed25519.PrivateKey, doc []byte) (*Bundle, error) {
	if _, err := ParseDocument(doc); err != nil {
		return nil, err
	}
	msg, err := signedBytes(doc)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	var c bytes.Buffer
	_ = json.Compact(&c, doc)
	return &Bundle{Format: BundleFormat, Overlay: json.RawMessage(c.Bytes()), KeyID: KeyID(pub), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))}, nil
}

// Verify checks a bundle's signature against the given key and returns the validated document and its signed bytes.
func Verify(bundle []byte, pub ed25519.PublicKey) (*Document, []byte, error) {
	if len(bundle) > MaxBundleBytes {
		return nil, nil, fmt.Errorf("%w: larger than %d bytes", ErrFormat, MaxBundleBytes)
	}
	var b Bundle
	dec := json.NewDecoder(bytes.NewReader(bundle))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || b.Format != BundleFormat || len(b.Overlay) == 0 {
		return nil, nil, ErrFormat
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, nil, ErrSignature
	}
	msg, err := signedBytes(b.Overlay)
	if err != nil {
		return nil, nil, err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return nil, nil, ErrSignature
	}
	doc, err := ParseDocument(b.Overlay)
	if err != nil {
		return nil, nil, err
	}
	return doc, msg[len(Domain):], nil
}

// ParseDocument decodes and validates a document. Unknown fields are refused, so a newer overlay cannot carry meaning an
// older server would silently ignore.
func ParseDocument(raw []byte) (*Document, error) {
	if len(raw) > MaxBundleBytes {
		return nil, invalid("larger than %d bytes", MaxBundleBytes)
	}
	var d Document
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, invalid("%v", err)
	}
	if dec.More() {
		return nil, invalid("trailing data")
	}
	if d.Format != DocumentFormat {
		return nil, fmt.Errorf("%w: format %q is not %q", ErrInvalid, d.Format, DocumentFormat)
	}
	if n := len([]rune(strings.TrimSpace(d.Name))); n < 1 || n > MaxNameLen {
		return nil, invalid("the name must be 1 to %d characters", MaxNameLen)
	}
	if d.Version < 1 {
		return nil, invalid("version must be a whole number of at least 1")
	}
	if d.IssuedAt != "" {
		if _, err := time.Parse(time.RFC3339, d.IssuedAt); err != nil {
			return nil, invalid("issued_at must be an RFC 3339 time")
		}
	}
	if len(d.Packages) > MaxEntries {
		return nil, invalid("more than %d packages", MaxEntries)
	}
	seen := map[string]bool{}
	for i := range d.Packages {
		e := &d.Packages[i]
		id := strings.ToLower(strings.TrimSpace(e.Identifier))
		if id == "" || len(id) > MaxIdentifier || strings.ContainsAny(id, " \t\r\n\x00") {
			return nil, invalid("package %d: the identifier is empty, too long or contains spaces", i+1)
		}
		if seen[id] {
			return nil, invalid("package %q appears twice", e.Identifier)
		}
		seen[id] = true
		if len(e.Note) > MaxNote || len(e.VerifiedNote) > MaxNote {
			return nil, invalid("package %q: a note is longer than %d characters", e.Identifier, MaxNote)
		}
		if err := installer.ValidateArgs(e.SilentArgs); err != nil {
			return nil, invalid("package %q: %v", e.Identifier, err)
		}
		if err := installer.ValidateProcessNames(e.Processes); err != nil {
			return nil, invalid("package %q: %v", e.Identifier, err)
		}
		if len(e.ExtraDetection) > MaxDetectionRaw {
			return nil, invalid("package %q: detection rules are too large", e.Identifier)
		}
		if !e.Verified && e.VerifiedNote != "" {
			return nil, invalid("package %q: a verified note without verified", e.Identifier)
		}
	}
	return &d, nil
}
