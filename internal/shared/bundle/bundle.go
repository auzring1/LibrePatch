// Package bundle encodes the enrollment string handed to `agent install --token`.
//
//	LP1.<base64url(JSON{"v":1,"gw":"host:port","root":"sha256/...","tok":"...","org":"uuid"})>
package bundle

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/google/uuid"
)

const prefix = "LP1."

// Bundle is the decoded enrollment string.
type Bundle struct {
	V       int    `json:"v"`
	Gateway string `json:"gw"`
	RootPin string `json:"root"`
	Token   string `json:"tok"`
	Org     string `json:"org"`
}

// Encode returns the LP1.* string.
func (b Bundle) Encode() (string, error) {
	if err := b.Validate(); err != nil {
		return "", err
	}
	j, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(j), nil
}

// Parse decodes and validates an LP1.* string.
func Parse(s string) (Bundle, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, prefix) {
		return Bundle{}, errors.New("enrollment token must start with LP1. (copy the full string from the console)")
	}
	if len(s) > 2048 {
		return Bundle{}, errors.New("enrollment token too long")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s[len(prefix):])
	if err != nil {
		return Bundle{}, fmt.Errorf("enrollment token is not valid base64url: %w", err)
	}
	var b Bundle
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return Bundle{}, fmt.Errorf("enrollment token JSON: %w", err)
	}
	return b, b.Validate()
}

// Validate checks field formats.
func (b Bundle) Validate() error {
	if b.V != 1 {
		return fmt.Errorf("unsupported enrollment token version %d", b.V)
	}
	if _, _, err := net.SplitHostPort(b.Gateway); err != nil {
		return fmt.Errorf("gateway address %q: %w", b.Gateway, err)
	}
	if !strings.HasPrefix(b.RootPin, "sha256/") {
		return errors.New("root pin must be sha256/<base64>")
	}
	pin, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(b.RootPin, "sha256/"))
	if err != nil || len(pin) != 32 {
		return errors.New("root pin is not a base64 SHA-256 value")
	}
	if tok, err := base64.RawURLEncoding.DecodeString(b.Token); err != nil || len(tok) < 32 {
		return errors.New("token secret must be >= 32 random bytes (base64url)")
	}
	if _, err := uuid.Parse(b.Org); err != nil {
		return errors.New("org must be a UUID")
	}
	return nil
}
