package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// decodeKey accepts a 32-byte key encoded as hex (64 chars) or base64.
func decodeKey(s string) ([]byte, error) {
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("must decode (hex or base64) to exactly 32 bytes")
}
