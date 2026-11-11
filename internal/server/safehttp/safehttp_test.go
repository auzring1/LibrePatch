package safehttp

import (
	"errors"
	"testing"
)

func TestRefuseLocal(t *testing.T) {
	for addr, refused := range map[string]bool{
		"169.254.169.254:80": true,
		"[fe80::1]:443":      true,
		"127.0.0.1:8080":     true,
		"[::1]:8080":         true,
		"0.0.0.0:80":         true,
		"10.1.2.3:443":       false, // a mirror on the local network is normal
		"93.184.216.34:443":  false,
	} {
		err := RefuseLocal("tcp", addr, nil)
		if (err != nil) != refused || (refused && !errors.Is(err, ErrLocal)) {
			t.Errorf("%s: refused=%v, want %v (%v)", addr, err != nil, refused, err)
		}
	}
}
