package notify

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRefuseLocalTargets(t *testing.T) {
	for addr, refused := range map[string]bool{
		"169.254.169.254:80": true, // cloud metadata
		"[fe80::1]:443":      true,
		"127.0.0.1:8080":     true, // the server's own listeners
		"[::1]:8080":         true,
		"0.0.0.0:80":         true,
		"[::]:80":            true,
		"10.1.2.3:443":       false, // an internal receiver is the point of the feature
		"192.168.1.20:8443":  false,
		"93.184.216.34:443":  false,
	} {
		err := refuseLocalTargets("tcp", addr, nil)
		if (err != nil) != refused {
			t.Errorf("%s: refused=%v, want %v (%v)", addr, err != nil, refused, err)
		}
	}
}

// The check must apply to the connection actually made, whatever the URL says.
func TestPosterDoesNotReachLoopback(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	_, err := httpPoster{}.Post(t.Context(), srv.URL, nil, []byte("{}"))
	if err == nil || !strings.Contains(err.Error(), "cannot target") || hit {
		t.Fatalf("a webhook to a loopback receiver must be refused before it connects: err=%v hit=%v", err, hit)
	}
}
