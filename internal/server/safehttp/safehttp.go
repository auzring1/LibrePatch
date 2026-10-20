// Package safehttp builds the HTTP client the server uses to fetch things an administrator pointed it at (catalog overlays,
// vulnerability feeds). It refuses loopback and link-local addresses, so such an address cannot be used to reach the server
// itself or a cloud metadata service, follows few redirects and has timeouts. Private LAN addresses are allowed: a feed
// mirror on the local network is a normal thing to have.
package safehttp

import (
	"errors"
	"net"
	"net/http"
	"syscall"
	"time"
)

// ErrLocal is the message for a refused address.
var ErrLocal = errors.New("addresses on this server itself and link-local addresses are not allowed")

func refuseLocal(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()) {
		return ErrLocal
	}
	return nil
}

// NewClient returns a client with a 30 second total timeout.
func NewClient() *http.Client { return NewClientTimeout(30 * time.Second) }

// NewClientTimeout is NewClient with a chosen total timeout (the vulnerability feeds are large).
func NewClientTimeout(total time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, Control: refuseLocal}
	return &http.Client{
		Timeout:   total,
		Transport: &http.Transport{DialContext: d.DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, DisableKeepAlives: true, Proxy: http.ProxyFromEnvironment},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}
