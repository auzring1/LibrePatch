package peercache

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ValidURL checks the address of a peer as it appears in a signed job: https, a private IPv4 address, a port from 1024 up,
// and nothing else. A peer is never reached by name, and never outside the private address ranges.
func ValidURL(raw string) (host string, err error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || len(raw) > 64 {
		return "", errors.New("a peer address looks like https://192.168.1.20:7421")
	}
	ip := net.ParseIP(u.Hostname()).To4()
	if ip == nil || !ip.IsPrivate() {
		return "", errors.New("a peer must be a private IPv4 address")
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil || p < 1024 || p > 65535 {
		return "", errors.New("a peer port is 1024 to 65535")
	}
	return u.Host, nil
}

// Fetch asks one peer for the file with the given hash. The caller hashes what it receives. Connecting and the first reply
// are tight (a peer that is switched off must not stall a job); the transfer itself is bounded by the caller's context.
func Fetch(ctx context.Context, cfg *tls.Config, raw string, sha []byte) (io.ReadCloser, error) {
	host, err := ValidURL(raw)
	if err != nil {
		return nil, err
	}
	if len(sha) != 32 {
		return nil, ErrBadHash
	}
	tr := &http.Transport{
		TLSClientConfig:       cfg,
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		DisableKeepAlives:     true,
		Proxy:                 nil, // a peer is on the local network; never through a proxy
	}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/v1/content/"+hex.EncodeToString(sha), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req) // #nosec G107 G704 -- a private IPv4 address from a signed job, validated above
	if err != nil {
		tr.CloseIdleConnections()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("peer answered HTTP %d", resp.StatusCode)
	}
	return resp.Body, nil
}
