package core

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"sync"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/peercache"
)

// Sharing downloaded installers with other computers on the same network (D126). The organization turns it on
// (PeerCachePolicy in the HelloAck); the agent's local ceiling can keep it off whatever the server says.

// peerState is what the agent currently does for the policy.
type peerState struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	key    string // port + certificate: when it changes the listener restarts
	cache  *peercache.Cache
	client *tls.Config
}

// peerAllowed: the local ceiling is empty (everything) or names peer_cache.
func (a *Agent) peerAllowed() bool {
	if len(a.Cfg.AllowedJobs) == 0 {
		return true
	}
	for _, n := range a.Cfg.AllowedJobs {
		if n == "peer_cache" {
			return true
		}
	}
	return false
}

// applyPeerPolicy starts, restarts or stops sharing to match the policy. ctx outlives a single connection.
func (a *Agent) applyPeerPolicy(ctx context.Context, pol *agentv1.PeerCachePolicy, root *x509.Certificate, cert, issuing []byte, key crypto.Signer) {
	p := &a.peer
	p.mu.Lock()
	defer p.mu.Unlock()
	want := pol != nil && pol.Enabled && a.peerAllowed() && pol.Port >= 1024 && pol.Port <= 65535
	if !want {
		a.stopPeerLocked()
		return
	}
	maxMB := min(max(pol.MaxMb, 256), 20480)
	if p.cache == nil {
		p.cache = &peercache.Cache{Dir: filepath.Join(a.DataDir, "peer-cache")}
	}
	p.cache.MaxBytes = int64(maxMB) << 20
	p.client = peercache.ClientTLS(root, cert, issuing, key)
	k := fmt.Sprintf("%d/%x", pol.Port, cert[len(cert)-16:])
	if p.cancel != nil && p.key == k {
		return
	}
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	lctx, cancel := context.WithCancel(ctx)
	srv := &peercache.Server{Cache: p.cache, TLS: peercache.ServerTLS(root, cert, issuing, key), Log: a.Log,
		Allow: func(ip net.IP) bool { return peercache.InAny(peercache.LocalNetworks(), ip) }}
	ln, err := net.Listen("tcp4", ":"+strconv.Itoa(int(pol.Port)))
	if err != nil {
		cancel()
		a.Log.Warn("peer cache: cannot listen; not sharing", "port", pol.Port, "err", err)
		a.peerPort.Store(0)
		return
	}
	if err := peercache.OpenFirewall(uint16(pol.Port)); err != nil { // #nosec G115 -- 1024..65535
		a.Log.Warn("peer cache: could not open the firewall for the port; other computers may not reach this one", "err", err)
	}
	p.cancel, p.key = cancel, k
	a.peerPort.Store(pol.Port)
	a.Log.Info("peer cache: sharing downloads", "port", pol.Port, "max_mb", maxMB)
	go func() {
		if err := srv.ServeListener(lctx, ln); err != nil {
			a.Log.Warn("peer cache: listener ended", "err", err)
		}
		_ = ln.Close()
	}()
}

func (a *Agent) stopPeerLocked() {
	p := &a.peer
	if p.cancel != nil {
		p.cancel()
		p.cancel, p.key = nil, ""
		peercache.CloseFirewall()
		a.Log.Info("peer cache: no longer sharing")
	}
	if p.cache != nil {
		p.cache.Clear() // the policy is off: give the disk space back
		p.cache = nil
	}
	p.client = nil
	a.peerPort.Store(0)
}

// cachePut keeps a verified installer for other computers (the job engine calls it after the hash check).
func (a *Agent) cachePut(path string, sha []byte) {
	a.peer.mu.Lock()
	c := a.peer.cache
	a.peer.mu.Unlock()
	if c == nil {
		return
	}
	if err := c.Put(path, sha); err != nil {
		a.Log.Debug("peer cache: not kept", "err", err)
	}
}

// fetchFromPeer asks another computer for a file. Without the organization's policy it does nothing.
func (a *Agent) fetchFromPeer(ctx context.Context, rawURL string, sha []byte) (io.ReadCloser, error) {
	a.peer.mu.Lock()
	cfg := a.peer.client
	a.peer.mu.Unlock()
	if cfg == nil {
		return nil, fmt.Errorf("sharing downloads is not turned on")
	}
	return peercache.Fetch(ctx, cfg, rawURL, sha)
}
