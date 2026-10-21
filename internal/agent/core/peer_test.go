package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/config"
	"github.com/auzring1/librepatch/internal/server/pki"
)

func freePort(t *testing.T) uint32 {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint32(ln.Addr().(*net.TCPAddr).Port)
}

func peerAgent(t *testing.T, allowed ...string) (*Agent, *x509.Certificate, []byte, []byte, *ecdsa.PrivateKey) {
	h, err := pki.NewHierarchy("Contoso Health", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	au := pki.NewAuthority(h.Root.Cert, h.Issuing, h.JobSigning)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := uuid.New()
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: id.String()}}, key)
	c, err := au.IssueDeviceCert(csr, id, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{Cfg: &config.Config{AllowedJobs: allowed}, DataDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return a, h.Root.Cert, c.Raw, h.Issuing.Cert.Raw, key
}

func TestSharingFollowsThePolicyAndStopsWhenItIsTurnedOff(t *testing.T) {
	a, root, cert, iss, key := peerAgent(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t)
	a.applyPeerPolicy(ctx, &agentv1.PeerCachePolicy{Enabled: true, Port: port, MaxMb: 512}, root, cert, iss, key)
	if a.peerPort.Load() != port || a.peer.cache == nil || a.peer.cache.MaxBytes != 512<<20 {
		t.Fatalf("port %d cache %+v", a.peerPort.Load(), a.peer.cache)
	}
	// The same policy again changes nothing (no second listener on the same port).
	a.applyPeerPolicy(ctx, &agentv1.PeerCachePolicy{Enabled: true, Port: port, MaxMb: 1024}, root, cert, iss, key)
	if a.peerPort.Load() != port || a.peer.cache.MaxBytes != 1024<<20 {
		t.Fatal("a larger cache limit applies without restarting")
	}
	// A file in the cache is removed when sharing stops.
	_ = os.WriteFile(filepath.Join(a.peer.cache.Dir, "leftover"), []byte("x"), 0o600)
	dir := a.peer.cache.Dir
	a.applyPeerPolicy(ctx, &agentv1.PeerCachePolicy{Enabled: false}, root, cert, iss, key)
	if a.peerPort.Load() != 0 || a.peer.cache != nil || a.peer.client != nil {
		t.Fatal("still sharing")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("the cache was not emptied: %v", ents)
	}
	// No policy at all (an older server) means off.
	a.applyPeerPolicy(ctx, nil, root, cert, iss, key)
	if a.peerPort.Load() != 0 {
		t.Fatal("no policy must mean off")
	}
}

func TestTheLocalCeilingKeepsSharingOffWhateverTheServerSays(t *testing.T) {
	a, root, cert, iss, key := peerAgent(t, "inventory", "software_install")
	a.applyPeerPolicy(context.Background(), &agentv1.PeerCachePolicy{Enabled: true, Port: freePort(t), MaxMb: 512}, root, cert, iss, key)
	if a.peerPort.Load() != 0 || a.peer.cache != nil {
		t.Fatal("the ceiling was overridden by the server")
	}
	b, root, cert, iss, key := peerAgent(t, "inventory", "peer_cache")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.applyPeerPolicy(ctx, &agentv1.PeerCachePolicy{Enabled: true, Port: freePort(t), MaxMb: 512}, root, cert, iss, key)
	if b.peerPort.Load() == 0 {
		t.Fatal("a ceiling that names peer_cache allows it")
	}
	for _, p := range []uint32{0, 80, 1023, 70000} {
		c, root, cert, iss, key := peerAgent(t)
		c.applyPeerPolicy(ctx, &agentv1.PeerCachePolicy{Enabled: true, Port: p, MaxMb: 512}, root, cert, iss, key)
		if c.peerPort.Load() != 0 {
			t.Errorf("port %d accepted", p)
		}
	}
}

func TestAPortThatIsInUseIsNotReportedAsSharing(t *testing.T) {
	a, root, cert, iss, key := peerAgent(t)
	ln, _ := net.Listen("tcp4", ":0")
	defer ln.Close()
	a.applyPeerPolicy(context.Background(), &agentv1.PeerCachePolicy{Enabled: true, Port: uint32(ln.Addr().(*net.TCPAddr).Port), MaxMb: 512}, root, cert, iss, key)
	if a.peerPort.Load() != 0 {
		t.Fatal("reported a port it could not open")
	}
}
