package jobs

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

func peerSource(url string) *agentv1.ContentSource {
	return &agentv1.ContentSource{Kind: agentv1.ContentSourceKind_CONTENT_SOURCE_KIND_PEER, Url: url}
}

func TestAnUnavailablePeerFallsBackToTheVendorAndTheFileIsKept(t *testing.T) {
	r := newRig(t)
	r.installerRegisters("2.0", 0)
	var kept [][]byte
	r.e.CacheFile = func(path string, sha []byte) { kept = append(kept, sha) }
	se, env := r.installEnv("j1", func(_ *agentv1.JobEnvelope, b *agentv1.InstallBody) {
		b.Installer.Sources = append([]*agentv1.ContentSource{peerSource("https://192.168.7.9:7421")}, b.Installer.Sources...)
	})
	r.e.Accept(se, env)
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(kept) != 1 {
		t.Fatalf("%v kept=%d %+v", r.state("j1"), len(kept), r.rec.last("j1"))
	}
}

func TestAPeerThatSendsTheWrongBytesIsSkippedAndNothingIsKept(t *testing.T) {
	r := newRig(t)
	r.installerRegisters("2.0", 0)
	r.f.data["https://192.168.7.9:7421"] = []byte("not the installer")
	kept := 0
	r.e.CacheFile = func(string, []byte) { kept++ }
	se, env := r.installEnv("j1", func(_ *agentv1.JobEnvelope, b *agentv1.InstallBody) {
		b.Installer.Sources = append([]*agentv1.ContentSource{peerSource("https://192.168.7.9:7421")}, b.Installer.Sources...)
	})
	r.e.Accept(se, env)
	r.tick()
	if r.state("j1") != agentv1.JobState_JOB_STATE_SUCCEEDED || kept != 1 {
		t.Fatalf("%v kept=%d", r.state("j1"), kept)
	}
	// A wrong-bytes peer is reported as a mismatch to the fallback logic, not as a security event: a peer may simply be stale.
	for _, k := range r.rec.sec {
		if k == agentv1.SecurityEventKind_SECURITY_EVENT_KIND_HASH_MISMATCH {
			t.Fatal("a bad peer answer must not raise a security event when another source delivered the file")
		}
	}
}

func TestPeerSourcesAreValidatedBeforeTheJobIsAccepted(t *testing.T) {
	for _, bad := range []string{"https://example.com:7421", "https://8.8.8.8:7421", "http://192.168.1.2:7421", "https://192.168.1.2:80", "https://192.168.1.2:7421/x"} {
		r := newRig(t)
		se, env := r.installEnv("j1", func(_ *agentv1.JobEnvelope, b *agentv1.InstallBody) {
			b.Installer.Sources = append([]*agentv1.ContentSource{peerSource(bad)}, b.Installer.Sources...)
		})
		r.e.Accept(se, env)
		if r.state("j1") != agentv1.JobState_JOB_STATE_REJECTED {
			t.Errorf("%s: %v", bad, r.state("j1"))
		}
	}
}

func TestMultiFetcherUsesThePeerFunctionOnlyForPeerSources(t *testing.T) {
	var asked []string
	m := &MultiFetcher{Peer: func(_ context.Context, url string, sha []byte) (io.ReadCloser, error) {
		asked = append(asked, url)
		return io.NopCloser(strings.NewReader("x")), nil
	}}
	rc, err := m.Open(context.Background(), peerSource("https://10.0.0.5:7421"), "j", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	_ = rc.Close()
	if len(asked) != 1 || asked[0] != "https://10.0.0.5:7421" {
		t.Fatalf("%v", asked)
	}
	if _, err := (&MultiFetcher{}).Open(context.Background(), peerSource("https://10.0.0.5:7421"), "j", nil); err == nil {
		t.Fatal("without sharing turned on a peer source must fail")
	}
	m.Peer = func(context.Context, string, []byte) (io.ReadCloser, error) { return nil, errors.New("down") }
	if _, err := m.Open(context.Background(), peerSource("https://10.0.0.5:7421"), "j", nil); err == nil {
		t.Fatal("an unreachable peer is an error")
	}
}
