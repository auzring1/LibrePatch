package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/auzring1/librepatch/internal/shared/release"
)

// TestExternalSignerRoundTrip walks the KMS contract (decision D68): manifest -> tosign -> external
// Ed25519 signature -> attach -> verify, and checks the result equals what `sign` produces in one step.
func TestExternalSignerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	exe := p("agent.exe")
	if err := os.WriteFile(exe, []byte("MZ-not-really-an-exe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := keygen([]string{"--out", p("release.key")}); err != nil {
		t.Fatal(err)
	}
	common := []string{"--exe", exe, "--version", "1.2.3", "--authenticode-subject", "CN=Dry Run", "--released-at", "1700000000"}
	if err := manifestCmd(append([]string{"--out", p("manifest.json")}, common...)); err != nil {
		t.Fatal(err)
	}
	if err := toSign([]string{"--manifest", p("manifest.json"), "--out", p("tosign.bin")}); err != nil {
		t.Fatal(err)
	}
	mb, _ := os.ReadFile(p("manifest.json"))
	tb, _ := os.ReadFile(p("tosign.bin"))
	if !bytes.Equal(tb, append([]byte(release.Domain), mb...)) {
		t.Fatal("tosign is not domain prefix + manifest")
	}
	if err := signBytes([]string{"--key", p("release.key"), "--in", p("tosign.bin"), "--out", p("sig.bin")}); err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(p("release.pub"))
	raw, err := hex.DecodeString(strings.TrimSpace(string(pub)))
	if err != nil || len(raw) != 32 {
		t.Fatal("bad public key file")
	}
	kid := release.KeyID(raw)
	// A signature from some other key must be refused at attach time.
	if err := keygen([]string{"--out", p("other.key")}); err != nil {
		t.Fatal(err)
	}
	if err := attach([]string{"--manifest", p("manifest.json"), "--signature", p("sig.bin"), "--pub", p("other.pub"), "--out", p("wrong.lprel")}); err == nil {
		t.Fatal("attach accepted a signature that does not verify under the given public key")
	}
	if err := attach([]string{"--manifest", p("manifest.json"), "--signature", p("sig.bin"), "--pub", p("release.pub"), "--out", p("external.lprel")}); err != nil {
		t.Fatal(err)
	}
	if err := attach([]string{"--manifest", p("manifest.json"), "--signature", p("sig.bin"), "--key-id", kid, "--out", p("byid.lprel")}); err != nil {
		t.Fatal(err)
	}
	if err := verify([]string{"--bundle", p("external.lprel"), "--exe", exe, "--pub", p("release.pub")}); err != nil {
		t.Fatalf("external-signed bundle does not verify: %v", err)
	}
	// One-step `sign` with the same fixed released-at gives the same bundle (Ed25519 is deterministic).
	if err := sign(append([]string{"--key", p("release.key"), "--out", p("direct.lprel")}, common...)); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(p("external.lprel"))
	b, _ := os.ReadFile(p("direct.lprel"))
	if !bytes.Equal(a, b) {
		t.Fatal("manifest/tosign/attach and sign disagree")
	}
}

func TestSignBytesRefusesForeignInput(t *testing.T) {
	dir := t.TempDir()
	if err := keygen([]string{"--out", filepath.Join(dir, "k.key")}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x"), []byte("some other message"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := signBytes([]string{"--key", filepath.Join(dir, "k.key"), "--in", filepath.Join(dir, "x"), "--out", filepath.Join(dir, "s")}); err == nil {
		t.Fatal("signed bytes without the release domain prefix")
	}
}
