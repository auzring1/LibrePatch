package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func manifest(version string) *Manifest {
	h := sha256.Sum256([]byte("binary " + version))
	return &Manifest{Format: 1, Product: Product, Version: version, OS: "windows", Arch: "amd64", SHA256: hex.EncodeToString(h[:]), Size: 1234}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := key(t)
	mb, err := Marshal(manifest("1.2.3"))
	if err != nil {
		t.Fatal(err)
	}
	sig := Sign(priv, mb)
	m, err := Verify([]ed25519.PublicKey{pub}, mb, sig, KeyID(pub))
	if err != nil || m.Version != "1.2.3" {
		t.Fatalf("verify: %v %+v", err, m)
	}
	// An empty key id means "try every key" (a bundle without one is still checked).
	if _, err := Verify([]ed25519.PublicKey{pub}, mb, sig, ""); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRefuses(t *testing.T) {
	pub, priv := key(t)
	other, otherPriv := key(t)
	mb, _ := Marshal(manifest("1.2.3"))
	sig := Sign(priv, mb)

	if _, err := Verify(nil, mb, sig, ""); err == nil || !strings.Contains(err.Error(), "no vendor release key") {
		t.Fatalf("a build without keys must refuse everything: %v", err)
	}
	if _, err := Verify([]ed25519.PublicKey{other}, mb, sig, ""); err == nil {
		t.Fatal("signature by an untrusted key accepted")
	}
	if _, err := Verify([]ed25519.PublicKey{pub}, append([]byte(" "), mb...), sig, KeyID(pub)); err == nil {
		t.Fatal("tampered manifest accepted")
	}
	if _, err := Verify([]ed25519.PublicKey{pub}, mb, sig, KeyID(other)); err == nil {
		t.Fatal("key id mismatch accepted")
	}
	// The domain separator matters: a signature over the raw bytes is not a release signature.
	raw := ed25519.Sign(priv, mb)
	if _, err := Verify([]ed25519.PublicKey{pub}, mb, raw, KeyID(pub)); err == nil {
		t.Fatal("signature without the domain prefix accepted")
	}
	// Valid signature but a bad manifest (unknown field, bad hash, wrong product).
	for name, body := range map[string]string{
		"unknown field": `{"format":1,"product":"` + Product + `","version":"1.0.0","os":"windows","arch":"amd64","sha256":"` + strings.Repeat("a", 64) + `","size":5,"evil":true}`,
		"bad hash":      `{"format":1,"product":"` + Product + `","version":"1.0.0","os":"windows","arch":"amd64","sha256":"zz","size":5}`,
		"product":       `{"format":1,"product":"other","version":"1.0.0","os":"windows","arch":"amd64","sha256":"` + strings.Repeat("a", 64) + `","size":5}`,
		"trailing":      `{"format":1,"product":"` + Product + `","version":"1.0.0","os":"windows","arch":"amd64","sha256":"` + strings.Repeat("a", 64) + `","size":5} {}`,
		"huge":          `{"format":1,"product":"` + Product + `","version":"1.0.0","os":"windows","arch":"amd64","sha256":"` + strings.Repeat("a", 64) + `","size":999999999999}`,
	} {
		b := []byte(body)
		if _, err := Verify([]ed25519.PublicKey{other}, b, Sign(otherPriv, b), KeyID(other)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckApplicable(t *testing.T) {
	m := manifest("1.5.0")
	m.MinVersion = "1.2.0"
	for _, c := range []struct {
		cur, os, arch string
		ok            bool
	}{
		{"1.4.0", "windows", "amd64", true},
		{"1.2.0", "windows", "amd64", true},
		{"1.1.9", "windows", "amd64", false}, // too old for a direct jump
		{"1.5.0", "windows", "amd64", false}, // already running
		{"1.6.0", "windows", "amd64", false}, // downgrade
		{"1.4.0", "linux", "amd64", false},   // wrong platform
		{"1.4.0", "windows", "arm64", false},
	} {
		err := m.CheckApplicable(c.cur, c.os, c.arch)
		if (err == nil) != c.ok {
			t.Errorf("%+v: %v", c, err)
		}
	}
	rb := manifest("1.3.0")
	rb.RollbackFrom = []string{"1.4.0"}
	if err := rb.CheckApplicable("1.4.0", "windows", "amd64"); err != nil {
		t.Errorf("sanctioned rollback refused: %v", err)
	}
	if err := rb.CheckApplicable("1.4.1", "windows", "amd64"); err == nil {
		t.Error("rollback from an unlisted version allowed")
	}
}

func TestRequireAuthenticode(t *testing.T) {
	RequireAuthenticode = "true"
	defer func() { RequireAuthenticode = "" }()
	if _, err := Marshal(manifest("1.0.0")); err == nil {
		t.Fatal("a manifest without a pinned signer must be refused by a release build")
	}
	m := manifest("1.0.0")
	m.AuthenticodeSubject = "Example Vendor Ltd"
	if _, err := Marshal(m); err != nil {
		t.Fatal(err)
	}
}

// A stolen release key must not be enough to pin a certificate of the attacker's choosing.
func TestAuthenticodeSubjectsCompiledIn(t *testing.T) {
	AuthenticodeSubjects = "Example Vendor Ltd|Example Vendor Ltd (2027)"
	defer func() { AuthenticodeSubjects = "" }()
	for _, bad := range []string{"", "Evil Corp", "Example Vendor"} {
		m := manifest("1.0.0")
		m.AuthenticodeSubject = bad
		if _, err := Marshal(m); err == nil {
			t.Errorf("subject %q accepted by a build that trusts only the compiled-in subjects", bad)
		}
	}
	for _, good := range []string{"Example Vendor Ltd", "example vendor ltd (2027)"} {
		m := manifest("1.0.0")
		m.AuthenticodeSubject = good
		if _, err := Marshal(m); err != nil {
			t.Errorf("subject %q refused: %v", good, err)
		}
	}
}

func TestKeysAndBundle(t *testing.T) {
	pub, priv := key(t)
	keys, err := ParseKeys(hex.EncodeToString(pub) + " , ")
	if err != nil || len(keys) != 1 {
		t.Fatalf("%v %d", err, len(keys))
	}
	if _, err := ParseKeys("nothex"); err == nil {
		t.Fatal("bad key accepted")
	}
	mb, _ := Marshal(manifest("2.0.0"))
	enc, err := EncodeBundle(&Bundle{Manifest: mb, Signature: Sign(priv, mb), KeyID: KeyID(pub)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodeBundle(enc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(keys, b.Manifest, b.Signature, b.KeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBundle([]byte(`{"manifest":"","extra":1}`)); err == nil {
		t.Fatal("unknown bundle field accepted")
	}
}

func FuzzVerify(f *testing.F) {
	pub, priv := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		p, s, _ := ed25519.GenerateKey(rand.Reader)
		return p, s
	}()
	good, _ := Marshal(manifest("1.0.0"))
	f.Add(good)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		// A signed-by-us arbitrary body must either be rejected or yield a manifest that re-validates.
		m, err := Verify([]ed25519.PublicKey{pub}, b, Sign(priv, b), KeyID(pub))
		if err == nil {
			if verr := m.validate(); verr != nil {
				t.Fatalf("accepted a manifest that does not validate: %v", verr)
			}
		}
	})
}

// FuzzBundle: the .lprel file and the manifest inside it arrive from an upload (server) or from a job
// (agent). Parsing must never panic, and a manifest that ParseUnverified accepts must be one that
// Marshal accepts too (the signer and the verifier agree on what is valid).
func FuzzBundle(f *testing.F) {
	f.Add([]byte(`{"manifest":"e30=","signature":"AA==","key_id":"00"}`))
	f.Add([]byte(`{"format":1,"product":"` + Product + `","version":"1.2.3","os":"windows","arch":"amd64","sha256":"` + strings.Repeat("a", 64) + `","size":10}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeBundle(data)
		m, err := ParseUnverified(data)
		if err != nil {
			return
		}
		if _, err := Marshal(m); err != nil {
			t.Fatalf("ParseUnverified accepted a manifest that Marshal rejects: %v", err)
		}
		_ = m.CheckApplicable("1.0.0", "windows", "amd64")
	})
}
