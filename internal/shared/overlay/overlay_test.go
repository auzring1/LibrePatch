package overlay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

const good = `{
  "format": "librepatch-overlay/1",
  "name": "Clinic IT overlay",
  "version": 3,
  "issued_at": "2026-10-19T12:00:00Z",
  "packages": [
    {"identifier": "7zip.7zip", "self_updating": false, "verified": true, "verified_note": "Tested on the Windows 11 image", "silent_args": ["/S"]},
    {"identifier": "Google.Chrome", "self_updating": true, "note": "Updates itself."}
  ]
}`

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := keys(t)
	b, err := Sign(priv, []byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if b.KeyID != KeyID(pub) || b.Format != BundleFormat {
		t.Fatalf("bundle: %+v", b)
	}
	raw, _ := json.Marshal(b)
	doc, _, err := Verify(raw, pub)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Name != "Clinic IT overlay" || doc.Version != 3 || len(doc.Packages) != 2 || !doc.Packages[0].Verified || doc.Packages[1].SelfUpdating == nil || !*doc.Packages[1].SelfUpdating {
		t.Fatalf("document: %+v", doc)
	}
}

func TestAWrongKeyOrATamperedDocumentIsRefused(t *testing.T) {
	pub, priv := keys(t)
	other, _ := keys(t)
	b, _ := Sign(priv, []byte(good))
	raw, _ := json.Marshal(b)
	if _, _, err := Verify(raw, other); !errors.Is(err, ErrSignature) {
		t.Fatalf("a different key: %v", err)
	}
	// Change one thing the signature covers: the silent argument.
	tampered := strings.Replace(string(raw), `\"/S\"`, `\"/Q\"`, 1)
	tampered = strings.Replace(tampered, `"/S"`, `"/Q"`, 1)
	if tampered == string(raw) {
		t.Fatal("the test did not change the document")
	}
	if _, _, err := Verify([]byte(tampered), pub); !errors.Is(err, ErrSignature) {
		t.Fatalf("a tampered document: %v", err)
	}
	// Whitespace is not covered, so a re-indented file still verifies.
	var indented bytes.Buffer
	if err := json.Indent(&indented, raw, "", "    "); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(indented.Bytes(), pub); err != nil {
		t.Fatalf("re-indented: %v", err)
	}
}

func TestASignatureMadeWithoutTheDomainDoesNotVerify(t *testing.T) {
	// The signature covers a domain string, so a signature over the bare document (what any other signer of this key
	// might have produced) is not accepted as an overlay.
	pub, priv := keys(t)
	var c bytes.Buffer
	if err := json.Compact(&c, []byte(good)); err != nil {
		t.Fatal(err)
	}
	b := Bundle{Format: BundleFormat, Overlay: json.RawMessage(c.Bytes()), KeyID: KeyID(pub), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, c.Bytes()))}
	raw, _ := json.Marshal(b)
	if _, _, err := Verify(raw, pub); !errors.Is(err, ErrSignature) {
		t.Fatalf("a signature without the domain: %v", err)
	}
	b.Signature = ""
	raw, _ = json.Marshal(b)
	if _, _, err := Verify(raw, pub); !errors.Is(err, ErrSignature) {
		t.Fatalf("an empty signature: %v", err)
	}
}

func TestParseDocumentRefusesBadInput(t *testing.T) {
	cases := map[string]string{
		"unknown field":   `{"format":"librepatch-overlay/1","name":"x","version":1,"packages":[],"extra":1}`,
		"wrong format":    `{"format":"librepatch-overlay/2","name":"x","version":1,"packages":[]}`,
		"no name":         `{"format":"librepatch-overlay/1","name":" ","version":1,"packages":[]}`,
		"version zero":    `{"format":"librepatch-overlay/1","name":"x","version":0,"packages":[]}`,
		"bad time":        `{"format":"librepatch-overlay/1","name":"x","version":1,"issued_at":"yesterday","packages":[]}`,
		"duplicate":       `{"format":"librepatch-overlay/1","name":"x","version":1,"packages":[{"identifier":"A.B"},{"identifier":"a.b"}]}`,
		"space in id":     `{"format":"librepatch-overlay/1","name":"x","version":1,"packages":[{"identifier":"A B"}]}`,
		"unsafe argument": `{"format":"librepatch-overlay/1","name":"x","version":1,"packages":[{"identifier":"A.B","silent_args":["/S; calc"]}]}`,
		"bad program":     `{"format":"librepatch-overlay/1","name":"x","version":1,"packages":[{"identifier":"A.B","processes":["C:\\x\\a.exe"]}]}`,
		"windows program": `{"format":"librepatch-overlay/1","name":"x","version":1,"packages":[{"identifier":"A.B","processes":["lsass.exe"]}]}`,
		"note too long":   `{"format":"librepatch-overlay/1","name":"x","version":1,"packages":[{"identifier":"A.B","note":"` + strings.Repeat("n", 501) + `"}]}`,
		"orphan note":     `{"format":"librepatch-overlay/1","name":"x","version":1,"packages":[{"identifier":"A.B","verified_note":"yes"}]}`,
		"trailing data":   `{"format":"librepatch-overlay/1","name":"x","version":1,"packages":[]} {}`,
		"not json":        `hello`,
	}
	for name, doc := range cases {
		if _, err := ParseDocument([]byte(doc)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted or wrong error: %v", name, err)
		}
	}
	if _, err := ParseDocument([]byte(`{"format":"librepatch-overlay/1","name":"x","version":1,"packages":[]}`)); err != nil {
		t.Fatalf("an empty overlay is valid: %v", err)
	}
}

func TestSignRefusesAnInvalidDocument(t *testing.T) {
	_, priv := keys(t)
	if _, err := Sign(priv, []byte(`{"format":"librepatch-overlay/1","name":"x","version":1,"packages":[{"identifier":"A.B","silent_args":["/S && evil"]}]}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("signing an unsafe overlay: %v", err)
	}
}

func TestVerifyRefusesNonBundles(t *testing.T) {
	pub, _ := keys(t)
	for _, in := range []string{"", "{}", `{"format":"x"}`, `{"format":"librepatch-overlay-bundle/1","overlay":{},"key_id":"","signature":"!!"}`, strings.Repeat("a", MaxBundleBytes+1)} {
		if _, _, err := Verify([]byte(in), pub); err == nil {
			t.Errorf("accepted %.30q", in)
		}
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, _ := keys(t)
	if _, err := ParsePublicKey(" " + strings.ToUpper(hexOf(pub)) + "\n"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "zz", "abcd"} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, d[c>>4], d[c&15])
	}
	return string(out)
}
