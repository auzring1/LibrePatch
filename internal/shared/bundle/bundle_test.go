package bundle

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func valid() Bundle {
	tok := make([]byte, 32)
	_, _ = rand.Read(tok)
	pin := make([]byte, 32)
	return Bundle{V: 1, Gateway: "agents.example.com:8443", RootPin: "sha256/" + base64.StdEncoding.EncodeToString(pin),
		Token: base64.RawURLEncoding.EncodeToString(tok), Org: uuid.NewString()}
}

func TestRoundTrip(t *testing.T) {
	b := valid()
	s, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, "LP1.") {
		t.Fatal(s)
	}
	got, err := Parse("  " + s + "\n")
	if err != nil || got != b {
		t.Fatalf("got %+v err %v", got, err)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]func(*Bundle){
		"version": func(b *Bundle) { b.V = 2 },
		"gateway": func(b *Bundle) { b.Gateway = "nohostport" },
		"pin":     func(b *Bundle) { b.RootPin = "md5/abc" },
		"pinlen":  func(b *Bundle) { b.RootPin = "sha256/YWJj" },
		"token":   func(b *Bundle) { b.Token = "short" },
		"org":     func(b *Bundle) { b.Org = "x" },
	}
	for name, mut := range cases {
		b := valid()
		mut(&b)
		if _, err := b.Encode(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	for _, s := range []string{"", "CUR2.abc", "LP1.!!!", "LP1." + base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"extra":1}`))} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q): expected error", s)
		}
	}
}
