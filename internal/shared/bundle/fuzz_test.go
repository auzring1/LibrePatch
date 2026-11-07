package bundle

import "testing"

// FuzzParse: an enrollment string is typed or pasted by an administrator, but it is still parsed
// as untrusted text. Whatever Parse accepts must survive Encode and Parse again unchanged.
func FuzzParse(f *testing.F) {
	good := Bundle{V: 1, Gateway: "librepatch.example.com:8443", RootPin: "sha256/" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Token: "tok", Org: "00000000-0000-0000-0000-000000000001"}
	if s, err := good.Encode(); err == nil {
		f.Add(s)
	}
	f.Add("LP1.")
	f.Add("LP1.e30")
	f.Fuzz(func(t *testing.T, s string) {
		b, err := Parse(s)
		if err != nil {
			return
		}
		enc, err := b.Encode()
		if err != nil {
			t.Fatalf("accepted %q but cannot encode it: %v", s, err)
		}
		again, err := Parse(enc)
		if err != nil || again != b {
			t.Fatalf("round trip changed the bundle: %+v -> %+v (%v)", b, again, err)
		}
	})
}
