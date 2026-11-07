package vercmp

import (
	"bytes"
	"strings"
	"testing"
)

func TestOrdering(t *testing.T) {
	// Each row must be strictly increasing under Compare.
	chains := [][]string{
		{"1", "1.0.1", "1.1", "1.10", "2", "10", "100"},
		{"130.0.6723.91", "130.0.6723.92", "131.0.1", "200"},
		{"1.0-alpha", "1.0-beta", "1.0-rc1", "1.0-rc2", "1.0", "1.0.1"},
		{"2023.01.05", "2023.1.6", "2023.12.1"},
		{"7.9", "7.10", "23.01"},
		{"1.0.0.0.1", "1.0.0.1", "1.0.1"},
		{"9", "9.1", "9.1.1a", "9.1.1b", "9.1.2"},
	}
	for _, c := range chains {
		for i := 0; i+1 < len(c); i++ {
			if got := Compare(c[i], c[i+1]); got != -1 {
				t.Errorf("Compare(%q, %q) = %d, want -1", c[i], c[i+1], got)
			}
			if got := Compare(c[i+1], c[i]); got != 1 {
				t.Errorf("Compare(%q, %q) = %d, want 1", c[i+1], c[i], got)
			}
		}
	}
}

func TestEquality(t *testing.T) {
	groups := [][]string{
		{"1.0", "1.0.0", "1", "1.0.0.0", "v1.0", "V1"},
		{"1.0-beta", "1.0.0-BETA", "1-beta"},
		{"001.002", "1.2"},
		{"2.0.0_1", "2.0.0-1", "2.0.0.1", "2 0 0 1"},
	}
	for _, g := range groups {
		for _, v := range g[1:] {
			if Compare(g[0], v) != 0 {
				t.Errorf("Compare(%q, %q) != 0 (keys %x vs %x)", g[0], v, Key(g[0]), Key(v))
			}
		}
	}
}

func TestNoKey(t *testing.T) {
	for _, v := range []string{"", "   ", "unknown", "beta", "-", "v", string(bytes.Repeat([]byte("1"), 300))} {
		if Key(v) != nil {
			t.Errorf("Key(%q) should be nil", v)
		}
	}
	// Unversioned sorts below everything.
	if Compare("", "0.0.1") != -1 || Compare("", "") != 0 {
		t.Error("nil key ordering")
	}
}

func TestRealWorldVersions(t *testing.T) {
	cases := []struct{ a, b string }{
		{"23.01", "24.08"},                  // 7-Zip
		{"8.8.9", "8.9"},                    // Notepad++
		{"14.38.33135.0", "14.40.33810.0"},  // VC++ redist
		{"129.0.6668.101", "130.0.6723.59"}, // Chrome
		{"1.93.1", "1.94.0"},                // VS Code
		{"5.0.1.2345", "5.0.2"},
		{"2024.1", "2024.1.1"},
		{"10.0.19045.4894", "10.0.22631.4037"}, // Windows builds
	}
	for _, c := range cases {
		if Compare(c.a, c.b) != -1 {
			t.Errorf("%q should be < %q", c.a, c.b)
		}
	}
}

func TestKeyBounded(t *testing.T) {
	long := ""
	for i := 0; i < 200; i++ {
		long += "1."
	}
	if k := Key(long); k != nil && len(k) > MaxKeyLen+maxDigits+3 {
		t.Fatalf("unbounded key: %d", len(k))
	}
}

func FuzzKey(f *testing.F) {
	for _, s := range []string{"1.0", "v2.3.4-beta1", "", "1..2", "0", "٣.٤", "1.0\x00", "99999999999999999999999999999999999999999999"} {
		f.Add(s, "1.0")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		ka, kb := Key(a), Key(b)
		// antisymmetry
		if bytes.Compare(ka, kb) != -bytes.Compare(kb, ka) {
			t.Fatalf("not antisymmetric: %q %q", a, b)
		}
		// deterministic
		if !bytes.Equal(ka, Key(a)) {
			t.Fatalf("not deterministic: %q", a)
		}
		// bounded
		if len(ka) > MaxKeyLen+maxDigits+3 {
			t.Fatalf("key too long for %q", a)
		}
	})
}

func TestHugeNumericSegmentHasNoKey(t *testing.T) {
	// Segments are capped so the one-byte digit-length prefix can never wrap.
	if Key("1"+strings.Repeat("0", maxDigits)) != nil {
		t.Fatal("over-long segment accepted")
	}
	if Key("1"+strings.Repeat("0", maxDigits-1)) == nil {
		t.Fatal("longest allowed segment rejected")
	}
}
