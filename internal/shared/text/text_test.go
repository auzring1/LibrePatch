package text

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"abc", 5, "abc"},
		{"abc", 3, "abc"},
		{"abc", 2, "ab"},
		{"abc", 0, ""},
		{"abc", -1, ""},
		{"aé", 2, "a"},  // é is two bytes: do not keep half of it
		{"aé", 3, "aé"}, // exactly fits
		{"日本語", 4, "日"},
		{"😀😀", 7, "😀"},
		{"", 4, ""},
	}
	for _, c := range cases {
		if got := Truncate(c.in, c.max); got != c.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
	}
}

func TestTruncateKeepsValidUTF8(t *testing.T) {
	s := strings.Repeat("aé日😀", 50)
	for max := 0; max < len(s); max++ {
		got := Truncate(s, max)
		if len(got) > max || !utf8.ValidString(got) {
			t.Fatalf("max %d: got %d bytes, valid=%v", max, len(got), utf8.ValidString(got))
		}
	}
}
