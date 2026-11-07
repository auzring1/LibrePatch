// Package vercmp compares software version strings and encodes them as
// byte strings whose lexicographic order equals version order. The server
// stores the encoding (bytea) so "version < X" works in SQL, and the agent
// uses the same code for detection rules (Phase 3), so both always agree.
//
// Semantics (modelled on winget): versions split into segments at '.', '-',
// '_', '+', spaces and digit/letter boundaries. Numeric segments compare by
// value, text segments case-insensitively. Trailing zero segments are
// insignificant (1.0 == 1.0.0), a pre-release text suffix sorts before the
// release (1.0-beta < 1.0), and extra numeric segments sort after
// (1.0 < 1.0.1). Unparseable or empty versions have no key (nil).
package vercmp

import (
	"bytes"
	"strings"
)

// Segment tags. Order matters: text < end < number gives
// 1.0-beta < 1.0 < 1.0.1 under plain byte comparison.
const (
	tagText = 0x10
	tagEnd  = 0x20
	tagNum  = 0x30

	// MaxKeyLen bounds the encoded key (inputs are attacker-influenced).
	MaxKeyLen = 512
	maxDigits = 40
)

type segment struct {
	text bool
	val  string // digits without leading zeros, or lowercased text
}

// Key returns the sortable encoding of v, or nil if v has no usable version
// (empty, no digits at all, or too long). Callers store nil as SQL NULL.
func Key(v string) []byte {
	segs, ok := parse(v)
	if !ok {
		return nil
	}
	segs = trimZeros(segs)
	out := make([]byte, 0, 16)
	for _, s := range segs {
		if s.text {
			out = append(out, tagText)
			out = append(out, s.val...)
			out = append(out, 0x00)
		} else {
			out = append(out, tagNum, byte(len(s.val))) // #nosec G115 -- parse caps segments at maxDigits
			out = append(out, s.val...)
		}
		if len(out) > MaxKeyLen {
			return nil
		}
	}
	return append(out, tagEnd)
}

// Compare returns -1, 0 or +1. Versions without a key sort before all others
// (and equal each other).
func Compare(a, b string) int {
	return bytes.Compare(Key(a), Key(b))
}

func parse(v string) ([]segment, bool) {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 256 {
		return nil, false
	}
	// "v1.2.3" -> "1.2.3"
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	var segs []segment
	hasDigit := false
	i := 0
	for i < len(v) {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			j := i
			for j < len(v) && v[j] >= '0' && v[j] <= '9' {
				j++
			}
			d := strings.TrimLeft(v[i:j], "0")
			if d == "" {
				d = "0"
			}
			if len(d) > maxDigits {
				return nil, false
			}
			segs = append(segs, segment{val: d})
			hasDigit = true
			i = j
		case isLetter(c):
			j := i
			for j < len(v) && isLetter(v[j]) {
				j++
			}
			segs = append(segs, segment{text: true, val: strings.ToLower(v[i:j])})
			i = j
		default:
			i++ // separator
		}
	}
	if !hasDigit {
		return nil, false
	}
	return segs, true
}

func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// trimZeros removes numeric-zero segments whose next non-zero segment is the
// end or a text segment, so 1.0 == 1.0.0 and 1.0-beta == 1.0.0-beta, while
// 1.0.2 keeps its zero.
func trimZeros(s []segment) []segment {
	out := make([]segment, 0, len(s))
	for i, seg := range s {
		if !seg.text && seg.val == "0" {
			j := i + 1
			for j < len(s) && !s[j].text && s[j].val == "0" {
				j++
			}
			if j == len(s) || s[j].text {
				continue
			}
		}
		out = append(out, seg)
	}
	return out
}
