// Package inventory ingests agent software and user inventory, normalizes
// titles so the same product groups together across versions and installers,
// and stores it with version keys for fleet-wide queries.
package inventory

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	archParenRe  = regexp.MustCompile(`(?i)\s*\([^)]*\b(?:x64|x86|x86_64|amd64|arm64|64-bit|32-bit|64 bit|32 bit|win64|win32)\b[^)]*\)`)
	archTokenRe  = regexp.MustCompile(`(?i)(?:^|[\s_-])(?:x64|x86|x86_64|amd64|arm64|win64|win32|64-bit|32-bit|64bit|32bit)(?:$|[\s_-])`)
	scopeParenRe = regexp.MustCompile(`(?i)\s*\((?:user|machine|system|per-user|all users|current user)\)\s*$`)
	trailVersion = regexp.MustCompile(`(?i)[\s_\-–—]+v?\d+(?:\.\d+)+[0-9a-z.+\-]*\s*$`)
	spaceRe      = regexp.MustCompile(`\s+`)
	pubSuffixRe  = regexp.MustCompile(`\b(?:incorporated|inc|llc|l\.l\.c|ltd|limited|corp|corporation|gmbh|co|company|ag|bv|b\.v|plc|oy|s\.a|sa|srl|pty)\b\.?`)
	pubPunctRe   = regexp.MustCompile(`[^\p{L}\p{N}+#&]+`)
)

// MaxNormalizedLen bounds stored normalized values.
const MaxNormalizedLen = 300

// NormalizeName reduces a software display name to a stable product identity:
// lower case, no trademark marks, no version, architecture or per-user/machine
// qualifiers. It never returns an empty string.
func NormalizeName(name, version string) string {
	// Lower-casing can lengthen a string (some runes map to longer ones), so
	// the bound is applied after it.
	return clipRunes(strings.ToLower(reduceName(name, version)), MaxNormalizedLen)
}

// DisplayName is NormalizeName with the original capitalization, for showing
// a product in lists ("7-Zip" rather than "7-Zip 23.01 (x64 edition)").
func DisplayName(name, version string) string {
	return reduceName(name, version)
}

func reduceName(name, version string) string {
	orig := strings.TrimSpace(strings.ToValidUTF8(name, "\uFFFD"))
	version = strings.ToValidUTF8(version, "\uFFFD")
	n := strings.NewReplacer("™", "", "®", "", "©", "", "\u00a0", " ").Replace(orig)
	if v := strings.TrimSpace(version); v != "" {
		n = removeWord(removeWord(n, "v"+v), v)
	}
	n = archParenRe.ReplaceAllString(n, "")
	n = scopeParenRe.ReplaceAllString(n, "")
	// Architecture tokens outside parentheses ("... x64 ...", "- 64-bit").
	for {
		loc := archTokenRe.FindStringIndex(n)
		if loc == nil {
			break
		}
		n = n[:loc[0]] + " " + n[loc[1]:]
	}
	for { // strip repeated trailing version numbers: "foo 1.2 - 14.3.4"
		next := trailVersion.ReplaceAllString(n, "")
		if next == n {
			break
		}
		n = next
	}
	n = strings.Trim(spaceRe.ReplaceAllString(n, " "), " -–—_,.;:")
	if n == "" {
		n = strings.Trim(spaceRe.ReplaceAllString(orig, " "), " ")
	}
	if n == "" {
		n = "unknown"
	}
	return clipRunes(n, MaxNormalizedLen)
}

// NormalizePublisher reduces a publisher to its distinguishing words.
func NormalizePublisher(p string) string {
	p = strings.ToLower(strings.TrimSpace(strings.ToValidUTF8(p, "\uFFFD")))
	p = strings.NewReplacer("™", "", "®", "", "©", "").Replace(p)
	p = pubSuffixRe.ReplaceAllString(p, " ")
	p = strings.TrimPrefix(strings.TrimSpace(p), "the ")
	p = pubPunctRe.ReplaceAllString(p, " ")
	p = strings.Join(strings.Fields(p), " ")
	return clipRunes(p, MaxNormalizedLen)
}

// removeWord removes case-insensitive occurrences of tok that are delimited by
// non-alphanumerics. Inputs whose lower-casing changes byte length (rare
// non-ASCII case mappings) are left untouched rather than risk bad offsets.
func removeWord(s, tok string) string {
	if tok == "" || len(tok) > 100 {
		return s
	}
	low, lowTok := strings.ToLower(s), strings.ToLower(tok)
	if len(low) != len(s) || len(lowTok) != len(tok) {
		return s
	}
	var out strings.Builder
	for {
		i := strings.Index(low, lowTok)
		if i < 0 {
			out.WriteString(s)
			break
		}
		end := i + len(lowTok)
		before := i == 0 || !isAlnum(rune(low[i-1]))
		after := end == len(low) || !isAlnum(rune(low[end]))
		if before && after {
			out.WriteString(s[:i])
		} else {
			out.WriteString(s[:end])
		}
		s, low = s[end:], low[end:]
	}
	return out.String()
}

func isAlnum(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

func clipRunes(s string, max int) string {
	if len(s) <= max && utf8.ValidString(s) {
		return s
	}
	r := []rune(strings.ToValidUTF8(s, "\uFFFD"))
	for len(string(r)) > max {
		r = r[:len(r)-1]
	}
	return string(r)
}
