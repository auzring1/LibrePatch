// Package text holds the string helpers that more than one binary needs.
package text

import (
	"strings"
	"unicode/utf8"
)

// Truncate cuts s to at most max bytes without splitting a UTF-8 sequence. Protobuf and PostgreSQL both reject invalid
// UTF-8, so a plain s[:max] on text that came from a registry, an installer log or an agent can make a report or a
// database write fail.
func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 0 {
		return ""
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max]
}

// CSVSafe neutralizes spreadsheet formula injection (OWASP "CSV Injection"): a cell starting with = + - @ tab or CR is
// prefixed with an apostrophe so Excel and LibreOffice treat it as text. Every CSV the server writes passes its cells
// through this one function, because the values come from endpoints and are untrusted.
func CSVSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
