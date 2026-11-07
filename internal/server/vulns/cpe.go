// Package vulns looks up known vulnerabilities for what is installed on the fleet (Phase 7, D123).
//
// It combines two public feeds: the CISA catalog of vulnerabilities known to be exploited (KEV) and the NIST National
// Vulnerability Database (NVD), whose entries say which product versions a CVE affects. An installed program is
// found in the NVD data through a CPE vendor and product name (a mapping the administrator can edit); Windows itself
// through its build number. Everything is matched on this server, against inventory the agents already report: nothing
// about the fleet is sent anywhere.
package vulns

import (
	"errors"
	"strings"
)

// CPE is the part of a CPE 2.3 name the matching needs.
type CPE struct {
	Part    string // "a" application, "o" operating system, "h" hardware
	Vendor  string
	Product string
	Version string // "*" and "-" mean any
}

// ParseCPE23 reads a CPE 2.3 formatted string such as "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*". A colon inside a
// component is escaped with a backslash, and so are some punctuation characters ("notepad\+\+").
func ParseCPE23(s string) (CPE, error) {
	parts := splitCPE(s)
	if len(parts) < 6 || parts[0] != "cpe" || parts[1] != "2.3" {
		return CPE{}, errors.New("not a CPE 2.3 name")
	}
	c := CPE{Part: parts[2], Vendor: unescapeCPE(parts[3]), Product: unescapeCPE(parts[4]), Version: unescapeCPE(parts[5])}
	if c.Part == "" || c.Vendor == "" || c.Product == "" || len(s) > 600 {
		return CPE{}, errors.New("incomplete CPE name")
	}
	return c, nil
}

// splitCPE splits on colons that are not escaped.
func splitCPE(s string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			cur.WriteByte(s[i])
			cur.WriteByte(s[i+1])
			i++
		case s[i] == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	return append(out, cur.String())
}

func unescapeCPE(s string) string {
	if !strings.Contains(s, `\`) {
		return strings.ToLower(s)
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return strings.ToLower(b.String())
}

// Any reports whether the version component names no particular version.
func (c CPE) Any() bool { return c.Version == "" || c.Version == "*" || c.Version == "-" }
