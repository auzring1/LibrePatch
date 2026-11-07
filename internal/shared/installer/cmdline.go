package installer

import (
	"errors"
	"strings"
)

// SplitCommandLine splits a Windows command line (as stored in an
// UninstallString) into arguments using the CommandLineToArgvW rules for
// quotes and backslashes. It performs no expansion and runs nothing.
func SplitCommandLine(s string) ([]string, error) {
	if len(s) > 4096 {
		return nil, errors.New("command line too long")
	}
	var args []string
	var cur strings.Builder
	inQuote, have := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			n := 0
			for i < len(s) && s[i] == '\\' {
				n++
				i++
			}
			if i < len(s) && s[i] == '"' {
				cur.WriteString(strings.Repeat(`\`, n/2))
				if n%2 == 1 {
					cur.WriteByte('"')
					i++
				}
				// an even count leaves the quote to be processed next
				i--
			} else {
				cur.WriteString(strings.Repeat(`\`, n))
				i--
			}
			have = true
		case c == '"':
			inQuote = !inQuote
			have = true
		case (c == ' ' || c == '\t') && !inQuote:
			if have {
				args = append(args, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteByte(c)
			have = true
		}
	}
	if inQuote {
		return nil, errors.New("unbalanced quote in command line")
	}
	if have {
		args = append(args, cur.String())
	}
	return args, nil
}

// EscapeArg quotes one argument for a Windows command line, the inverse of
// SplitCommandLine (same rules as golang.org/x/sys/windows.EscapeArg).
func EscapeArg(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	bs := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			bs++
		case '"':
			b.WriteString(strings.Repeat(`\`, bs*2+1))
			b.WriteByte('"')
			bs = 0
		default:
			b.WriteString(strings.Repeat(`\`, bs))
			bs = 0
			b.WriteByte(c)
		}
	}
	b.WriteString(strings.Repeat(`\`, bs*2))
	b.WriteByte('"')
	return b.String()
}

// ComposeCommandLine joins exe and args into one command line.
func ComposeCommandLine(exe string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, EscapeArg(exe))
	for _, a := range args {
		parts = append(parts, EscapeArg(a))
	}
	return strings.Join(parts, " ")
}
