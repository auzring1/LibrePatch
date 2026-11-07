package installer

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Limits on admin- or manifest-supplied extra arguments.
const (
	MaxArgs   = 32
	MaxArgLen = 256
)

var (
	// /switch, -switch, --switch with an optional =value or :value part.
	switchRe = regexp.MustCompile(`^(?:/|--?)[A-Za-z0-9][A-Za-z0-9_.-]*(?:[=:][A-Za-z0-9_.:\\/ @+,-]*)?$`)
	// MSI public property: UPPERCASE_NAME=value
	propRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*=[A-Za-z0-9_.:\\/ @+,-]*$`)
	// switches that change what msiexec does rather than how silently it does it
	msiForbidden = map[string]bool{"/i": true, "/x": true, "/a": true, "/j": true, "/p": true, "/f": true,
		"/y": true, "/z": true, "/uninstall": true, "/package": true, "/update": true, "/advertise": true,
		"/qb": false}
	// public properties that load external code or files
	propForbidden = map[string]bool{"TRANSFORMS": true, "PATCH": true, "SETUPEXENAME": true, "MSIINSTANCEGUID": true}
)

// ErrArg is returned for every rejected argument.
var ErrArg = errors.New("installer: argument not allowed")

// ValidateArgs checks extra install arguments. Tokens are passed as an argument
// array (never through a shell) but are still restricted to a conservative
// grammar: a switch (optionally with a value) or an MSI PROPERTY=value pair.
func ValidateArgs(args []string) error {
	if len(args) > MaxArgs {
		return fmt.Errorf("%w: more than %d arguments", ErrArg, MaxArgs)
	}
	for _, a := range args {
		if err := ValidateArg(a); err != nil {
			return err
		}
	}
	return nil
}

// ValidateArg checks one token.
func ValidateArg(a string) error {
	if a == "" || len(a) > MaxArgLen {
		return fmt.Errorf("%w: empty or longer than %d bytes", ErrArg, MaxArgLen)
	}
	for _, r := range a {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\'' || r == '`' || r == '&' || r == '|' || r == '<' || r == '>' ||
			r == '^' || r == ';' || r == '$' || r == '(' || r == ')' || r > 0x7e {
			return fmt.Errorf("%w: unsafe character %q", ErrArg, r)
		}
	}
	if switchRe.MatchString(a) {
		name := strings.ToLower(a)
		if i := strings.IndexAny(name, "=:"); i >= 0 {
			name = name[:i]
		}
		// msiexec accepts -x and --x as well as /x; look them all up as /x.
		name = "/" + strings.TrimLeft(name, "/-")
		if msiForbidden[name] {
			return fmt.Errorf("%w: %s is not a permitted switch", ErrArg, a)
		}
		return nil
	}
	if propRe.MatchString(a) {
		name := a[:strings.IndexByte(a, '=')]
		if propForbidden[name] {
			return fmt.Errorf("%w: property %s is not permitted", ErrArg, name)
		}
		return nil
	}
	return fmt.Errorf("%w: %q is neither a switch nor PROPERTY=value", ErrArg, a)
}

// Spec describes one process-based install.
type Spec struct {
	Type    Type
	Scope   Scope
	Path    string   // installer file (absolute, already verified)
	LogPath string   // where the installer may write its log ('' = none)
	Extra   []string // validated extra tokens
}

// Command returns the executable and argument vector for a process-based
// install. The caller resolves "msiexec.exe" to System32 and runs the vector
// without a shell.
func Command(s Spec) (exe string, args []string, err error) {
	if err := ValidateArgs(s.Extra); err != nil {
		return "", nil, err
	}
	if s.Path == "" {
		return "", nil, errors.New("installer: no installer path")
	}
	switch s.Type {
	case MSI:
		args = []string{"/i", s.Path, "/qn", "/norestart"}
		if s.Scope == User {
			args = append(args, "ALLUSERS=2", "MSIINSTALLPERUSER=1")
		} else {
			args = append(args, "ALLUSERS=1")
		}
		if s.LogPath != "" {
			args = append(args, "/l*v", s.LogPath)
		}
		return "msiexec.exe", append(args, s.Extra...), nil
	case Inno:
		args = []string{"/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"}
		if s.Scope == User {
			args = append(args, "/CURRENTUSER")
		} else {
			args = append(args, "/ALLUSERS")
		}
		if s.LogPath != "" {
			args = append(args, "/LOG="+s.LogPath)
		}
		return s.Path, append(args, s.Extra...), nil
	case NSIS:
		return s.Path, append([]string{"/S"}, s.Extra...), nil
	case Burn:
		args = []string{"/quiet", "/norestart"}
		if s.LogPath != "" {
			args = append(args, "/log", s.LogPath)
		}
		return s.Path, append(args, s.Extra...), nil
	case EXE:
		if len(s.Extra) == 0 {
			return "", nil, errors.New("installer: an EXE installer needs silent switches (from the manifest or an override)")
		}
		return s.Path, append([]string(nil), s.Extra...), nil
	}
	return "", nil, fmt.Errorf("installer: %s is not a process-based type", s.Type)
}
