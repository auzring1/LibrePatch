package installer

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Limits for archive extraction.
const (
	MaxZipFiles = 20000
	MaxZipBytes = 4 << 30
)

// ErrZip is returned for unsafe or oversized archives.
var ErrZip = errors.New("installer: unsafe archive")

// safeRel validates an archive member name: relative, no traversal, no drive
// letters or alternate data streams, no backslash tricks.
func safeRel(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%w: empty name", ErrZip)
	}
	if strings.ContainsAny(name, `\:`) {
		return "", fmt.Errorf("%w: %q", ErrZip, name)
	}
	if strings.Contains(name, "//") {
		return "", fmt.Errorf("%w: empty path segment in %q", ErrZip, name)
	}
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("%w: absolute path %q", ErrZip, name)
	}
	clean := filepath.ToSlash(filepath.Clean(name))
	if clean == ".." || strings.HasPrefix(clean, "../") || clean == "." {
		return "", fmt.Errorf("%w: traversal %q", ErrZip, name)
	}
	for _, seg := range strings.Split(clean, "/") {
		if seg == ".." || seg == "" {
			return "", fmt.Errorf("%w: %q", ErrZip, name)
		}
		// reserved Windows device names would address devices, not files
		base := strings.ToUpper(strings.SplitN(seg, ".", 2)[0])
		if reservedName(base) || strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			// Windows also strips trailing dots and spaces, which makes "a." and "a" the same file.
			return "", fmt.Errorf("%w: reserved or ambiguous name %q", ErrZip, name)
		}
	}
	return clean, nil
}

func reservedName(base string) bool {
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) {
		return base[3] >= '1' && base[3] <= '9'
	}
	return false
}

// ExtractZip extracts src into dst (which must exist and be empty or private).
// It rejects traversal, symlinks, special files, colliding names and archives
// larger than the limits, and never overwrites a file.
func ExtractZip(src, dst string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrZip, err)
	}
	defer r.Close()
	if len(r.File) > MaxZipFiles {
		return fmt.Errorf("%w: too many entries", ErrZip)
	}
	var total uint64
	seen := map[string]bool{}
	for _, f := range r.File {
		rel, err := safeRel(f.Name)
		if err != nil {
			return err
		}
		key := strings.ToLower(rel)
		if seen[key] {
			return fmt.Errorf("%w: duplicate entry %q", ErrZip, f.Name)
		}
		seen[key] = true
		mode := f.Mode()
		if mode&os.ModeSymlink != 0 || (!mode.IsRegular() && !mode.IsDir()) {
			return fmt.Errorf("%w: %q is not a plain file", ErrZip, f.Name)
		}
		total += f.UncompressedSize64
		if total > MaxZipBytes {
			return fmt.Errorf("%w: expands beyond %d bytes", ErrZip, int64(MaxZipBytes))
		}
		target := filepath.Join(dst, filepath.FromSlash(rel))
		if !strings.HasPrefix(target, filepath.Clean(dst)+string(filepath.Separator)) {
			return fmt.Errorf("%w: %q escapes the destination", ErrZip, f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := extractOne(f, target); err != nil {
			return err
		}
	}
	return nil
}

func extractOne(f *zip.File, target string) error {
	in, err := f.Open()
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- target validated by ExtractZip
	if err != nil {
		return err
	}
	// Bound by the declared size: a lying header cannot expand past the total limit.
	n, err := io.Copy(out, io.LimitReader(in, int64(f.UncompressedSize64)+1)) // #nosec G110 G115 -- bounded; the declared size was checked against the total limit
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if uint64(n) != f.UncompressedSize64 { // #nosec G115 -- n is non-negative
		return fmt.Errorf("%w: %q size does not match its header", ErrZip, f.Name)
	}
	return nil
}

// ExpandEnv expands %NAME% references using only allow-listed variables.
func ExpandEnv(p string, user bool, get func(string) string) (string, error) {
	allowed := map[string]bool{"PROGRAMFILES": true, "PROGRAMFILES(X86)": true, "PROGRAMW6432": true,
		"PROGRAMDATA": true, "SYSTEMROOT": true, "WINDIR": true, "COMMONPROGRAMFILES": true}
	if user {
		allowed["LOCALAPPDATA"], allowed["APPDATA"], allowed["USERPROFILE"] = true, true, true
	}
	var b strings.Builder
	for {
		i := strings.IndexByte(p, '%')
		if i < 0 {
			b.WriteString(p)
			break
		}
		j := strings.IndexByte(p[i+1:], '%')
		if j < 0 {
			return "", errors.New("unterminated %variable%")
		}
		name := strings.ToUpper(p[i+1 : i+1+j])
		if !allowed[name] {
			return "", fmt.Errorf("environment variable %%%s%% is not allowed here", name)
		}
		v := get(name)
		if v == "" {
			return "", fmt.Errorf("environment variable %%%s%% is empty", name)
		}
		b.WriteString(p[:i])
		b.WriteString(v)
		p = p[i+1+j+1:]
	}
	return b.String(), nil
}
