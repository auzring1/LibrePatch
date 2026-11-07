package sbom

import (
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"runtime/debug"
	"strings"
)

// GoOptions control FromGoBinary.
type GoOptions struct {
	// Version is the release version of the described product (the Go linker only knows "(devel)").
	Version string
	// Name overrides the component name (default: the binary's file name).
	Name string
	// Epoch is the document timestamp in unix seconds (use SOURCE_DATE_EPOCH).
	Epoch int64
}

// FromGoBinary returns the CycloneDX document for a Go binary (any GOOS/GOARCH).
func FromGoBinary(path string, o GoOptions) ([]byte, error) {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading Go build info from %s: %w", path, err)
	}
	return fromBuildInfo(bi, filepath.Base(path), o)
}

func fromBuildInfo(bi *debug.BuildInfo, base string, o GoOptions) ([]byte, error) {
	if o.Version == "" {
		return nil, errors.New("a release version is required")
	}
	name := o.Name
	if name == "" {
		name = strings.TrimSuffix(base, ".exe")
	}
	mainPath := bi.Main.Path
	if mainPath == "" {
		mainPath = bi.Path
	}
	rootRef := "pkg:golang/" + purlPath(mainPath) + "@" + purlEscape(o.Version) + "#" + purlEscape(name)
	root := Component{
		Type: "application", BOMRef: rootRef, Name: name, Version: o.Version,
		PURL: "pkg:golang/" + purlPath(mainPath) + "@" + purlEscape(o.Version),
		Properties: []Property{
			{Name: "librepatch:go-main-package", Value: bi.Path},
			{Name: "librepatch:go-version", Value: bi.GoVersion},
			{Name: "librepatch:hash-kind", Value: "component hashes of Go modules are the go.sum h1 dirhash decoded to hex: SHA-256 over the sorted list of the module files' SHA-256 digests, not the digest of a zip archive"},
			{Name: "librepatch:dependency-graph", Value: "flat: every module linked into the binary is a direct dependency of the product (the module-level graph is not recorded)"},
		},
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "GOOS", "GOARCH", "CGO_ENABLED", "-trimpath", "GOAMD64", "GOARM64", "-tags":
			root.Properties = append(root.Properties, Property{Name: "librepatch:go-build-" + strings.TrimPrefix(s.Key, "-"), Value: s.Value})
		}
	}
	b := newBOM(o.Epoch, root)
	// The Metadata copy is the one consumers read; keep the bom-ref out of components[] (it is the subject).
	deps := []string{}

	std := strings.TrimPrefix(bi.GoVersion, "go")
	stdRef := "pkg:golang/stdlib@" + purlEscape(std)
	b.Components = append(b.Components, Component{
		Type: "library", BOMRef: stdRef, Name: "stdlib", Version: std, Scope: "required", PURL: stdRef,
		Description: "Go standard library and runtime, compiled in by the toolchain " + bi.GoVersion,
	})
	deps = append(deps, stdRef)

	for _, m := range bi.Deps {
		eff := m
		var props []Property
		if m.Replace != nil {
			eff = m.Replace
			props = append(props, Property{Name: "librepatch:go-replaces", Value: m.Path + "@" + m.Version})
		}
		ref := "pkg:golang/" + purlPath(eff.Path) + "@" + purlEscape(eff.Version)
		c := Component{
			Type: "library", BOMRef: ref, Name: eff.Path, Version: eff.Version, Scope: "required", PURL: ref,
			Properties: props,
		}
		if h, ok := goSumHash(eff.Sum); ok {
			c.Hashes = []Hash{{Alg: "SHA-256", Content: h}}
			c.Properties = append(c.Properties, Property{Name: "librepatch:go-sum", Value: eff.Sum})
		}
		b.Components = append(b.Components, c)
		deps = append(deps, ref)
	}
	b.Dependencies = append(b.Dependencies, Dependency{Ref: rootRef, DependsOn: deps})
	for _, c := range b.Components {
		b.Dependencies = append(b.Dependencies, Dependency{Ref: c.BOMRef})
	}
	return b.finish()
}

// goSumHash converts a go.sum "h1:<base64>" value into the hex of the 32-byte SHA-256 it encodes.
func goSumHash(sum string) (string, bool) {
	rest, ok := strings.CutPrefix(sum, "h1:")
	if !ok {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(rest)
	if err != nil || len(raw) != 32 {
		return "", false
	}
	return hex.EncodeToString(raw), true
}

// purlEscape percent-encodes everything except the purl-safe characters.
func purlEscape(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_', c == '~':
			sb.WriteByte(c)
		default:
			fmt.Fprintf(&sb, "%%%02X", c)
		}
	}
	return sb.String()
}

// purlPath escapes each segment of a slash-separated module path and keeps the slashes.
func purlPath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = purlEscape(s)
	}
	return strings.Join(segs, "/")
}
