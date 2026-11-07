package sbom

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"os"
	"regexp"
	"sort"
	"strings"
)

// NPMOptions control FromNPMLock.
type NPMOptions struct {
	// Version is the release version of the web bundle.
	Version string
	// Epoch is the document timestamp in unix seconds (use SOURCE_DATE_EPOCH).
	Epoch int64
}

type lockFile struct {
	Name            string             `json:"name"`
	Version         string             `json:"version"`
	LockfileVersion int                `json:"lockfileVersion"`
	Packages        map[string]lockPkg `json:"packages"`
}

type lockPkg struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
	Dev                  bool              `json:"dev"`
	DevOptional          bool              `json:"devOptional"`
	Optional             bool              `json:"optional"`
	Link                 bool              `json:"link"`
	License              json.RawMessage   `json:"license"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// FromNPMLock builds the SBOM for the production closure of a package-lock.json (lockfile v2 or v3).
func FromNPMLock(lockPath string, o NPMOptions) ([]byte, error) {
	data, err := os.ReadFile(lockPath) // #nosec G304 -- operator-chosen path
	if err != nil {
		return nil, err
	}
	return fromNPMLock(data, o)
}

func fromNPMLock(data []byte, o NPMOptions) ([]byte, error) {
	if o.Version == "" {
		return nil, errors.New("a release version is required")
	}
	var lf lockFile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("package-lock.json: %w", err)
	}
	if lf.LockfileVersion < 2 || len(lf.Packages) == 0 {
		return nil, errors.New("package-lock.json: lockfileVersion 2 or 3 with a \"packages\" map is required")
	}
	rootPkg, ok := lf.Packages[""]
	if !ok {
		return nil, errors.New("package-lock.json: no root package entry")
	}
	rootName := rootPkg.Name
	if rootName == "" {
		rootName = lf.Name
	}
	if rootName == "" {
		rootName = "web"
	}
	rootRef := "pkg:npm/" + npmPurlName(rootName) + "@" + purlEscape(o.Version)
	root := Component{
		Type: "application", BOMRef: rootRef, Name: rootName, Version: o.Version, PURL: rootRef,
		Description: brand.Name + " web console production bundle (Vite build embedded in the server binary)",
		Licenses:    npmLicense(rootPkg.License),
		Properties: []Property{
			{Name: "librepatch:scope", Value: "production dependencies of the lockfile (dev dependencies, which are not shipped, are excluded)"},
		},
	}
	b := newBOM(o.Epoch, root)

	// Keep the production closure: everything not marked dev (npm marks devOptional for packages
	// reachable only through dev dependencies and optional ones).
	keep := map[string]bool{}
	for p, pkg := range lf.Packages {
		if p == "" || pkg.Dev || pkg.DevOptional || pkg.Link || pkg.Version == "" {
			continue
		}
		keep[p] = true
	}
	refOf := map[string]string{}
	for p := range keep {
		pkg := lf.Packages[p]
		name := pkg.Name
		if name == "" {
			name = nameFromPath(p)
		}
		ref := "pkg:npm/" + npmPurlName(name) + "@" + purlEscape(pkg.Version)
		refOf[p] = ref
		c := Component{
			Type: "library", BOMRef: ref, Name: name, Version: pkg.Version, Scope: "required", PURL: ref,
			Licenses: npmLicense(pkg.License),
		}
		if grp, short, ok := splitScope(name); ok {
			c.Group, c.Name = grp, short
		}
		if h, ok := npmIntegrity(pkg.Integrity); ok {
			c.Hashes = []Hash{h}
		}
		if pkg.Resolved != "" {
			c.ExternalRefs = []ExternalRef{{Type: "distribution", URL: pkg.Resolved}}
		}
		if pkg.Optional {
			c.Properties = append(c.Properties, Property{Name: "librepatch:npm-optional", Value: "true"})
		}
		b.Components = append(b.Components, c)
	}

	// Edges: resolve each declared dependency the way node does (nearest node_modules upwards).
	edges := map[string]map[string]bool{}
	addEdges := func(from string, deps ...map[string]string) {
		set := edges[from]
		if set == nil {
			set = map[string]bool{}
			edges[from] = set
		}
		for _, m := range deps {
			for name := range m {
				if to, ok := resolveNPM(lf.Packages, keep, from, name); ok {
					set[refOf[to]] = true
				}
			}
		}
	}
	for p := range keep {
		pkg := lf.Packages[p]
		addEdges(p, pkg.Dependencies, pkg.OptionalDependencies, pkg.PeerDependencies)
	}
	b.Dependencies = append(b.Dependencies, Dependency{Ref: rootRef, DependsOn: resolveRoot(lf.Packages, keep, refOf, rootPkg.Dependencies)})
	for p := range keep {
		d := Dependency{Ref: refOf[p]}
		for r := range edges[p] {
			d.DependsOn = append(d.DependsOn, r)
		}
		b.Dependencies = append(b.Dependencies, d)
	}
	return b.finish()
}

func resolveRoot(pk map[string]lockPkg, keep map[string]bool, refOf map[string]string, deps map[string]string) []string {
	set := map[string]bool{}
	for name := range deps {
		if to, ok := resolveNPM(pk, keep, "", name); ok {
			set[refOf[to]] = true
		}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// resolveNPM finds the lockfile path that `from` gets when it requires `name`.
func resolveNPM(pk map[string]lockPkg, keep map[string]bool, from, name string) (string, bool) {
	dir := from
	for {
		cand := "node_modules/" + name
		if dir != "" {
			cand = dir + "/node_modules/" + name
		}
		if _, ok := pk[cand]; ok {
			return cand, keep[cand]
		}
		if dir == "" {
			return "", false
		}
		i := strings.LastIndex(dir, "node_modules/")
		if i < 0 {
			dir = ""
			continue
		}
		dir = strings.TrimSuffix(dir[:i], "/")
	}
}

func nameFromPath(p string) string {
	i := strings.LastIndex(p, "node_modules/")
	if i < 0 {
		return p
	}
	return p[i+len("node_modules/"):]
}

func splitScope(name string) (group, short string, ok bool) {
	if !strings.HasPrefix(name, "@") {
		return "", name, false
	}
	g, s, found := strings.Cut(name, "/")
	if !found {
		return "", name, false
	}
	return g, s, true
}

// npmPurlName encodes "@scope/name" as "%40scope/name".
func npmPurlName(name string) string {
	if g, s, ok := splitScope(name); ok {
		return purlEscape(g) + "/" + purlEscape(s)
	}
	return purlEscape(name)
}

// npmIntegrity converts "sha512-<base64>" (or sha384/sha256/sha1) to a CycloneDX hash.
func npmIntegrity(s string) (Hash, bool) {
	best := Hash{}
	rank := map[string]int{"sha1": 1, "sha256": 2, "sha384": 3, "sha512": 4}
	alg := map[string]string{"sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}
	size := map[string]int{"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}
	bestRank := 0
	for _, f := range strings.Fields(s) {
		a, v, ok := strings.Cut(f, "-")
		if !ok || rank[a] <= bestRank {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(raw) != size[a] {
			continue
		}
		best = Hash{Alg: alg[a], Content: hex.EncodeToString(raw)}
		bestRank = rank[a]
	}
	return best, bestRank > 0
}

// spdxIDs are the identifiers this project's allow-list can meet; anything else is written as a name or expression.
var spdxIDs = map[string]bool{
	"MIT": true, "ISC": true, "Apache-2.0": true, "BSD-2-Clause": true, "BSD-3-Clause": true,
	"0BSD": true, "MPL-2.0": true, "CC0-1.0": true, "Unlicense": true, "BlueOak-1.0.0": true, "Python-2.0": true,
	"CC-BY-4.0": true, "CC-BY-3.0": true, "Zlib": true, "OFL-1.1": true, // OFL-1.1: the bundled Inter font only (see sbom_test.go fontException)
}

var exprRE = regexp.MustCompile(`[\s()]`)

func npmLicense(raw json.RawMessage) []LicenseItem {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || strings.TrimSpace(s) == "" {
		return nil
	}
	s = strings.TrimSpace(s)
	switch {
	case spdxIDs[s]:
		return []LicenseItem{{License: &License{ID: s}}}
	case exprRE.MatchString(s):
		return []LicenseItem{{Expression: s}}
	default:
		return []LicenseItem{{License: &License{Name: s}}}
	}
}
