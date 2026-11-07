package wingetindex

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

// Name and publisher normalization, modelled on the one winget uses to build the index's norm_names and norm_publishers
// columns. It is checked against the real index: for 99.4% of its 15,516 packages, normalizing the package's own name
// gives one of the normalized names the index lists for it (the rest are quirks like "v6" suffixes and edition words).

var (
	archX64Re = regexp.MustCompile(`(?i)(?:^|[\s\-_(\[])(?:x64|amd64|x86[_-]64|64[\s-]?bits?)(?:$|[\s)\]])`)
	archX86Re = regexp.MustCompile(`(?i)(?:^|[\s\-_(\[])(?:x86|32[\s-]?bits?|win32)(?:$|[\s)\]])`)
	archOther = regexp.MustCompile(`(?i)(?:^|[\s\-_(\[])(?:arm64|aarch64)(?:$|[\s)\]])`)
	parenRe   = regexp.MustCompile(`[\(\[][^\)\]]*[\)\]]`)
	versionRe = regexp.MustCompile(`(?i)\bv?\d+(?:\.\d+)+[a-z]?\b`)
	vWordRe   = regexp.MustCompile(`(?i)\bv\d+\b`)
	verWordRe = regexp.MustCompile(`(?i)\bversion\b`)
	localeRe  = regexp.MustCompile(`(?i)[\s(\[-]*\b[a-z]{2}-[a-z]{2}\b[\s)\]]*`)
	cMarkRe   = regexp.MustCompile(`(?i)\(c\)`)
	legalRe   = regexp.MustCompile(`(?i)\b(?:incorporated|inc|llc|ltd|limited|corporation|corp|company|co|gmbh|ag|sa|bv|plc|pty|pvt|oy|ab|as|kk|srl|spa|lp|llp)\b\.?`)
	marks     = strings.NewReplacer("™", "", "®", "", "©", "")
)

func alnum(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NormalizeName reduces a program's display name to the form the index uses ("Google Chrome" becomes "googlechrome")
// and reports the architecture the name mentions ("X64", "X86" or "").
func NormalizeName(name string) (norm, arch string) {
	n := marks.Replace(name)
	strip := func(re *regexp.Regexp, tag string) {
		for {
			padded := " " + n + " "
			if !re.MatchString(padded) {
				return
			}
			if arch == "" {
				arch = tag
			}
			n = re.ReplaceAllString(padded, " ")
		}
	}
	// Parenthesized qualifiers are dropped, but the architecture inside them ("(x64 edition)") still counts.
	n = parenRe.ReplaceAllStringFunc(n, func(g string) string {
		for _, c := range []struct {
			re  *regexp.Regexp
			tag string
		}{{archX64Re, "X64"}, {archX86Re, "X86"}} {
			if c.re.MatchString(" "+g+" ") && arch == "" {
				arch = c.tag
			}
		}
		return " "
	})
	strip(archX64Re, "X64")
	strip(archX86Re, "X86")
	strip(archOther, "")
	n = versionRe.ReplaceAllString(n, " ")
	n = vWordRe.ReplaceAllString(n, " ")
	n = verWordRe.ReplaceAllString(n, " ")
	n = localeRe.ReplaceAllString(n, " ")
	return alnum(n), arch
}

// NormalizePublisher reduces a publisher ("Google LLC") to the index's form ("google").
func NormalizePublisher(p string) string {
	p = cMarkRe.ReplaceAllString(marks.Replace(p), "")
	return alnum(legalRe.ReplaceAllString(p, ""))
}

// publishersAgree: the same vendor, allowing the index's shorter form ("zoom") of a longer legal name
// ("Zoom Video Communications, Inc.").
func publishersAgree(installed string, listed []string) bool {
	if installed == "" {
		return false
	}
	for _, l := range listed {
		if l == installed {
			return true
		}
		short, long := l, installed
		if len(short) > len(long) {
			short, long = long, short
		}
		if len(short) >= 4 && strings.HasPrefix(long, short) {
			return true
		}
	}
	return false
}

// Installed is what the inventory knows about one installed program.
type Installed struct {
	Name        string
	Publisher   string
	ItemKey     string // the uninstall registry key's name, or the product code
	ProductCode string
	Source      string // reg64, reg32, hku, hku32, msi, appx, portable
}

// Match is a package the index lists for an installed program.
type Match struct {
	ID            string
	Name          string
	LatestVersion string
	VersionKey    []byte
	// By says how it was recognised: "product_code" (the program's product code or uninstall key is the package's) or
	// "name" (the normalized name and the publisher agree).
	By string
}

// Matcher answers "which package is this installed program?".
type Matcher struct {
	pkgs      []Package
	keys      [][]byte
	byProduct map[string][]int
	byName    map[string][]int
	Modified  int64 // unix seconds of the index
}

// NewMatcher indexes a snapshot.
func NewMatcher(s *Snapshot) *Matcher {
	m := &Matcher{pkgs: s.Packages, keys: make([][]byte, len(s.Packages)), byProduct: map[string][]int{}, byName: map[string][]int{}}
	if !s.Modified.IsZero() {
		m.Modified = s.Modified.Unix()
	}
	for i, p := range s.Packages {
		m.keys[i] = vercmp.Key(p.LatestVersion)
		for _, k := range p.ProductCodes {
			m.byProduct[k] = append(m.byProduct[k], i)
		}
		for _, k := range p.NormNames {
			m.byName[k] = append(m.byName[k], i)
		}
	}
	return m
}

// Len is the number of packages.
func (m *Matcher) Len() int { return len(m.pkgs) }

// Package returns a package by its identifier.
func (m *Matcher) Package(id string) (Package, bool) {
	for _, p := range m.pkgs {
		if strings.EqualFold(p.ID, id) {
			return p, true
		}
	}
	return Package{}, false
}

// Search finds packages by a fragment of the identifier, name or moniker (case-insensitive), best first.
func (m *Matcher) Search(q string, limit int) []Package {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" || limit <= 0 {
		return nil
	}
	type scored struct {
		i     int
		score int
	}
	var hits []scored
	for i, p := range m.pkgs {
		id, name, mon := strings.ToLower(p.ID), strings.ToLower(p.Name), strings.ToLower(p.Moniker)
		s := 0
		switch {
		case id == q || name == q || mon == q:
			s = 100
		case strings.HasPrefix(name, q) || strings.HasPrefix(id, q):
			s = 60
		case strings.Contains(name, q) || strings.Contains(id, q) || strings.Contains(mon, q):
			s = 30
		}
		if s > 0 {
			hits = append(hits, scored{i, s*1000 - len(p.ID)})
		}
	}
	// small selection sort of the best `limit` (limit is tiny)
	var out []Package
	for len(out) < limit && len(hits) > 0 {
		best := 0
		for j := range hits {
			if hits[j].score > hits[best].score {
				best = j
			}
		}
		out = append(out, m.pkgs[hits[best].i])
		hits = append(hits[:best], hits[best+1:]...)
	}
	return out
}

func (m *Matcher) result(i int, by string) Match {
	p := m.pkgs[i]
	return Match{ID: p.ID, Name: p.Name, LatestVersion: p.LatestVersion, VersionKey: m.keys[i], By: by}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func uniq(in []int) []int {
	seen := map[int]bool{}
	out := in[:0:0]
	for _, i := range in {
		if !seen[i] {
			seen[i] = true
			out = append(out, i)
		}
	}
	return out
}

// Reason says why an installed program was not recognised, so the console can tell the administrator instead of leaving
// "no update" unexplained.
type Reason struct {
	// Code is one of: store_app, portable, no_publisher (the name is in the index but the program lists no publisher),
	// publisher_differs (the name is in the index under another publisher), ambiguous (several packages fit equally
	// well) or unknown (nothing in the index fits).
	Code string
	// IDs are the packages involved (at most maxReasonIDs).
	IDs []string
}

const maxReasonIDs = 4

func (m *Matcher) ids(idx []int) []string {
	var out []string
	for _, i := range idx {
		if len(out) == maxReasonIDs {
			break
		}
		out = append(out, m.pkgs[i].ID)
	}
	return out
}

// preferOne narrows several equally good candidates to the one the caller prefers (the package the administrator
// already imported); it changes nothing unless exactly one of them is preferred.
func (m *Matcher) preferOne(pool []int, prefer func(id string) bool) []int {
	if prefer == nil || len(pool) < 2 {
		return pool
	}
	var p []int
	for _, i := range pool {
		if prefer(m.pkgs[i].ID) {
			p = append(p, i)
		}
	}
	if len(p) == 1 {
		return p
	}
	return pool
}

// baseOf narrows several candidates to the base package when the rest are only other installer flavours of it: the same
// publisher, the same newest version and an identifier that extends the base one with a suffix (Google.Chrome and
// Google.Chrome.EXE are the same browser, delivered as an MSI and as an executable). Winget lists such flavours as separate
// packages, so without this a program that fits both is never recognised and an old Chrome shows no update. Packages that
// differ in version (Firefox and Firefox ESR) are left alone: they are different programs.
func (m *Matcher) baseOf(pool []int) []int {
	if len(pool) < 2 {
		return pool
	}
	for _, b := range pool {
		base := m.pkgs[b]
		all := true
		for _, i := range pool {
			if i == b {
				continue
			}
			o := m.pkgs[i]
			if !strings.HasPrefix(strings.ToLower(o.ID), strings.ToLower(base.ID)+".") || o.LatestVersion != base.LatestVersion || !samePublishers(base.NormPublishers, o.NormPublishers) {
				all = false
				break
			}
		}
		if all {
			return []int{b}
		}
	}
	return pool
}

func samePublishers(a, b []string) bool {
	for _, x := range a {
		if contains(b, x) {
			return true
		}
	}
	return false
}

// Find recognises an installed program. It is deliberately cautious: a program that matches several packages equally
// well, or only by name without a matching publisher, is not matched (a wrong match could install the wrong software).
func (m *Matcher) Find(in Installed) (Match, bool) {
	mt, why := m.Recognise(in, nil)
	return mt, why == nil
}

// Recognise is Find with two additions: it says why a program was not recognised, and when several packages fit
// equally well it takes the one prefer reports as already known (for example, imported into the catalog). prefer may
// be nil.
func (m *Matcher) Recognise(in Installed, prefer func(id string) bool) (Match, *Reason) {
	switch in.Source {
	case "appx":
		return Match{}, &Reason{Code: "store_app"}
	case "portable":
		return Match{}, &Reason{Code: "portable"}
	}
	norm, arch := NormalizeName(in.Name)
	pub := NormalizePublisher(in.Publisher)
	var names []string
	if norm != "" {
		names = append(names, norm)
		for _, a := range []string{arch, map[string]string{"reg64": "X64", "reg32": "X86", "hku32": "X86"}[in.Source]} {
			if a != "" {
				names = append(names, norm+"("+a+")")
			}
		}
	}
	nameOK := func(i int) bool {
		for _, n := range names {
			if contains(m.pkgs[i].NormNames, n) {
				return true
			}
		}
		return false
	}

	// 1. The product code or the uninstall key's name is the strongest evidence.
	var byCode []int
	for _, k := range []string{strings.ToLower(strings.TrimSpace(in.ProductCode)), strings.ToLower(strings.TrimSpace(in.ItemKey))} {
		if k != "" {
			byCode = append(byCode, m.byProduct[k]...)
		}
	}
	byCode = uniq(byCode)
	switch {
	case len(byCode) == 1:
		return m.result(byCode[0], "product_code"), nil
	case len(byCode) > 1: // e.g. Firefox and Firefox ESR share a key: the name decides
		var pool []int
		for _, i := range byCode {
			if nameOK(i) {
				pool = append(pool, i)
			}
		}
		if len(pool) == 0 { // the name says nothing: the publisher must at least agree
			for _, i := range byCode {
				if publishersAgree(pub, m.pkgs[i].NormPublishers) {
					pool = append(pool, i)
				}
			}
		}
		if pool = m.baseOf(m.preferOne(pool, prefer)); len(pool) == 1 {
			return m.result(pool[0], "product_code"), nil
		}
		return Match{}, &Reason{Code: "ambiguous", IDs: m.ids(byCode)}
	}

	// 2. Name and publisher.
	var named, cand []int
	for _, n := range names {
		for _, i := range m.byName[n] {
			named = append(named, i)
			if publishersAgree(pub, m.pkgs[i].NormPublishers) {
				cand = append(cand, i)
			}
		}
	}
	named, cand = uniq(named), uniq(cand)
	if pub == "" {
		if len(named) > 0 {
			return Match{}, &Reason{Code: "no_publisher", IDs: m.ids(named)}
		}
		return Match{}, &Reason{Code: "unknown"}
	}
	if len(cand) > 1 { // prefer the one that also lists the exact architecture-qualified name
		var exact []int
		for _, i := range cand {
			if len(names) > 1 && contains(m.pkgs[i].NormNames, names[len(names)-1]) {
				exact = append(exact, i)
			}
		}
		if len(exact) == 1 {
			cand = exact
		}
		cand = m.baseOf(m.preferOne(cand, prefer))
	}
	switch {
	case len(cand) == 1:
		return m.result(cand[0], "name"), nil
	case len(cand) > 1:
		return Match{}, &Reason{Code: "ambiguous", IDs: m.ids(cand)}
	case len(named) > 0:
		return Match{}, &Reason{Code: "publisher_differs", IDs: m.ids(named)}
	}
	return Match{}, &Reason{Code: "unknown"}
}

// Newer reports whether the package's latest version is newer than the installed version key.
func (mt Match) Newer(installedKey []byte) bool {
	return installedKey != nil && len(mt.VersionKey) > 0 && string(installedKey) < string(mt.VersionKey)
}

func vercmpKey(v string) ([]byte, bool) { k := vercmp.Key(v); return k, k != nil }
