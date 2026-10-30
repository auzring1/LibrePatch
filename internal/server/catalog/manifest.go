// Package catalog turns winget manifests (and administrator uploads) into
// installable, validated package metadata. winget is a metadata source only:
// nothing here executes winget (docs/research/winget-and-user-context.md).
package catalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/auzring1/librepatch/internal/shared/installer"
	"github.com/auzring1/librepatch/internal/shared/text"
)

// MaxManifestBytes bounds each manifest file.
const MaxManifestBytes = 1 << 20

// ErrManifest wraps manifest problems.
var ErrManifest = errors.New("catalog: invalid manifest")

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrManifest, fmt.Sprintf(format, a...))
}

type switches struct {
	Silent             string `yaml:"Silent"`
	SilentWithProgress string `yaml:"SilentWithProgress"`
	Custom             string `yaml:"Custom"`
}

type appsEntry struct {
	DisplayName    string `yaml:"DisplayName"`
	Publisher      string `yaml:"Publisher"`
	DisplayVersion string `yaml:"DisplayVersion"`
	ProductCode    string `yaml:"ProductCode"`
	UpgradeCode    string `yaml:"UpgradeCode"`
}

type nestedFile struct {
	RelativeFilePath string `yaml:"RelativeFilePath"`
}

type installerFields struct {
	Architecture          string       `yaml:"Architecture"`
	InstallerType         string       `yaml:"InstallerType"`
	NestedInstallerType   string       `yaml:"NestedInstallerType"`
	NestedInstallerFiles  []nestedFile `yaml:"NestedInstallerFiles"`
	Scope                 string       `yaml:"Scope"`
	InstallerURL          string       `yaml:"InstallerUrl"`
	InstallerSha256       string       `yaml:"InstallerSha256"`
	ProductCode           string       `yaml:"ProductCode"`
	MinimumOSVersion      string       `yaml:"MinimumOSVersion"`
	InstallerSwitches     switches     `yaml:"InstallerSwitches"`
	InstallerSuccessCodes []int        `yaml:"InstallerSuccessCodes"`
	ExpectedReturnCodes   []struct {
		InstallerReturnCode int    `yaml:"InstallerReturnCode"`
		ReturnResponse      string `yaml:"ReturnResponse"`
	} `yaml:"ExpectedReturnCodes"`
	AppsAndFeaturesEntries []appsEntry `yaml:"AppsAndFeaturesEntries"`
	Dependencies           struct {
		PackageDependencies []struct {
			PackageIdentifier string `yaml:"PackageIdentifier"`
		} `yaml:"PackageDependencies"`
	} `yaml:"Dependencies"`
	ElevationRequirement string `yaml:"ElevationRequirement"`
	// PackageFamilyName names an MSIX/AppX package ("Microsoft.WindowsTerminal_8wekyb3d8bbwe").
	PackageFamilyName string `yaml:"PackageFamilyName"`
}

type rawManifest struct {
	PackageIdentifier string `yaml:"PackageIdentifier"`
	PackageVersion    string `yaml:"PackageVersion"`
	DefaultLocale     string `yaml:"DefaultLocale"`
	ManifestType      string `yaml:"ManifestType"`

	installerFields `yaml:",inline"`
	Installers      []installerFields `yaml:"Installers"`

	PackageName      string `yaml:"PackageName"`
	Publisher        string `yaml:"Publisher"`
	PackageURL       string `yaml:"PackageUrl"`
	License          string `yaml:"License"`
	ShortDescription string `yaml:"ShortDescription"`
}

// Detection mirrors a detection rule stored in catalog_installers.detection.
type Detection struct {
	Kind      string `json:"kind"` // msi | registry | file | appx
	Key       string `json:"key"`
	ValueName string `json:"value_name,omitempty"`
	Version   string `json:"version,omitempty"`
	Cmp       string `json:"cmp,omitempty"` // "" | eq | ge
}

// Installer is one normalized installer of a package version.
type Installer struct {
	Arch          string // x64 | x86 | arm64 | neutral
	Scope         string // machine | user | any
	Type          string // installer.Type name
	NestedType    string
	NestedPath    string
	URL           string
	SHA256        []byte
	FileName      string
	ProductCode   string
	UpgradeCode   string
	Silent        []string // switches for generic EXE installers
	Custom        []string // extra manifest switches
	SuccessCodes  []int
	ExpectedCodes []int
	MinOS         string
	Detection     []Detection
	Dependencies  []string
	// Unsupported explains why this installer cannot be deployed by this version ('' = deployable).
	Unsupported string
}

// Parsed is a normalized package version.
type Parsed struct {
	Identifier string
	Version    string
	Name       string
	Publisher  string
	Homepage   string
	License    string
	Summary    string
	Installers []Installer
	// ManifestSHA256 covers the manifest text exactly as imported.
	ManifestSHA256 []byte
}

var (
	idRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+\-]{0,199}$`)
	shaRe  = regexp.MustCompile(`^[0-9A-Fa-f]{64}$`)
	guidRe = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)
	// registry key names we may generate detection rules for
	keyNameRe = regexp.MustCompile(`^[A-Za-z0-9 _.+()\-{}]{1,200}$`)
)

// ValidIdentifier checks a winget PackageIdentifier.
func ValidIdentifier(s string) bool { return idRe.MatchString(s) && strings.Contains(s, ".") }

func decode(b []byte) (*rawManifest, error) {
	if len(b) > MaxManifestBytes {
		return nil, bad("manifest file larger than %d bytes", MaxManifestBytes)
	}
	var m rawManifest
	dec := yaml.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&m); err != nil {
		return nil, bad("YAML: %v", err)
	}
	return &m, nil
}

// ParseFiles parses a winget manifest set: either one singleton file, or the
// version + installer + default-locale files of a multi-file manifest. files
// maps any name to its content; the manifest types inside decide the roles.
func ParseFiles(files [][]byte) (*Parsed, error) {
	if len(files) == 0 || len(files) > 8 {
		return nil, bad("expected 1 to 8 manifest files")
	}
	h := sha256.New()
	var version, installerM, locale *rawManifest
	for _, f := range files {
		m, err := decode(f)
		if err != nil {
			return nil, err
		}
		h.Write(f)
		switch strings.ToLower(m.ManifestType) {
		case "singleton":
			version, installerM, locale = m, m, m
		case "version":
			version = m
		case "installer":
			installerM = m
		case "defaultlocale":
			locale = m
		}
	}
	if version == nil || installerM == nil {
		return nil, bad("version and installer manifests are required")
	}
	p := &Parsed{Identifier: version.PackageIdentifier, Version: version.PackageVersion, ManifestSHA256: h.Sum(nil)}
	if !ValidIdentifier(p.Identifier) {
		return nil, bad("PackageIdentifier %q is not valid", p.Identifier)
	}
	if installerM.PackageIdentifier != p.Identifier || (locale != nil && locale.PackageIdentifier != p.Identifier) {
		return nil, bad("manifest files disagree about the PackageIdentifier")
	}
	if p.Version == "" || len(p.Version) > 128 {
		return nil, bad("PackageVersion missing or too long")
	}
	if locale != nil {
		p.Name, p.Publisher, p.Homepage, p.License, p.Summary = locale.PackageName, locale.Publisher, locale.PackageURL, locale.License, locale.ShortDescription
	}
	if p.Name == "" {
		p.Name = p.Identifier
	}
	p.Name, p.Publisher, p.Summary = clip(p.Name, 200), clip(p.Publisher, 200), clip(p.Summary, 1000)
	p.Homepage, p.License = httpsOrEmpty(p.Homepage), clip(p.License, 200)
	if len(installerM.Installers) == 0 {
		return nil, bad("no installers")
	}
	for _, raw := range installerM.Installers {
		in, err := normalize(p, merge(installerM.installerFields, raw))
		if err != nil {
			return nil, err
		}
		p.Installers = append(p.Installers, in)
	}
	return p, nil
}

func clip(s string, n int) string {
	return text.Truncate(strings.ToValidUTF8(strings.TrimSpace(s), ""), n)
}

func httpsOrEmpty(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || len(s) > 500 {
		return ""
	}
	return s
}

// merge applies root-level installer defaults to one installer entry.
func merge(def, in installerFields) installerFields {
	pick := func(a, b string) string {
		if a != "" {
			return a
		}
		return b
	}
	out := in
	out.Architecture = pick(in.Architecture, def.Architecture)
	out.InstallerType = pick(in.InstallerType, def.InstallerType)
	out.NestedInstallerType = pick(in.NestedInstallerType, def.NestedInstallerType)
	out.Scope = pick(in.Scope, def.Scope)
	out.ProductCode = pick(in.ProductCode, def.ProductCode)
	out.MinimumOSVersion = pick(in.MinimumOSVersion, def.MinimumOSVersion)
	out.ElevationRequirement = pick(in.ElevationRequirement, def.ElevationRequirement)
	out.PackageFamilyName = pick(in.PackageFamilyName, def.PackageFamilyName)
	out.InstallerSwitches.Silent = pick(in.InstallerSwitches.Silent, def.InstallerSwitches.Silent)
	out.InstallerSwitches.SilentWithProgress = pick(in.InstallerSwitches.SilentWithProgress, def.InstallerSwitches.SilentWithProgress)
	out.InstallerSwitches.Custom = pick(in.InstallerSwitches.Custom, def.InstallerSwitches.Custom)
	if len(out.NestedInstallerFiles) == 0 {
		out.NestedInstallerFiles = def.NestedInstallerFiles
	}
	if len(out.InstallerSuccessCodes) == 0 {
		out.InstallerSuccessCodes = def.InstallerSuccessCodes
	}
	if len(out.ExpectedReturnCodes) == 0 {
		out.ExpectedReturnCodes = def.ExpectedReturnCodes
	}
	if len(out.AppsAndFeaturesEntries) == 0 {
		out.AppsAndFeaturesEntries = def.AppsAndFeaturesEntries
	}
	if len(out.Dependencies.PackageDependencies) == 0 {
		out.Dependencies = def.Dependencies
	}
	return out
}

func mapType(s string) (installer.Type, bool) {
	switch strings.ToLower(s) {
	case "msi", "wix":
		return installer.MSI, true
	case "msix", "appx":
		return installer.MSIX, true
	case "inno":
		return installer.Inno, true
	case "nullsoft", "nsis":
		return installer.NSIS, true
	case "burn":
		return installer.Burn, true
	case "exe":
		return installer.EXE, true
	case "zip":
		return installer.Zip, true
	case "portable":
		return installer.Portable, true
	}
	return "", false
}

func mapArch(s string) string {
	switch strings.ToLower(s) {
	case "x64":
		return "x64"
	case "x86":
		return "x86"
	case "arm64":
		return "arm64"
	case "neutral", "":
		return "neutral"
	}
	return "" // arm (32-bit) and unknown: not deployable
}

func tokens(s string) []string { return strings.Fields(strings.ReplaceAll(s, " ", " ")) }

func normalize(p *Parsed, r installerFields) (Installer, error) {
	in := Installer{Scope: "any", MinOS: clip(r.MinimumOSVersion, 40)}
	in.Arch = mapArch(r.Architecture)
	t, ok := mapType(r.InstallerType)
	if !ok {
		in.Type = "exe"
		in.Unsupported = fmt.Sprintf("unknown installer type %q", r.InstallerType)
	} else {
		in.Type = string(t)
	}
	if in.Arch == "" {
		in.Arch = "neutral"
		in.Unsupported = "architecture " + r.Architecture + " is not supported (x64, x86 and arm64 only)"
	}
	switch strings.ToLower(r.Scope) {
	case "machine":
		in.Scope = "machine"
	case "user":
		in.Scope = "user"
	}
	u, err := url.Parse(r.InstallerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(r.InstallerURL) > 2048 {
		return in, bad("installer URL %q is not an https URL", r.InstallerURL)
	}
	in.URL = r.InstallerURL
	if !shaRe.MatchString(r.InstallerSha256) {
		return in, bad("InstallerSha256 is missing or malformed for %s", r.InstallerURL)
	}
	in.SHA256, _ = hex.DecodeString(r.InstallerSha256)
	in.FileName = fileNameFromURL(u, in.Type)

	if t == installer.MSIX {
		// MSIX/AppX packages are installed for the whole computer by the agent (D151), whatever scope the manifest names.
		in.Scope = "machine"
		if _, ok := installer.AppxNameFromFamily(r.PackageFamilyName); !ok && in.Unsupported == "" {
			in.Unsupported = "the manifest has no usable PackageFamilyName, which the agent needs to find the MSIX package"
		}
		if !installer.IsMSIXFileName(in.FileName) {
			ext := ".msix"
			if strings.Contains(strings.ToLower(u.Path), "bundle") {
				ext = ".msixbundle"
			}
			in.FileName = strings.TrimRight(in.FileName, ". ") + ext
		}
	}
	if t == installer.Zip {
		nt, ok := mapType(r.NestedInstallerType)
		if !ok || !nt.RunsProcess() && nt != installer.Portable {
			in.Unsupported = "ZIP packages need a process-based nested installer"
		} else if len(r.NestedInstallerFiles) == 0 {
			in.Unsupported = "ZIP package without NestedInstallerFiles"
		} else {
			in.NestedType = string(nt)
			in.NestedPath = strings.ReplaceAll(r.NestedInstallerFiles[0].RelativeFilePath, `\`, "/")
		}
		if nt == installer.Portable {
			in.Unsupported = "ZIP-packaged portable apps are not supported in this version"
		}
	}
	in.ProductCode = strings.TrimSpace(r.ProductCode)
	for _, e := range r.AppsAndFeaturesEntries {
		if in.ProductCode == "" {
			in.ProductCode = strings.TrimSpace(e.ProductCode)
		}
		if in.UpgradeCode == "" {
			in.UpgradeCode = strings.TrimSpace(e.UpgradeCode)
		}
	}
	// Silent switches matter for generic EXE installers; the other types get the
	// agent's own per-type silent switches. Custom switches are appended for all.
	eff := t
	if t == installer.Zip && in.NestedType != "" {
		eff = installer.Type(in.NestedType)
	}
	if eff == installer.EXE {
		s := r.InstallerSwitches.Silent
		if s == "" {
			s = r.InstallerSwitches.SilentWithProgress
		}
		in.Silent = tokens(s)
		if len(in.Silent) == 0 && in.Unsupported == "" {
			in.Unsupported = "no silent install switch in the manifest; add one as a package override"
		}
	}
	in.Custom = tokens(r.InstallerSwitches.Custom)
	if err := installer.ValidateArgs(append(append([]string{}, in.Silent...), in.Custom...)); err != nil && in.Unsupported == "" {
		in.Unsupported = "the manifest's switches are not allowed (" + err.Error() + "); override them"
	}
	in.SuccessCodes = r.InstallerSuccessCodes
	for _, e := range r.ExpectedReturnCodes {
		if strings.EqualFold(e.ReturnResponse, "installInProgress") || strings.EqualFold(e.ReturnResponse, "downloadInstallerFailed") {
			continue
		}
		if strings.EqualFold(e.ReturnResponse, "alreadyInstalled") || strings.EqualFold(e.ReturnResponse, "upgradeVersionNotNewer") {
			in.ExpectedCodes = append(in.ExpectedCodes, e.InstallerReturnCode)
		}
	}
	for _, d := range r.Dependencies.PackageDependencies {
		if ValidIdentifier(d.PackageIdentifier) {
			in.Dependencies = append(in.Dependencies, d.PackageIdentifier)
		}
	}
	in.Detection = detectionFor(p, in, r)
	return in, nil
}

func fileNameFromURL(u *url.URL, typ string) string {
	name := path.Base(u.Path)
	name = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-+() ", r) {
			return r
		}
		return '_'
	}, name)
	name = strings.TrimLeft(name, ".-_ +()")
	if len(name) > 100 {
		name = name[len(name)-100:]
	}
	ext := map[string]string{"msi": ".msi", "zip": ".zip", "msix": ".msix", "portable": ".exe"}[typ]
	if ext == "" {
		ext = ".exe"
	}
	if name == "" || !strings.Contains(name, ".") {
		name = "installer" + ext
	}
	return name
}

// detectionFor derives a default detection rule from the product code.
func detectionFor(p *Parsed, in Installer, r installerFields) []Detection {
	if in.Type == "msix" {
		// The agent looks the package up by its identity name, in the registrations Windows keeps for all users (D151).
		name, ok := installer.AppxNameFromFamily(r.PackageFamilyName)
		if !ok {
			return nil
		}
		return []Detection{{Kind: "appx", Key: installer.AppxDetectionKey(name), Version: p.Version, Cmp: "ge"}}
	}
	ver := p.Version
	for _, e := range r.AppsAndFeaturesEntries {
		if e.DisplayVersion != "" {
			ver = e.DisplayVersion
			break
		}
	}
	switch {
	case in.ProductCode != "" && guidRe.MatchString(in.ProductCode) && (in.Type == "msi" || in.NestedType == "msi"):
		// an MSI product code is specific to one version: presence is enough
		return []Detection{{Kind: "msi", Key: in.ProductCode}}
	case in.ProductCode != "" && keyNameRe.MatchString(in.ProductCode):
		return []Detection{{Kind: "registry", Key: in.ProductCode, Version: ver, Cmp: "ge"}}
	}
	return nil
}
