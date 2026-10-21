package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/shared/installer"
	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

// Service imports and manages catalog packages.
type Service struct {
	Pool    *pgxpool.Pool
	Source  Source
	Content *Store
	Overlay *Overlay
	Now     func() time.Time
	// HTTP fetches overlay sources; nil uses a client that refuses addresses on this server itself (tests replace it).
	HTTP *http.Client
}

// ErrInvalid wraps validation problems in administrator input.
var ErrInvalid = errors.New("catalog: invalid input")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

func (s *Service) overlay() *Overlay {
	if s.Overlay != nil {
		return s.Overlay
	}
	return LoadOverlay()
}

// ImportResult summarizes an import.
type ImportResult struct {
	PackageID  uuid.UUID `json:"package_id"`
	VersionID  uuid.UUID `json:"version_id"`
	Identifier string    `json:"identifier"`
	Version    string    `json:"version"`
	Installers int       `json:"installers"`
	Deployable int       `json:"deployable"`
	Warnings   []string  `json:"warnings"`
}

// Import fetches the manifests of identifier@version (latest when version is
// empty), validates and normalizes them, and stores the package.
func (s *Service) Import(ctx context.Context, org, user uuid.UUID, identifier, version string) (*ImportResult, error) {
	if s.Source == nil {
		return nil, errors.New("no winget source configured")
	}
	if !ValidIdentifier(identifier) {
		return nil, invalid("PackageIdentifier must look like Publisher.Package")
	}
	if version == "" {
		vs, err := s.Source.Versions(ctx, identifier)
		if err != nil {
			return nil, err
		}
		if len(vs) == 0 {
			return nil, ErrNotFound
		}
		version = vs[0]
	}
	files, err := s.Source.Manifests(ctx, identifier, version)
	if err != nil {
		return nil, err
	}
	p, err := ParseFiles(files)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(p.Identifier, identifier) || p.Version != version {
		return nil, invalid("the manifest describes %s %s, not %s %s", p.Identifier, p.Version, identifier, version)
	}
	return s.store(ctx, org, user, p)
}

func (s *Service) store(ctx context.Context, org, user uuid.UUID, p *Parsed) (*ImportResult, error) {
	res := &ImportResult{Identifier: p.Identifier, Version: p.Version, Installers: len(p.Installers)}
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		self, vouch, tests := s.overlayState(org, p.Identifier)
		pkgID, err := q.UpsertCatalogPackage(ctx, dbq.UpsertCatalogPackageParams{ID: uuid.New(), OrgID: org, Source: "winget",
			Identifier: p.Identifier, Name: p.Name, Publisher: p.Publisher, Homepage: p.Homepage, License: p.License,
			Description: p.Summary, SelfUpdating: self, ImportedBy: &user})
		if err != nil {
			return err
		}
		verID, err := q.UpsertCatalogVersion(ctx, dbq.UpsertCatalogVersionParams{ID: uuid.New(), PackageID: pkgID, Version: p.Version,
			VersionKey: vercmp.Key(p.Version), ManifestSha256: p.ManifestSHA256})
		if err != nil {
			return err
		}
		if err := q.DeleteVersionInstallers(ctx, verID); err != nil {
			return err
		}
		for _, in := range p.Installers {
			sw, _ := json.Marshal(map[string][]string{"silent": nz(in.Silent), "custom": nz(in.Custom)})
			det, _ := json.Marshal(nzd(in.Detection))
			if err := q.InsertCatalogInstaller(ctx, dbq.InsertCatalogInstallerParams{ID: uuid.New(), VersionID: verID,
				Architecture: in.Arch, Scope: in.Scope, InstallerType: in.Type, NestedType: in.NestedType, NestedPath: in.NestedPath,
				Url: in.URL, Sha256: in.SHA256, Size: 0, FileName: in.FileName, ProductCode: in.ProductCode, UpgradeCode: in.UpgradeCode,
				Switches: sw, SuccessCodes: toInt32(in.SuccessCodes), ExpectedCodes: toInt32(in.ExpectedCodes), MinOs: in.MinOS,
				Detection: det, UsesContentBlob: false, Unsupported: in.Unsupported}); err != nil {
				return err
			}
			if in.Unsupported == "" {
				res.Deployable++
			} else {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s %s installer not deployable: %s", in.Arch, in.Type, in.Unsupported))
			}
			if len(in.Detection) == 0 && in.Unsupported == "" {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s %s installer has no detection rule; add one in the package overrides or its success is judged by exit code only", in.Arch, in.Type))
			}
		}
		res.PackageID, res.VersionID = pkgID, verID
		return q.SetPackageOverlayState(ctx, dbq.SetPackageOverlayStateParams{OrgID: org, ID: pkgID, SelfUpdating: self, Overlay: vouch, TestsPassed: tests})
	})
	if err != nil {
		return nil, err
	}
	res.Warnings = dedupe(res.Warnings)
	return res, nil
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nzd(d []Detection) []Detection {
	if d == nil {
		return []Detection{}
	}
	return d
}

func toInt32(in []int) []int32 {
	out := make([]int32, 0, len(in))
	for _, v := range in {
		out = append(out, int32(v)) // #nosec G115 -- exit codes
	}
	return out
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// CustomSpec describes an administrator-uploaded package.
type CustomSpec struct {
	Identifier    string      `json:"identifier"` // e.g. Custom.AcmeTool (the "Custom." prefix is added when missing)
	Name          string      `json:"name"`
	Publisher     string      `json:"publisher"`
	Version       string      `json:"version"`
	Description   string      `json:"description"`
	SHA256        string      `json:"sha256"` // of the uploaded content (hex)
	FileName      string      `json:"file_name"`
	Type          string      `json:"type"`
	NestedType    string      `json:"nested_type"`
	NestedPath    string      `json:"nested_path"`
	Arch          string      `json:"arch"`
	Scope         string      `json:"scope"`
	Args          []string    `json:"args"`
	ProductCode   string      `json:"product_code"`
	SignerSubject string      `json:"signer_subject"`
	SuccessCodes  []int       `json:"success_codes"`
	Detection     []Detection `json:"detection"`
}

var fileRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ +()\-]{0,127}$`)

// AddCustom registers an uploaded installer as a package version.
func (s *Service) AddCustom(ctx context.Context, org, user uuid.UUID, c CustomSpec) (*ImportResult, error) {
	id := strings.TrimSpace(c.Identifier)
	if !strings.HasPrefix(strings.ToLower(id), "custom.") {
		id = "Custom." + id
	}
	if !idRe.MatchString(id) || len(id) < 8 {
		return nil, invalid("identifier may contain letters, digits and . _ + -")
	}
	if strings.TrimSpace(c.Name) == "" || len(c.Name) > 200 || len(c.Publisher) > 200 || len(c.Description) > 1000 {
		return nil, invalid("name is required (at most 200 characters)")
	}
	if c.Version == "" || len(c.Version) > 128 || strings.ContainsAny(c.Version, `/\`) {
		return nil, invalid("version is required")
	}
	t := installer.Type(strings.ToLower(c.Type))
	if !t.Valid() || t == installer.MSIX {
		return nil, invalid("installer type must be msi, inno, nsis, burn, exe, portable or zip")
	}
	switch c.Arch {
	case "x64", "x86", "arm64", "neutral":
	default:
		return nil, invalid("arch must be x64, x86, arm64 or neutral")
	}
	switch c.Scope {
	case "machine", "user", "any":
	default:
		return nil, invalid("scope must be machine, user or any")
	}
	if (t == installer.Portable || t == installer.Zip) && c.Scope != "machine" {
		return nil, invalid("portable and ZIP packages are machine-scope only")
	}
	if t == installer.Zip {
		nt := installer.Type(c.NestedType)
		if !nt.Valid() || !nt.RunsProcess() || c.NestedPath == "" || len(c.NestedPath) > 260 || strings.HasPrefix(c.NestedPath, "/") ||
			strings.Contains(c.NestedPath, "..") || strings.ContainsAny(c.NestedPath, `\:`) {
			return nil, invalid("a ZIP needs a process-based nested type and a relative nested path")
		}
	}
	if !fileRe.MatchString(c.FileName) || strings.Contains(c.FileName, "..") {
		return nil, invalid("file name must be a plain name")
	}
	if err := installer.ValidateArgs(c.Args); err != nil {
		return nil, invalid("%v", err)
	}
	if t == installer.EXE && len(c.Args) == 0 {
		return nil, invalid("an EXE installer needs silent switches")
	}
	if c.ProductCode != "" && !guidRe.MatchString(c.ProductCode) && !keyNameRe.MatchString(c.ProductCode) {
		return nil, invalid("product code is neither a GUID nor a registry key name")
	}
	if err := ValidateDetections(c.Detection); err != nil {
		return nil, err
	}
	if len(c.SuccessCodes) > 16 {
		return nil, invalid("too many success codes")
	}
	sha := decodeHex(c.SHA256)
	if len(sha) != 32 {
		return nil, invalid("sha256 must be the hash returned by the upload")
	}
	q := dbq.New(s.Pool)
	blob, err := q.GetContentBlob(ctx, dbq.GetContentBlobParams{OrgID: org, Sha256: sha})
	if err != nil {
		return nil, invalid("no uploaded content with that hash; upload the installer first")
	}
	sw, _ := json.Marshal(map[string][]string{"silent": []string{}, "custom": nz(c.Args)})
	if t == installer.EXE {
		sw, _ = json.Marshal(map[string][]string{"silent": c.Args, "custom": []string{}})
	}
	det, _ := json.Marshal(nzd(c.Detection))
	res := &ImportResult{Identifier: id, Version: c.Version, Installers: 1, Deployable: 1}
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		pkgID, err := q.UpsertCatalogPackage(ctx, dbq.UpsertCatalogPackageParams{ID: uuid.New(), OrgID: org, Source: "custom", Identifier: id,
			Name: strings.TrimSpace(c.Name), Publisher: c.Publisher, Description: c.Description, ImportedBy: &user})
		if err != nil {
			return err
		}
		verID, err := q.UpsertCatalogVersion(ctx, dbq.UpsertCatalogVersionParams{ID: uuid.New(), PackageID: pkgID, Version: c.Version, VersionKey: vercmp.Key(c.Version)})
		if err != nil {
			return err
		}
		if err := q.DeleteVersionInstallers(ctx, verID); err != nil {
			return err
		}
		res.PackageID, res.VersionID = pkgID, verID
		return q.InsertCatalogInstaller(ctx, dbq.InsertCatalogInstallerParams{ID: uuid.New(), VersionID: verID, Architecture: c.Arch, Scope: c.Scope,
			InstallerType: string(t), NestedType: c.NestedType, NestedPath: c.NestedPath, Sha256: sha, Size: blob.Size, FileName: c.FileName,
			SignerSubject: c.SignerSubject, ProductCode: c.ProductCode, Switches: sw, SuccessCodes: toInt32(c.SuccessCodes),
			ExpectedCodes: []int32{}, Detection: det, UsesContentBlob: true})
	})
	if err != nil {
		return nil, err
	}
	if len(c.Detection) == 0 {
		res.Warnings = []string{"no detection rule: success is judged by the installer's exit code only"}
	}
	return res, nil
}

func decodeHex(s string) []byte {
	if len(s) != 64 {
		return nil
	}
	b := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hi, ok1 := hexVal(s[2*i])
		lo, ok2 := hexVal(s[2*i+1])
		if !ok1 || !ok2 {
			return nil
		}
		b[i] = hi<<4 | lo
	}
	return b
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// ValidateDetections checks administrator-supplied detection rules.
func ValidateDetections(ds []Detection) error {
	if len(ds) > 16 {
		return invalid("at most 16 detection rules")
	}
	for _, d := range ds {
		if d.Key == "" || len(d.Key) > 512 || len(d.ValueName) > 256 || len(d.Version) > 128 {
			return invalid("detection rule fields out of range")
		}
		switch d.Kind {
		case "msi":
			if !guidRe.MatchString(d.Key) {
				return invalid("an MSI detection rule needs a {GUID} product code")
			}
		case "registry", "appx":
		case "file":
			if _, err := installer.ExpandEnv(d.Key, true, func(string) string { return "x" }); err != nil {
				return invalid("file detection path: %v", err)
			}
			if strings.Contains(d.Key, "..") {
				return invalid("file detection path must not contain ..")
			}
		default:
			return invalid("detection kind must be msi, registry, file or appx")
		}
		switch d.Cmp {
		case "", "eq", "ge":
		default:
			return invalid("detection version comparison must be eq or ge")
		}
		if d.Version != "" && vercmp.Key(d.Version) == nil {
			return invalid("detection version %q cannot be compared", d.Version)
		}
	}
	return nil
}

// Override is an organization's changes to a package.
type Override struct {
	SilentArgs      []string    `json:"silent_args"`
	ExtraDetection  []Detection `json:"extra_detection"`
	Pin             string      `json:"pin"`
	Excluded        bool        `json:"excluded"`
	UserScopePolicy string      `json:"user_scope_policy"`
	SelfUpdate      string      `json:"self_update_policy"`
	// Processes are the image names of the programs an update replaces (D124). nil = leave what is stored.
	Processes *[]string `json:"processes"`
}

// ValidatePin accepts "", "latest", "= <version>" or "< <version>".
func ValidatePin(pin string) error {
	if pin == "" || pin == "latest" {
		return nil
	}
	op, v, ok := strings.Cut(pin, " ")
	if !ok || (op != "=" && op != "<") || vercmp.Key(strings.TrimSpace(v)) == nil {
		return invalid(`version pin must be "", "latest", "= <version>" or "< <version>"`)
	}
	return nil
}

// Policies for per-user installs of a package.
var UserPolicies = []string{"report_only", "update_in_place", "convert_to_machine", "remove"}

// SetOverride validates and stores an override.
func (s *Service) SetOverride(ctx context.Context, org, user, pkg uuid.UUID, o Override) error {
	if err := installer.ValidateArgs(o.SilentArgs); err != nil {
		return invalid("%v", err)
	}
	if err := ValidateDetections(o.ExtraDetection); err != nil {
		return err
	}
	if err := ValidatePin(o.Pin); err != nil {
		return err
	}
	if o.UserScopePolicy != "" && !contains(UserPolicies, o.UserScopePolicy) {
		return invalid("user_scope_policy must be one of %s", strings.Join(UserPolicies, ", "))
	}
	if o.SelfUpdate != "" && o.SelfUpdate != "defer_to_vendor" && o.SelfUpdate != "enforce" {
		return invalid("self_update_policy must be defer_to_vendor or enforce")
	}
	if o.Processes != nil {
		if err := installer.ValidateProcessNames(*o.Processes); err != nil {
			return invalid("%v", err)
		}
	}
	q := dbq.New(s.Pool)
	if _, err := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: pkg, OrgID: org}); err != nil {
		return err
	}
	var procs []string
	if o.Processes != nil {
		procs = *o.Processes
	} else if cur, err := q.GetPackageOverride(ctx, dbq.GetPackageOverrideParams{OrgID: org, PackageID: pkg}); err == nil {
		procs = cur.Processes // a client that does not know about programs must not erase them
	}
	det, _ := json.Marshal(nzd(o.ExtraDetection))
	return q.UpsertPackageOverride(ctx, dbq.UpsertPackageOverrideParams{OrgID: org, PackageID: pkg, SilentArgs: nz(o.SilentArgs),
		ExtraDetection: det, Pin: o.Pin, Excluded: o.Excluded, UserScopePolicy: o.UserScopePolicy, SelfUpdatePolicy: o.SelfUpdate, Processes: nz(procs), UpdatedBy: &user})
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

// ChooseVersion picks the version to deploy: the requested one, or the newest
// that satisfies the pin. Excluded packages are refused by the caller.
func ChooseVersion(versions []dbq.CatalogVersion, requested, pin string) (*dbq.CatalogVersion, error) {
	sorted := append([]dbq.CatalogVersion(nil), versions...)
	sort.Slice(sorted, func(i, j int) bool { return vercmp.Compare(sorted[i].Version, sorted[j].Version) > 0 })
	ok := func(v string) bool {
		if pin == "" || pin == "latest" {
			return true
		}
		op, pv, _ := strings.Cut(pin, " ")
		c := vercmp.Compare(v, strings.TrimSpace(pv))
		if op == "=" {
			return c == 0
		}
		return c < 0
	}
	for i := range sorted {
		if requested != "" {
			if sorted[i].Version == requested {
				if !ok(requested) {
					return nil, invalid("version %s does not satisfy the package's version pin %q", requested, pin)
				}
				return &sorted[i], nil
			}
			continue
		}
		if ok(sorted[i].Version) {
			return &sorted[i], nil
		}
	}
	if requested != "" {
		return nil, invalid("version %s is not in the catalog", requested)
	}
	return nil, invalid("no catalog version satisfies the package's version pin %q", pin)
}

// SelectInstaller picks the best deployable installer for an architecture and scope.
func SelectInstaller(ins []dbq.CatalogInstaller, deviceArch, scope string) *dbq.CatalogInstaller {
	arches := archPreference(deviceArch)
	typeRank := map[string]int{"msi": 0, "inno": 1, "nsis": 1, "burn": 1, "exe": 2, "zip": 3, "portable": 4}
	var best *dbq.CatalogInstaller
	bestScore := 1 << 30
	for i := range ins {
		in := &ins[i]
		if in.Unsupported != "" {
			continue
		}
		ar := indexOf(arches, in.Architecture)
		if ar < 0 {
			continue
		}
		sc := 0
		switch {
		case in.Scope == scope:
		case in.Scope == "any":
			sc = 1
		default:
			continue
		}
		score := ar*100 + sc*10 + typeRank[in.InstallerType]
		if score < bestScore {
			best, bestScore = in, score
		}
	}
	return best
}

// archPreference lists installer architectures a device can run, best first.
func archPreference(deviceArch string) []string {
	switch strings.ToLower(deviceArch) {
	case "amd64", "x64", "x86_64":
		return []string{"x64", "neutral", "x86"}
	case "arm64":
		return []string{"arm64", "neutral", "x64", "x86"}
	case "386", "x86":
		return []string{"x86", "neutral"}
	}
	return []string{"neutral"}
}

func indexOf(s []string, x string) int {
	for i, v := range s {
		if v == x {
			return i
		}
	}
	return -1
}

// VerifyChange describes what an administrator's mark changed (for the audit entry).
type VerifyChange struct {
	Identifier     string
	Version        string // the newest imported version, the one being vouched for
	TestsPassed    bool   // the package passed the VM test matrix on its own
	BeforeVerified bool
	AfterVerified  bool
	BeforeByOrg    bool
}

// SetOrgVerified marks a winget package as verified by the organization, or removes that mark. The package stays verified
// if it also passed the VM test matrix. Custom packages need no verification and are refused.
func (s *Service) SetOrgVerified(ctx context.Context, org, user, pkgID uuid.UUID, verified bool) (*VerifyChange, error) {
	q := dbq.New(s.Pool)
	pkg, err := q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: pkgID, OrgID: org})
	if err != nil {
		return nil, ErrNotFound
	}
	if pkg.Source != "winget" {
		return nil, invalid("only packages from winget need verification; your own uploads are never asked about")
	}
	ch := &VerifyChange{Identifier: pkg.Identifier, TestsPassed: s.overlay().Verified(pkg.Identifier, ""), BeforeVerified: pkg.Verified, BeforeByOrg: pkg.VerifiedByOrg}
	if vs, err := q.ListPackageVersions(ctx, pkg.ID); err == nil && len(vs) > 0 {
		ch.Version = vs[0].Version
	}
	ch.AfterVerified = verified || ch.TestsPassed || pkg.VerifiedByOverlay != ""
	err = q.SetPackageOrgVerified(ctx, dbq.SetPackageOrgVerifiedParams{OrgID: org, ID: pkg.ID, ByOrg: verified, TestsPassed: ch.TestsPassed, By: user,
		At: time.Now().UTC(), Version: ch.Version})
	if err != nil {
		return nil, err
	}
	return ch, nil
}
