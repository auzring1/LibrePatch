// Package branding holds the per-deployment branding: organization name, product name override, colors, login
// page texts, report footer and the five images (decision D92). Everything is optional and an empty value means
// "the default", so an installation that never opens the page looks like the stock product.
package branding

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/shared/brand"
)

// DefaultAccent is the accent color of an installation that did not choose one. It passes every check in Checks.
const DefaultAccent = "#1971c2"

// Settings are the texts and colors an administrator can set. An empty string means "use the default" (product
// name, accent) or "show nothing" (everything else).
type Settings struct {
	OrgName        string `json:"org_name"`
	ProductName    string `json:"product_name"`
	AccentColor    string `json:"accent_color"`
	SecondaryColor string `json:"secondary_color"`
	LoginHeadline  string `json:"login_headline"`
	LoginMessage   string `json:"login_message"`
	LoginFooter    string `json:"login_footer"`
	SupportEmail   string `json:"support_email"`
	SupportPhone   string `json:"support_phone"`
	SupportURL     string `json:"support_url"`
	ReportFooter   string `json:"report_footer"`
	// DefaultTheme is the console theme for people who have not chosen one ("" = follow the device). AllowedThemes
	// limits which themes people may pick (empty = all). Theme ids are checked for shape only: the console knows
	// which themes exist, so adding one needs no server change.
	DefaultTheme  string   `json:"default_theme"`
	AllowedThemes []string `json:"allowed_themes"`
}

// Defaults are the values used while a setting is empty.
type Defaults struct {
	ProductName string `json:"product_name"`
	AccentColor string `json:"accent_color"`
}

// DefaultValues returns the built-in defaults.
func DefaultValues() Defaults { return Defaults{ProductName: brand.Name, AccentColor: DefaultAccent} }

// ValidationError lists the fields that were refused, with a message for each.
type ValidationError struct{ Fields map[string]string }

func (e *ValidationError) Error() string {
	var parts []string
	for k, v := range e.Fields {
		parts = append(parts, k+": "+v)
	}
	return "branding: " + strings.Join(parts, "; ")
}

var colorRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
var phoneRe = regexp.MustCompile(`^[0-9+()\-. x]{3,40}$`)

// bidi controls can make text read differently from how it is stored.
func hasBidi(s string) bool {
	for _, r := range s {
		if (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return true
		}
	}
	return false
}

// text normalizes and checks a free-text field. Multi-line fields keep newlines.
func text(fields map[string]string, name, label, v string, max int, multiline bool) string {
	v = strings.ReplaceAll(strings.TrimSpace(v), "\r\n", "\n")
	if utf8.RuneCountInString(v) > max {
		fields[name] = fmt.Sprintf("%s can be at most %d characters.", label, max)
		return v
	}
	if !utf8.ValidString(v) || hasBidi(v) {
		fields[name] = label + " contains characters that are not allowed."
		return v
	}
	for _, r := range v {
		if unicode.IsControl(r) && !(multiline && (r == '\n' || r == '\t')) {
			fields[name] = label + " contains control characters."
			return v
		}
	}
	return v
}

// Validate checks and normalizes settings. Colors are stored lower-case. The accent and secondary colors must pass
// the contrast checks (WCAG AA), because the console draws text and graphics with them.
func Validate(in Settings) (Settings, error) {
	f := map[string]string{}
	out := Settings{}
	out.OrgName = text(f, "org_name", "The organization name", in.OrgName, 120, false)
	out.ProductName = text(f, "product_name", "The product name", in.ProductName, 60, false)
	out.LoginHeadline = text(f, "login_headline", "The headline", in.LoginHeadline, 120, false)
	out.LoginMessage = text(f, "login_message", "The welcome message", in.LoginMessage, 1000, true)
	out.LoginFooter = text(f, "login_footer", "The footer text", in.LoginFooter, 1000, true)
	out.ReportFooter = text(f, "report_footer", "The report footer", in.ReportFooter, 500, true)

	color := func(name, label, v string) string {
		v = strings.TrimSpace(v)
		if v == "" {
			return ""
		}
		if !colorRe.MatchString(v) {
			f[name] = label + " must be a color like #1971c2."
			return v
		}
		return strings.ToLower(v)
	}
	out.AccentColor = color("accent_color", "The accent color", in.AccentColor)
	out.SecondaryColor = color("secondary_color", "The secondary color", in.SecondaryColor)

	if v := strings.TrimSpace(in.SupportEmail); v != "" {
		a, err := mail.ParseAddress(v)
		if err != nil || a.Address != v || a.Name != "" || len(v) > 254 {
			f["support_email"] = "The support email must be an address like help@example.org."
		} else {
			out.SupportEmail = strings.ToLower(v)
		}
	}
	if v := strings.TrimSpace(in.SupportPhone); v != "" {
		if !phoneRe.MatchString(v) {
			f["support_phone"] = "The support phone number can contain digits, spaces and + ( ) - . x only (3 to 40 characters)."
		} else {
			out.SupportPhone = v
		}
	}
	if v := strings.TrimSpace(in.SupportURL); v != "" {
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(v) > 300 || strings.ContainsAny(v, " \t\r\n\\<>\"'`") {
			f["support_url"] = "The support link must be an https:// address (up to 300 characters)."
		} else {
			out.SupportURL = v
		}
	}
	out.DefaultTheme, out.AllowedThemes = themes(f, in.DefaultTheme, in.AllowedThemes)
	if f["accent_color"] == "" && f["secondary_color"] == "" {
		for _, c := range Failing(Checks(out.AccentColor, out.SecondaryColor)) {
			name := "accent_color"
			if strings.HasPrefix(c.ID, "secondary") {
				name = "secondary_color"
			}
			f[name] = fmt.Sprintf("Not accessible enough: %s needs a contrast of at least %.1f:1 but has %.2f:1 (WCAG AA). Choose a darker or lighter color.", c.Label, c.Required, c.Ratio)
		}
	}
	if len(f) > 0 {
		return Settings{}, &ValidationError{Fields: f}
	}
	return out, nil
}

var themeIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// MaxThemes bounds the list of offered themes.
const MaxThemes = 16

// ValidThemeID reports whether id is shaped like a theme id.
func ValidThemeID(id string) bool { return themeIDRe.MatchString(id) }

// themes checks the default theme and the offered list: well-formed, no duplicates, and the default is one of the
// offered themes when the list is not empty.
func themes(f map[string]string, def string, allowed []string) (string, []string) {
	def = strings.TrimSpace(def)
	if def != "" && !themeIDRe.MatchString(def) {
		f["default_theme"] = "The default theme is not valid."
	}
	out := make([]string, 0, len(allowed))
	seen := map[string]bool{}
	for _, a := range allowed {
		a = strings.TrimSpace(a)
		switch {
		case !themeIDRe.MatchString(a):
			f["allowed_themes"] = "A theme in the list is not valid."
		case seen[a]:
			f["allowed_themes"] = "A theme is listed twice."
		default:
			seen[a] = true
			out = append(out, a)
		}
	}
	if len(out) > MaxThemes {
		f["allowed_themes"] = fmt.Sprintf("At most %d themes can be offered.", MaxThemes)
	}
	if len(out) > 0 && def != "" && !seen[def] && f["default_theme"] == "" {
		f["default_theme"] = "The default theme must be one of the offered themes."
	}
	return def, out
}

// AssetRef is how a stored image is referred to by pages.
type AssetRef struct {
	URL    string `json:"url"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

// AssetInfo is an asset's metadata for the administration page.
type AssetInfo struct {
	AssetRef
	Kind      string    `json:"kind"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Support is the support contact shown on the login page.
type Support struct {
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
	URL   string `json:"url,omitempty"`
}

// Public is what any visitor (signed out too) may read: it is shown on the login page.
type Public struct {
	ProductName    string               `json:"product_name"`
	OrgName        string               `json:"org_name"`
	Title          string               `json:"title"`
	AccentColor    string               `json:"accent_color"`
	SecondaryColor string               `json:"secondary_color"`
	LoginHeadline  string               `json:"login_headline"`
	LoginMessage   string               `json:"login_message"`
	LoginFooter    string               `json:"login_footer"`
	Support        Support              `json:"support"`
	DefaultTheme   string               `json:"default_theme"`
	AllowedThemes  []string             `json:"allowed_themes"`
	Assets         map[string]*AssetRef `json:"assets"`
	Version        string               `json:"version"`
}

// View is the administration view: the stored settings, what they resolve to, the images and the contrast checks.
type View struct {
	Settings  Settings              `json:"settings"`
	Resolved  Public                `json:"resolved"`
	Assets    map[string]*AssetInfo `json:"assets"`
	Defaults  Defaults              `json:"defaults"`
	Contrast  []Check               `json:"contrast"`
	UpdatedAt *time.Time            `json:"updated_at"`
}

// Actor identifies who changed the branding, for the audit log.
type Actor struct {
	Org  uuid.UUID
	User uuid.UUID
	IP   string
}

// Service reads and writes branding.
type Service struct {
	Pool *pgxpool.Pool
	Log  *slog.Logger
	Now  func() time.Time

	mu    sync.Mutex
	cache map[uuid.UUID]*View
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) invalidate(org uuid.UUID) {
	s.mu.Lock()
	delete(s.cache, org)
	s.mu.Unlock()
}

func assetURL(kind string, sha []byte) string {
	return "/api/v1/branding/assets/" + kind + "?v=" + hex.EncodeToString(sha)[:12]
}

func resolve(st Settings, assets map[string]*AssetInfo) Public {
	p := Public{ProductName: st.ProductName, OrgName: st.OrgName, AccentColor: st.AccentColor, SecondaryColor: st.SecondaryColor,
		LoginHeadline: st.LoginHeadline, LoginMessage: st.LoginMessage, LoginFooter: st.LoginFooter,
		Support: Support{Email: st.SupportEmail, Phone: st.SupportPhone, URL: st.SupportURL}, Assets: map[string]*AssetRef{},
		DefaultTheme: st.DefaultTheme, AllowedThemes: append([]string{}, st.AllowedThemes...)}
	if p.ProductName == "" {
		p.ProductName = brand.Name
	}
	if p.AccentColor == "" {
		p.AccentColor = DefaultAccent
	}
	p.Title = p.ProductName
	if p.OrgName != "" {
		p.Title = p.OrgName + " · " + p.ProductName
	}
	for k, a := range assets {
		ref := a.AssetRef
		p.Assets[k] = &ref
	}
	j, _ := json.Marshal(p) // Version is empty here, so it covers exactly the visible content
	sum := sha256.Sum256(j)
	p.Version = hex.EncodeToString(sum[:])[:12]
	return p
}

func fromRow(r dbq.Branding) Settings {
	return Settings{OrgName: r.OrgName, ProductName: r.ProductName, AccentColor: r.AccentColor, SecondaryColor: r.SecondaryColor,
		LoginHeadline: r.LoginHeadline, LoginMessage: r.LoginMessage, LoginFooter: r.LoginFooter,
		SupportEmail: r.SupportEmail, SupportPhone: r.SupportPhone, SupportURL: r.SupportUrl, ReportFooter: r.ReportFooter,
		DefaultTheme: r.DefaultTheme, AllowedThemes: append([]string{}, r.AllowedThemes...)}
}

func (s *Service) load(ctx context.Context, q *dbq.Queries, org uuid.UUID) (*View, error) {
	v := &View{Defaults: DefaultValues(), Assets: map[string]*AssetInfo{}}
	row, err := q.GetBranding(ctx, org)
	switch {
	case err == nil:
		v.Settings = fromRow(row)
		t := row.UpdatedAt
		v.UpdatedAt = &t
	case !store.IsNoRows(err):
		return nil, err
	}
	rows, err := q.ListBrandingAssets(ctx, org)
	if err != nil {
		return nil, err
	}
	for _, a := range rows {
		v.Assets[a.Kind] = &AssetInfo{Kind: a.Kind, Size: a.Size, SHA256: hex.EncodeToString(a.Sha256), UpdatedAt: a.UpdatedAt,
			AssetRef: AssetRef{URL: assetURL(a.Kind, a.Sha256), Width: int(a.Width), Height: int(a.Height)}}
	}
	v.Resolved = resolve(v.Settings, v.Assets)
	v.Contrast = Checks(v.Resolved.AccentColor, v.Resolved.SecondaryColor)
	return v, nil
}

// View returns the administration view of an organization.
func (s *Service) View(ctx context.Context, org uuid.UUID) (*View, error) {
	s.mu.Lock()
	if v, ok := s.cache[org]; ok {
		s.mu.Unlock()
		return v, nil
	}
	s.mu.Unlock()
	v, err := s.load(ctx, dbq.New(s.Pool), org)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.cache == nil {
		s.cache = map[uuid.UUID]*View{}
	}
	s.cache[org] = v
	s.mu.Unlock()
	return v, nil
}

// DefaultOrg returns the organization that the public pages describe, or uuid.Nil before setup.
func (s *Service) DefaultOrg(ctx context.Context) (uuid.UUID, error) {
	o, err := dbq.New(s.Pool).GetDefaultOrganization(ctx)
	if store.IsNoRows(err) {
		return uuid.Nil, nil
	}
	return o.ID, err
}

// Public returns what the signed-out pages show. Before setup it is the stock branding.
func (s *Service) Public(ctx context.Context) (Public, error) {
	org, err := s.DefaultOrg(ctx)
	if err != nil {
		return Public{}, err
	}
	if org == uuid.Nil {
		return resolve(Settings{}, nil), nil
	}
	v, err := s.View(ctx, org)
	if err != nil {
		return Public{}, err
	}
	return v.Resolved, nil
}

func snapshot(st Settings) map[string]any {
	return map[string]any{"org_name": st.OrgName, "product_name": st.ProductName, "accent_color": st.AccentColor,
		"secondary_color": st.SecondaryColor, "login_headline": st.LoginHeadline, "login_message": st.LoginMessage,
		"login_footer": st.LoginFooter, "support_email": st.SupportEmail, "support_phone": st.SupportPhone,
		"support_url": st.SupportURL, "report_footer": st.ReportFooter,
		"default_theme": st.DefaultTheme, "allowed_themes": strings.Join(st.AllowedThemes, ",")}
}

func diff(before, after Settings) (b, a map[string]any) {
	b, a = map[string]any{}, map[string]any{}
	bs, as := snapshot(before), snapshot(after)
	for k, v := range as {
		if bs[k] != v {
			b[k], a[k] = bs[k], v
		}
	}
	return b, a
}

func assetSummary(a *AssetInfo) any {
	if a == nil {
		return nil
	}
	return map[string]any{"sha256": a.SHA256, "size": a.Size, "width": a.Width, "height": a.Height}
}

func (s *Service) writeAudit(ctx context.Context, tx pgx.Tx, a Actor, action string, target string, details map[string]any) error {
	_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &a.Org, ActorType: audit.ActorUser, ActorID: a.User.String(), ActorIP: a.IP,
		Action: action, TargetType: "branding", TargetIDs: []string{target}, Outcome: audit.Success, Details: details}, s.now())
	return err
}

func upsertParams(org uuid.UUID, st Settings, now time.Time, by uuid.UUID) dbq.UpsertBrandingParams {
	return dbq.UpsertBrandingParams{OrgID: org, OrgName: st.OrgName, ProductName: st.ProductName, AccentColor: st.AccentColor,
		SecondaryColor: st.SecondaryColor, LoginHeadline: st.LoginHeadline, LoginMessage: st.LoginMessage, LoginFooter: st.LoginFooter,
		SupportEmail: st.SupportEmail, SupportPhone: st.SupportPhone, SupportUrl: st.SupportURL, ReportFooter: st.ReportFooter,
		DefaultTheme: st.DefaultTheme, AllowedThemes: append([]string{}, st.AllowedThemes...),
		UpdatedAt: now, UpdatedBy: &by}
}

// Update replaces the texts and colors. Changed fields are written to the audit log with their old and new values.
func (s *Service) Update(ctx context.Context, a Actor, in Settings) (*View, error) {
	st, err := Validate(in)
	if err != nil {
		return nil, err
	}
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		cur, err := s.load(ctx, q, a.Org)
		if err != nil {
			return err
		}
		before, after := diff(cur.Settings, st)
		if len(after) == 0 {
			return nil
		}
		if err := q.UpsertBranding(ctx, upsertParams(a.Org, st, s.now(), a.User)); err != nil {
			return err
		}
		return s.writeAudit(ctx, tx, a, "branding.update", a.Org.String(), map[string]any{"before": before, "after": after})
	})
	if err != nil {
		return nil, err
	}
	s.invalidate(a.Org)
	return s.View(ctx, a.Org)
}

// PutAsset validates, cleans and stores an image.
func (s *Service) PutAsset(ctx context.Context, a Actor, kind string, data []byte) (*View, error) {
	p, err := Process(kind, data)
	if err != nil {
		return nil, err
	}
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		cur, err := s.load(ctx, q, a.Org)
		if err != nil {
			return err
		}
		// An organization without a branding row gets one (all defaults) so the images have an owner row to be audited with.
		if cur.UpdatedAt == nil {
			if err := q.UpsertBranding(ctx, upsertParams(a.Org, Settings{}, s.now(), a.User)); err != nil {
				return err
			}
		}
		if err := q.UpsertBrandingAsset(ctx, dbq.UpsertBrandingAssetParams{OrgID: a.Org, Kind: kind, Content: p.PNG, ContentType: "image/png",
			Width: int32(p.Width), Height: int32(p.Height), Sha256: p.SHA256[:], UpdatedAt: s.now(), UpdatedBy: &a.User}); err != nil { // #nosec G115 -- bounded by Process
			return err
		}
		after := &AssetInfo{Size: int64(len(p.PNG)), SHA256: hex.EncodeToString(p.SHA256[:]), AssetRef: AssetRef{Width: p.Width, Height: p.Height}}
		return s.writeAudit(ctx, tx, a, "branding.asset_set", kind, map[string]any{"kind": kind, "before": assetSummary(cur.Assets[kind]), "after": assetSummary(after)})
	})
	if err != nil {
		return nil, err
	}
	s.invalidate(a.Org)
	return s.View(ctx, a.Org)
}

// ErrNoAsset means the slot holds no image.
var ErrNoAsset = errors.New("branding: no such image")

// DeleteAsset removes an image.
func (s *Service) DeleteAsset(ctx context.Context, a Actor, kind string) (*View, error) {
	if !ValidKind(kind) {
		return nil, &ValidationError{Fields: map[string]string{"kind": "Unknown image slot."}}
	}
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		cur, err := s.load(ctx, q, a.Org)
		if err != nil {
			return err
		}
		n, err := q.DeleteBrandingAsset(ctx, dbq.DeleteBrandingAssetParams{OrgID: a.Org, Kind: kind})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNoAsset
		}
		return s.writeAudit(ctx, tx, a, "branding.asset_delete", kind, map[string]any{"kind": kind, "before": assetSummary(cur.Assets[kind]), "after": nil})
	})
	if err != nil {
		return nil, err
	}
	s.invalidate(a.Org)
	return s.View(ctx, a.Org)
}

// Reset removes all branding: texts, colors and images go back to the defaults.
func (s *Service) Reset(ctx context.Context, a Actor) (*View, error) {
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		cur, err := s.load(ctx, q, a.Org)
		if err != nil {
			return err
		}
		if err := q.DeleteBrandingAssets(ctx, a.Org); err != nil {
			return err
		}
		if err := q.DeleteBranding(ctx, a.Org); err != nil {
			return err
		}
		assets := map[string]any{}
		for k, v := range cur.Assets {
			assets[k] = assetSummary(v)
		}
		return s.writeAudit(ctx, tx, a, "branding.reset", a.Org.String(), map[string]any{
			"before": map[string]any{"settings": snapshot(cur.Settings), "assets": assets},
			"after":  map[string]any{"settings": snapshot(Settings{}), "assets": map[string]any{}}})
	})
	if err != nil {
		return nil, err
	}
	s.invalidate(a.Org)
	return s.View(ctx, a.Org)
}

// Asset is a stored image ready to be served.
type Asset struct {
	Content []byte
	SHA256  string
	Width   int
	Height  int
}

// Asset reads one image of the default organization (for the public asset URLs).
func (s *Service) Asset(ctx context.Context, org uuid.UUID, kind string) (Asset, error) {
	if !ValidKind(kind) {
		return Asset{}, ErrNoAsset
	}
	row, err := dbq.New(s.Pool).GetBrandingAsset(ctx, dbq.GetBrandingAssetParams{OrgID: org, Kind: kind})
	if store.IsNoRows(err) {
		return Asset{}, ErrNoAsset
	}
	if err != nil {
		return Asset{}, err
	}
	return Asset{Content: row.Content, SHA256: hex.EncodeToString(row.Sha256), Width: int(row.Width), Height: int(row.Height)}, nil
}

// SetInitial stores the branding chosen in the first-run wizard, inside the wizard's transaction. logo may be nil.
func SetInitial(ctx context.Context, q *dbq.Queries, org, user uuid.UUID, orgName string, logo *Processed, now time.Time) error {
	st, err := Validate(Settings{OrgName: orgName})
	if err != nil {
		return err
	}
	if err := q.UpsertBranding(ctx, upsertParams(org, st, now, user)); err != nil {
		return err
	}
	if logo != nil {
		return q.UpsertBrandingAsset(ctx, dbq.UpsertBrandingAssetParams{OrgID: org, Kind: KindLogoLight, Content: logo.PNG, ContentType: "image/png",
			Width: int32(logo.Width), Height: int32(logo.Height), Sha256: logo.SHA256[:], UpdatedAt: now, UpdatedBy: &user}) // #nosec G115 -- bounded by Process
	}
	return nil
}

// ReportBrand is what an exported report (or an email) shows: the names, a footer and the logo as a data URI.
type ReportBrand struct {
	ProductName string
	OrgName     string
	Footer      string
	LogoDataURI string // empty without a logo
	LogoPNG     []byte // the same image as PNG bytes (for PDF reports); empty without a logo
	AccentColor string
}

// ForReport returns the report branding: the report logo, else the light logo, else none.
func (s *Service) ForReport(ctx context.Context, org uuid.UUID) (ReportBrand, error) {
	v, err := s.View(ctx, org)
	if err != nil {
		return ReportBrand{}, err
	}
	rb := ReportBrand{ProductName: v.Resolved.ProductName, OrgName: v.Resolved.OrgName, Footer: v.Settings.ReportFooter, AccentColor: v.Resolved.AccentColor}
	for _, k := range []string{KindReportLogo, KindLogoLight} {
		if _, ok := v.Assets[k]; !ok {
			continue
		}
		a, err := s.Asset(ctx, org, k)
		if err != nil {
			return rb, err
		}
		rb.LogoDataURI = "data:image/png;base64," + base64.StdEncoding.EncodeToString(a.Content)
		rb.LogoPNG = a.Content
		break
	}
	return rb, nil
}
