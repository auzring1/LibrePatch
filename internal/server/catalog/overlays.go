package catalog

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/shared/overlay"
)

// ErrConflict is returned when a name is already taken.
var ErrConflict = errors.New("catalog: conflict")

// refreshEvery is how often a source that has a URL is asked for a newer document.
const refreshEvery = 12 * time.Hour

// OverlaySource is the console's view of one overlay source.
type OverlaySource struct {
	ID          uuid.UUID  `json:"id"`
	Label       string     `json:"label"`
	Kind        string     `json:"kind"` // upload | url
	URL         string     `json:"url"`
	PublicKey   string     `json:"public_key"`
	KeyID       string     `json:"key_id"`
	Enabled     bool       `json:"enabled"`
	Priority    int32      `json:"priority"`
	DocName     string     `json:"doc_name"`
	DocVersion  int64      `json:"doc_version"`
	DocIssuedAt string     `json:"doc_issued_at"`
	Entries     int32      `json:"entries"`
	Verified    int        `json:"verified_entries"`
	FetchedAt   *time.Time `json:"fetched_at"`
	CheckedAt   *time.Time `json:"checked_at"`
	Status      string     `json:"status"` // ok | error | new
	LastError   string     `json:"last_error"`
}

func viewOverlay(r dbq.CatalogOverlay) OverlaySource {
	v := OverlaySource{ID: r.ID, Label: r.Label, Kind: r.Kind, URL: r.Url, PublicKey: r.PublicKey, Enabled: r.Enabled, Priority: r.Priority, DocName: r.DocName,
		DocVersion: r.DocVersion, DocIssuedAt: r.DocIssuedAt, Entries: r.Entries, FetchedAt: r.FetchedAt, CheckedAt: r.CheckedAt, Status: r.Status, LastError: r.LastError}
	if pub, err := overlay.ParsePublicKey(r.PublicKey); err == nil {
		v.KeyID = overlay.KeyID(pub)
	}
	if len(r.Document) > 0 {
		if d, err := overlay.ParseDocument(r.Document); err == nil {
			for _, p := range d.Packages {
				if p.Verified {
					v.Verified++
				}
			}
		}
	}
	return v
}

func isUniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// checkDocument runs the checks the shared package cannot (it does not know the detection rule grammar).
func checkDocument(d *overlay.Document) error {
	for _, e := range d.Packages {
		if len(e.ExtraDetection) == 0 {
			continue
		}
		var det []Detection
		if err := json.Unmarshal(e.ExtraDetection, &det); err != nil {
			return invalid("package %q: the detection rules are not valid: %v", e.Identifier, err)
		}
		if err := ValidateDetections(det); err != nil {
			return fmt.Errorf("package %q: %w", e.Identifier, err)
		}
	}
	return nil
}

// openBundle verifies a bundle under a public key and turns the refusals into messages an administrator can act on.
func openBundle(bundle []byte, pubHex string) (*overlay.Document, ed25519.PublicKey, error) {
	pub, err := overlay.ParsePublicKey(pubHex)
	if err != nil {
		return nil, nil, invalid("%v", err)
	}
	doc, _, err := overlay.Verify(bundle, pub)
	switch {
	case errors.Is(err, overlay.ErrSignature):
		return nil, nil, invalid("the signature does not match the public key you entered: the file was not signed with that key, or it was changed after signing")
	case errors.Is(err, overlay.ErrFormat):
		return nil, nil, invalid("this is not a signed LibrePatch overlay file (.lpov)")
	case err != nil:
		return nil, nil, invalid("%v", err)
	}
	if err := checkDocument(doc); err != nil {
		return nil, nil, err
	}
	return doc, pub, nil
}

func cleanLabel(label, fallback string) (string, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		label = strings.TrimSpace(fallback)
	}
	if n := len([]rune(label)); n < 1 || n > 100 {
		return "", invalid("the name must be 1 to 100 characters")
	}
	return label, nil
}

func cleanURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || len(raw) > 2000 {
		return "", invalid("the address must be an http or https URL without a user name or password")
	}
	return u.String(), nil
}

// ListOverlays returns the organization's overlay sources, highest priority first.
func (s *Service) ListOverlays(ctx context.Context, org uuid.UUID) ([]OverlaySource, error) {
	rows, err := dbq.New(s.Pool).ListCatalogOverlays(ctx, org)
	if err != nil {
		return nil, err
	}
	out := make([]OverlaySource, 0, len(rows))
	for _, r := range rows {
		out = append(out, viewOverlay(r))
	}
	return out, nil
}

// AddOverlay adds a source: an uploaded bundle (bundle set) or a URL to fetch (rawURL set). The document must verify under
// pubHex; nothing is stored otherwise.
func (s *Service) AddOverlay(ctx context.Context, org, user uuid.UUID, label, pubHex, rawURL string, bundle []byte) (*OverlaySource, error) {
	link, err := cleanURL(rawURL)
	if err != nil {
		return nil, err
	}
	kind, etag := "upload", ""
	if link != "" {
		kind = "url"
		body, tag, _, err := s.fetchBundle(ctx, link, "")
		if err != nil {
			return nil, invalid("could not fetch the overlay: %v", err)
		}
		bundle, etag = body, tag
	}
	if len(bundle) == 0 {
		return nil, invalid("give a signed overlay file or an address to fetch it from")
	}
	doc, pub, err := openBundle(bundle, pubHex)
	if err != nil {
		return nil, err
	}
	label, err = cleanLabel(label, doc.Name)
	if err != nil {
		return nil, err
	}
	j, _ := json.Marshal(doc)
	now := s.now()
	id := uuid.New()
	err = dbq.New(s.Pool).InsertCatalogOverlay(ctx, dbq.InsertCatalogOverlayParams{ID: id, OrgID: org, Label: label, Kind: kind, Url: link, PublicKey: hex.EncodeToString(pub),
		Enabled: true, Priority: 100, DocName: doc.Name, DocVersion: doc.Version, DocIssuedAt: doc.IssuedAt, Document: j, Entries: int32(len(doc.Packages)), // #nosec G115 -- at most 5000
		FetchedAt: &now, Etag: etag, CreatedBy: &user})
	if isUniqueViolation(err) {
		return nil, fmt.Errorf("%w: an overlay with that name already exists", ErrConflict)
	}
	if err != nil {
		return nil, err
	}
	if err := s.ReloadOverlays(ctx, org); err != nil {
		return nil, err
	}
	row, err := dbq.New(s.Pool).GetCatalogOverlay(ctx, dbq.GetCatalogOverlayParams{ID: id, OrgID: org})
	if err != nil {
		return nil, err
	}
	v := viewOverlay(row)
	return &v, nil
}

// OverlayChange is what an update did, for the audit entry.
type OverlayChange struct {
	Label      string
	DocVersion int64
	Changed    bool
	Entries    int
}

// ReplaceOverlay loads a newer signed file into an existing source (the same key must have signed it). A document older than
// the one the source has is refused: replacing a newer overlay with an older one would undo fixes.
func (s *Service) ReplaceOverlay(ctx context.Context, org, id uuid.UUID, bundle []byte) (*OverlayChange, error) {
	row, err := dbq.New(s.Pool).GetCatalogOverlay(ctx, dbq.GetCatalogOverlayParams{ID: id, OrgID: org})
	if err != nil {
		return nil, ErrNotFound
	}
	return s.accept(ctx, row, bundle, "")
}

func (s *Service) accept(ctx context.Context, row dbq.CatalogOverlay, bundle []byte, etag string) (*OverlayChange, error) {
	doc, _, err := openBundle(bundle, row.PublicKey)
	if err != nil {
		return nil, err
	}
	if doc.Version < row.DocVersion {
		return nil, invalid("this overlay is version %d, older than the version %d this source already has", doc.Version, row.DocVersion)
	}
	ch := &OverlayChange{Label: row.Label, DocVersion: doc.Version, Entries: len(doc.Packages)}
	if doc.Version == row.DocVersion && len(row.Document) > 0 {
		var old, cur any
		_ = json.Unmarshal(row.Document, &old)
		j, _ := json.Marshal(doc)
		_ = json.Unmarshal(j, &cur)
		a, _ := json.Marshal(old)
		b, _ := json.Marshal(cur)
		if string(a) == string(b) {
			return ch, s.checked(ctx, row.ID, "ok", "")
		}
	}
	j, _ := json.Marshal(doc)
	if _, err := dbq.New(s.Pool).SaveCatalogOverlayDocument(ctx, dbq.SaveCatalogOverlayDocumentParams{ID: row.ID, OrgID: row.OrgID, DocName: doc.Name, DocVersion: doc.Version,
		DocIssuedAt: doc.IssuedAt, Document: j, Entries: int32(len(doc.Packages)), FetchedAt: ptrTime(s.now()), Etag: etag}); err != nil { // #nosec G115 -- at most 5000
		return nil, err
	}
	ch.Changed = true
	return ch, s.ReloadOverlays(ctx, row.OrgID)
}

func ptrTime(t time.Time) *time.Time { return &t }

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// checked records the outcome of asking a source for a newer document.
func (s *Service) checked(ctx context.Context, id uuid.UUID, status, msg string) error {
	t := s.now()
	return dbq.New(s.Pool).SetCatalogOverlayChecked(ctx, dbq.SetCatalogOverlayCheckedParams{ID: id, CheckedAt: &t, Status: status, LastError: msg})
}

// RefreshOverlay asks a URL source for a newer document. A failure is recorded on the source (and returned); the document
// the source already has stays in use.
func (s *Service) RefreshOverlay(ctx context.Context, org, id uuid.UUID) (*OverlayChange, error) {
	q := dbq.New(s.Pool)
	row, err := q.GetCatalogOverlay(ctx, dbq.GetCatalogOverlayParams{ID: id, OrgID: org})
	if err != nil {
		return nil, ErrNotFound
	}
	if row.Kind != "url" || row.Url == "" {
		return nil, invalid("this overlay was uploaded; upload a newer file instead")
	}
	body, tag, notModified, err := s.fetchBundle(ctx, row.Url, row.Etag)
	if err != nil {
		_ = s.checked(ctx, row.ID, "error", trimErr(err))
		return nil, invalid("could not fetch the overlay: %v", err)
	}
	if notModified {
		return &OverlayChange{Label: row.Label, DocVersion: row.DocVersion, Entries: int(row.Entries)}, s.checked(ctx, row.ID, "ok", "")
	}
	ch, err := s.accept(ctx, row, body, tag)
	if err != nil {
		_ = s.checked(ctx, row.ID, "error", trimErr(err))
		return nil, err
	}
	return ch, nil
}

func trimErr(err error) string {
	m := strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": ")
	if len(m) > 500 {
		m = m[:500]
	}
	return m
}

// RefreshDueOverlays refreshes the URL sources that have not been asked for a while (run from the server's timer).
func (s *Service) RefreshDueOverlays(ctx context.Context) {
	due, err := dbq.New(s.Pool).ListDueOverlayRefreshes(ctx, ptrTime(s.now().Add(-refreshEvery)))
	if err != nil {
		return
	}
	for _, d := range due {
		if ctx.Err() != nil {
			return
		}
		_, _ = s.RefreshOverlay(ctx, d.OrgID, d.ID) // the outcome is recorded on the source
	}
}

// UpdateOverlay changes a source's name, switch, priority and address.
func (s *Service) UpdateOverlay(ctx context.Context, org, id uuid.UUID, label string, enabled bool, priority int32, rawURL string) (*OverlaySource, error) {
	q := dbq.New(s.Pool)
	row, err := q.GetCatalogOverlay(ctx, dbq.GetCatalogOverlayParams{ID: id, OrgID: org})
	if err != nil {
		return nil, ErrNotFound
	}
	label, err = cleanLabel(label, row.Label)
	if err != nil {
		return nil, err
	}
	if priority < 1 || priority > 1000 {
		return nil, invalid("the priority must be 1 to 1000 (a lower number wins)")
	}
	link := row.Url
	if row.Kind == "url" {
		if link, err = cleanURL(rawURL); err != nil {
			return nil, err
		}
		if link == "" {
			return nil, invalid("a source that is fetched from the web needs its address")
		}
	}
	n, err := q.UpdateCatalogOverlaySettings(ctx, dbq.UpdateCatalogOverlaySettingsParams{ID: id, OrgID: org, Label: label, Enabled: enabled, Priority: priority, Url: link})
	if isUniqueViolation(err) {
		return nil, fmt.Errorf("%w: an overlay with that name already exists", ErrConflict)
	}
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrNotFound
	}
	if err := s.ReloadOverlays(ctx, org); err != nil {
		return nil, err
	}
	row, err = q.GetCatalogOverlay(ctx, dbq.GetCatalogOverlayParams{ID: id, OrgID: org})
	if err != nil {
		return nil, err
	}
	v := viewOverlay(row)
	return &v, nil
}

// DeleteOverlay removes a source; what it said about packages stops applying.
func (s *Service) DeleteOverlay(ctx context.Context, org, id uuid.UUID) (string, error) {
	q := dbq.New(s.Pool)
	row, err := q.GetCatalogOverlay(ctx, dbq.GetCatalogOverlayParams{ID: id, OrgID: org})
	if err != nil {
		return "", ErrNotFound
	}
	if _, err := q.DeleteCatalogOverlay(ctx, dbq.DeleteCatalogOverlayParams{ID: id, OrgID: org}); err != nil {
		return "", err
	}
	return row.Label, s.ReloadOverlays(ctx, org)
}

// LoadOverlays reads every organization's overlays into memory (at start-up) and applies them to the catalog.
func (s *Service) LoadOverlays(ctx context.Context) error {
	rows, err := dbq.New(s.Pool).ListEnabledCatalogOverlays(ctx)
	if err != nil {
		return err
	}
	seen := map[uuid.UUID]bool{}
	for _, r := range rows {
		if !seen[r.OrgID] {
			seen[r.OrgID] = true
			if err := s.ReloadOverlays(ctx, r.OrgID); err != nil {
				return err
			}
		}
	}
	return nil
}

// ReloadOverlays rebuilds one organization's in-memory overlay entries from its enabled sources (the source with the lowest
// priority number wins for a package) and applies them to the catalog's packages.
func (s *Service) ReloadOverlays(ctx context.Context, org uuid.UUID) error {
	rows, err := dbq.New(s.Pool).ListCatalogOverlays(ctx, org)
	if err != nil {
		return err
	}
	m := map[string]OverlayEntry{}
	for _, r := range rows {
		if !r.Enabled || len(r.Document) == 0 {
			continue
		}
		doc, err := overlay.ParseDocument(r.Document)
		if err != nil {
			continue // a stored document that no longer parses is skipped, not allowed to break the others
		}
		for _, e := range doc.Packages {
			key := strings.ToLower(strings.TrimSpace(e.Identifier))
			if _, taken := m[key]; taken {
				continue
			}
			oe := OverlayEntry{Identifier: e.Identifier, Note: e.Note, Source: r.Label, Verified: e.Verified, VerifiedNote: e.VerifiedNote, SilentArgs: e.SilentArgs}
			if e.SelfUpdating != nil {
				oe.SelfUpdating, oe.SelfUpdatingSet = *e.SelfUpdating, true
			}
			if len(e.ExtraDetection) > 0 {
				_ = json.Unmarshal(e.ExtraDetection, &oe.ExtraDetection)
			}
			m[key] = oe
		}
	}
	s.overlay().SetOrg(org, m)
	return s.ApplyOverlayState(ctx, org)
}

// overlayState is what the overlays say about one package: whether it updates itself and which overlay vouches for it.
func (s *Service) overlayState(org uuid.UUID, identifier string) (self bool, vouch string, tests bool) {
	o := s.overlay()
	tests = o.Verified(identifier, "")
	if e, ok := o.EntryFor(org, identifier); ok {
		self = e.SelfUpdating
		if e.Verified {
			vouch = e.Source
		}
	}
	return self, vouch, tests
}

// ApplyOverlayState sets, for every winget package of the organization, the self-updating flag and the overlay verification
// that the overlays now say.
func (s *Service) ApplyOverlayState(ctx context.Context, org uuid.UUID) error {
	q := dbq.New(s.Pool)
	pkgs, err := q.ListPackageOverlayState(ctx, org)
	if err != nil {
		return err
	}
	for _, p := range pkgs {
		self, vouch, tests := s.overlayState(org, p.Identifier)
		verified := tests || p.VerifiedByOrg || vouch != ""
		if self == p.SelfUpdating && vouch == p.VerifiedByOverlay && verified == p.Verified {
			continue
		}
		if err := q.SetPackageOverlayState(ctx, dbq.SetPackageOverlayStateParams{OrgID: org, ID: p.ID, SelfUpdating: self, Overlay: vouch, TestsPassed: tests}); err != nil {
			return err
		}
	}
	return nil
}

// ---- fetching ----

// refuseLocal stops the server from being used to reach itself or the cloud metadata address through an overlay URL.
func refuseLocal(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()) {
		return errors.New("addresses on this server itself and link-local addresses are not allowed")
	}
	return nil
}

func defaultOverlayClient() *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, Control: refuseLocal}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{DialContext: d.DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second, DisableKeepAlives: true},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

// fetchBundle downloads a signed overlay. It returns notModified when the server answers 304 to the stored ETag. The body is
// capped; the signature, not the transport, is what makes the content trusted.
func (s *Service) fetchBundle(ctx context.Context, link, etag string) (body []byte, newTag string, notModified bool, err error) {
	c := s.HTTP
	if c == nil {
		c = defaultOverlayClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return nil, "", false, err
	}
	req.Header.Set("User-Agent", "librepatch-overlay")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, "", false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotModified {
		return nil, etag, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", false, fmt.Errorf("the server answered %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, overlay.MaxBundleBytes+1))
	if err != nil {
		return nil, "", false, err
	}
	if len(b) > overlay.MaxBundleBytes {
		return nil, "", false, fmt.Errorf("the file is larger than %d bytes", overlay.MaxBundleBytes)
	}
	tag := resp.Header.Get("ETag")
	if len(tag) > 200 {
		tag = ""
	}
	return b, tag, false, nil
}

// ---- starting an overlay from what the administrator already set ----

// Template builds an unsigned overlay document from what this organization has already set by hand: the silent arguments and
// detection rules of its package overrides, and the packages an administrator marked verified. It is the quickest way to
// write the first overlay: save it, edit it, sign it with librepatch-release.
func (s *Service) Template(ctx context.Context, org uuid.UUID, orgName string) (*overlay.Document, error) {
	q := dbq.New(s.Pool)
	pkgs, err := q.ListPackageOverlayState(ctx, org)
	if err != nil {
		return nil, err
	}
	doc := &overlay.Document{Format: overlay.DocumentFormat, Name: strings.TrimSpace(orgName + " overlay"), Version: 1, IssuedAt: s.now().UTC().Format(time.RFC3339), Packages: []overlay.Entry{}}
	if doc.Name == "overlay" || doc.Name == "" {
		doc.Name = "My overlay"
	}
	for _, p := range pkgs {
		ov, err := q.GetPackageOverride(ctx, dbq.GetPackageOverrideParams{OrgID: org, PackageID: p.ID})
		hasOv := err == nil && (len(ov.SilentArgs) > 0 || string(ov.ExtraDetection) != "" && string(ov.ExtraDetection) != "[]" && string(ov.ExtraDetection) != "null")
		if !hasOv && !p.VerifiedByOrg {
			continue
		}
		e := overlay.Entry{Identifier: p.Identifier}
		if hasOv {
			e.SilentArgs = ov.SilentArgs
			if d := strings.TrimSpace(string(ov.ExtraDetection)); d != "" && d != "[]" && d != "null" {
				e.ExtraDetection = json.RawMessage(ov.ExtraDetection)
			}
		}
		if p.VerifiedByOrg {
			e.Verified = true
		}
		if p.SelfUpdating {
			t := true
			e.SelfUpdating = &t
		}
		doc.Packages = append(doc.Packages, e)
	}
	return doc, nil
}
