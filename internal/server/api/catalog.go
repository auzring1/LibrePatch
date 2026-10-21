package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/catalog"
	"github.com/auzring1/librepatch/internal/server/wingetindex"
)

// maxUpload bounds one uploaded installer.
const maxUpload = 2 << 30

type packageView struct {
	ID          uuid.UUID `json:"id"`
	Source      string    `json:"source"`
	Identifier  string    `json:"identifier"`
	Name        string    `json:"name"`
	Publisher   string    `json:"publisher"`
	Homepage    string    `json:"homepage"`
	License     string    `json:"license"`
	Description string    `json:"description"`
	Verified    bool      `json:"verified"`
	// VerifiedSource says why the package counts as verified: "tests" (it passed the VM test matrix) or "organization" (an
	// administrator marked it after testing it); empty when it is not verified.
	VerifiedSource string `json:"verified_source"`
	// VerifiedBy names the overlay that vouches for the package when VerifiedSource is "overlay".
	VerifiedBy   string    `json:"verified_by,omitempty"`
	SelfUpdating bool      `json:"self_updating"`
	ImportedAt   time.Time `json:"imported_at"`
	VersionCount int32     `json:"version_count"`
}

func verifiedSourceOf(verified, byOrg bool, byOverlay string) string {
	switch {
	case byOrg:
		return "organization"
	case byOverlay != "":
		return "overlay"
	case verified:
		return "tests"
	}
	return ""
}

func viewPackage(p dbq.CatalogPackage, versions int32) packageView {
	return packageView{VerifiedSource: verifiedSourceOf(p.Verified, p.VerifiedByOrg, p.VerifiedByOverlay), VerifiedBy: p.VerifiedByOverlay, ID: p.ID, Source: p.Source, Identifier: p.Identifier, Name: p.Name, Publisher: p.Publisher, Homepage: p.Homepage,
		License: p.License, Description: p.Description, Verified: p.Verified, SelfUpdating: p.SelfUpdating, ImportedAt: p.ImportedAt, VersionCount: versions}
}

func (s *server) catalogSvc(w http.ResponseWriter) bool {
	if s.Catalog == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "The catalog is not available.")
		return false
	}
	return true
}

func (s *server) listPackages(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := paging(w, r, 100, 500)
	if !ok {
		return
	}
	q, ok := queryText(w, r, "q")
	if !ok {
		return
	}
	rows, err := s.q().ListCatalogPackages(r.Context(), dbq.ListCatalogPackagesParams{OrgID: principalFrom(r).OrgID, Q: q, RowLimit: limit, RowOffset: offset})
	if err != nil {
		s.Log.Error("list packages", "err", err)
		internalError(w)
		return
	}
	items := make([]packageView, 0, len(rows))
	for _, p := range rows {
		items = append(items, packageView{ID: p.ID, Source: p.Source, Identifier: p.Identifier, Name: p.Name, Publisher: p.Publisher,
			Homepage: p.Homepage, License: p.License, Description: p.Description, Verified: p.Verified, VerifiedSource: verifiedSourceOf(p.Verified, p.VerifiedByOrg, p.VerifiedByOverlay), SelfUpdating: p.SelfUpdating,
			ImportedAt: p.ImportedAt, VersionCount: p.VersionCount})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type suggestionView struct {
	Identifier   string `json:"identifier"`
	SelfUpdating bool   `json:"self_updating"`
	Note         string `json:"note,omitempty"`
}

// searchCatalog: GET /catalog/search?q= — imported packages, known suggestions,
// and (for something that looks like a winget identifier) the versions upstream.
func (s *server) searchCatalog(w http.ResponseWriter, r *http.Request) {
	if !s.catalogSvc(w) {
		return
	}
	q, ok := queryText(w, r, "q")
	if !ok || q == "" {
		if ok {
			badRequest(w, "q is required")
		}
		return
	}
	p := principalFrom(r)
	rows, err := s.q().ListCatalogPackages(r.Context(), dbq.ListCatalogPackagesParams{OrgID: p.OrgID, Q: q, RowLimit: 20, RowOffset: 0})
	if err != nil {
		internalError(w)
		return
	}
	imported := make([]packageView, 0, len(rows))
	have := map[string]bool{}
	for _, x := range rows {
		have[strings.ToLower(x.Identifier)] = true
		imported = append(imported, packageView{ID: x.ID, Source: x.Source, Identifier: x.Identifier, Name: x.Name, Publisher: x.Publisher,
			Verified: x.Verified, VerifiedSource: verifiedSourceOf(x.Verified, x.VerifiedByOrg, x.VerifiedByOverlay), VerifiedBy: x.VerifiedByOverlay, SelfUpdating: x.SelfUpdating, ImportedAt: x.ImportedAt, VersionCount: x.VersionCount})
	}
	sugg := []suggestionView{}
	for _, e := range s.Catalog.Overlay.KnownFor(principalFrom(r).OrgID) {
		if strings.Contains(strings.ToLower(e.Identifier), q) && !have[strings.ToLower(e.Identifier)] {
			sugg = append(sugg, suggestionView{Identifier: e.Identifier, SelfUpdating: e.SelfUpdating, Note: e.Note})
		}
	}
	out := map[string]any{"imported": imported, "suggestions": sugg}
	// Packages of the winget index that match the words typed (by name, identifier or moniker).
	if m := s.Winget.Matcher(); m != nil {
		type indexHit struct {
			Identifier    string `json:"identifier"`
			Name          string `json:"name"`
			LatestVersion string `json:"latest_version"`
			InCatalog     bool   `json:"in_catalog"`
		}
		hits := []indexHit{}
		for _, p := range m.Search(q, 15) {
			hits = append(hits, indexHit{Identifier: p.ID, Name: p.Name, LatestVersion: p.LatestVersion, InCatalog: have[strings.ToLower(p.ID)]})
		}
		out["index"] = hits
	}
	// An exact identifier is looked up upstream so it can be imported.
	if ident := strings.TrimSpace(r.URL.Query().Get("q")); catalog.ValidIdentifier(ident) && s.Catalog.Source != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		probe := map[string]any{"identifier": ident}
		if vs, err := s.Catalog.Source.Versions(ctx, ident); err != nil {
			if errors.Is(err, catalog.ErrNotFound) {
				probe["error"] = "not found in the winget repository"
			} else {
				probe["error"] = err.Error()
			}
		} else {
			if len(vs) > 30 {
				vs = vs[:30]
			}
			probe["versions"] = vs
		}
		out["probe"] = probe
	}
	writeJSON(w, http.StatusOK, out)
}

type importReq struct {
	Identifier string `json:"identifier"`
	Version    string `json:"version"`
}

func (s *server) importPackage(w http.ResponseWriter, r *http.Request) {
	if !s.catalogSvc(w) {
		return
	}
	var req importReq
	if !decode(w, r, &req) {
		return
	}
	p := principalFrom(r)
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	res, err := s.Catalog.Import(ctx, p.OrgID, p.UserID, strings.TrimSpace(req.Identifier), strings.TrimSpace(req.Version))
	switch {
	case errors.Is(err, catalog.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "That package or version was not found in the winget repository.")
		return
	case errors.Is(err, catalog.ErrInvalid), errors.Is(err, catalog.ErrManifest):
		writeError(w, http.StatusUnprocessableEntity, "invalid_package", strings.TrimPrefix(strings.TrimPrefix(err.Error(), catalog.ErrInvalid.Error()+": "), catalog.ErrManifest.Error()+": "))
		return
	case err != nil:
		s.Log.Warn("catalog import", "identifier", req.Identifier, "err", err)
		writeError(w, http.StatusBadGateway, "import_failed", "The package could not be imported: "+err.Error())
		return
	}
	_ = audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r),
		Action: "catalog.import", TargetType: "package", TargetIDs: []string{res.PackageID.String()}, Outcome: audit.Success,
		Details: map[string]any{"identifier": res.Identifier, "version": res.Version, "installers": res.Installers, "deployable": res.Deployable}})
	writeJSON(w, http.StatusCreated, res)
}

type installerView struct {
	ID            uuid.UUID           `json:"id"`
	Architecture  string              `json:"architecture"`
	Scope         string              `json:"scope"`
	Type          string              `json:"type"`
	NestedType    string              `json:"nested_type"`
	URL           string              `json:"url"`
	SHA256        string              `json:"sha256"`
	Size          int64               `json:"size"`
	FileName      string              `json:"file_name"`
	ProductCode   string              `json:"product_code"`
	SignerSubject string              `json:"signer_subject"`
	Silent        []string            `json:"silent_args"`
	Custom        []string            `json:"custom_args"`
	Detection     []catalog.Detection `json:"detection"`
	Unsupported   string              `json:"unsupported"`
	ServerContent bool                `json:"server_content"`
}

type versionView struct {
	ID         uuid.UUID       `json:"id"`
	Version    string          `json:"version"`
	ImportedAt time.Time       `json:"imported_at"`
	Installers []installerView `json:"installers"`
}

func (s *server) packageFromURL(w http.ResponseWriter, r *http.Request) (dbq.CatalogPackage, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Package not found.")
		return dbq.CatalogPackage{}, false
	}
	p, err := s.q().GetCatalogPackage(r.Context(), dbq.GetCatalogPackageParams{ID: id, OrgID: principalFrom(r).OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "not_found", "Package not found.")
		return p, false
	} else if err != nil {
		internalError(w)
		return p, false
	}
	return p, true
}

func (s *server) getPackage(w http.ResponseWriter, r *http.Request) {
	pkg, ok := s.packageFromURL(w, r)
	if !ok {
		return
	}
	q := s.q()
	vs, err := q.ListPackageVersions(r.Context(), pkg.ID)
	if err != nil {
		internalError(w)
		return
	}
	views := make([]versionView, 0, len(vs))
	for _, v := range vs {
		ins, err := q.ListVersionInstallers(r.Context(), v.ID)
		if err != nil {
			internalError(w)
			return
		}
		vv := versionView{ID: v.ID, Version: v.Version, ImportedAt: v.ImportedAt, Installers: make([]installerView, 0, len(ins))}
		for _, i := range ins {
			var sw struct {
				Silent []string `json:"silent"`
				Custom []string `json:"custom"`
			}
			_ = json.Unmarshal(i.Switches, &sw)
			var det []catalog.Detection
			_ = json.Unmarshal(i.Detection, &det)
			vv.Installers = append(vv.Installers, installerView{ID: i.ID, Architecture: i.Architecture, Scope: i.Scope, Type: i.InstallerType,
				NestedType: i.NestedType, URL: i.Url, SHA256: hex.EncodeToString(i.Sha256), Size: i.Size, FileName: i.FileName,
				ProductCode: i.ProductCode, SignerSubject: i.SignerSubject, Silent: nzs(sw.Silent), Custom: nzs(sw.Custom),
				Detection: nzdet(det), Unsupported: i.Unsupported, ServerContent: i.UsesContentBlob})
		}
		views = append(views, vv)
	}
	type ovView struct {
		SilentArgs      []string            `json:"silent_args"`
		ExtraDetection  []catalog.Detection `json:"extra_detection"`
		Pin             string              `json:"pin"`
		Excluded        bool                `json:"excluded"`
		UserScopePolicy string              `json:"user_scope_policy"`
		SelfUpdate      string              `json:"self_update_policy"`
		Processes       []string            `json:"processes"`
	}
	ov := ovView{SilentArgs: []string{}, ExtraDetection: []catalog.Detection{}, Processes: []string{}}
	if o, err := q.GetPackageOverride(r.Context(), dbq.GetPackageOverrideParams{OrgID: pkg.OrgID, PackageID: pkg.ID}); err == nil {
		var det []catalog.Detection
		_ = json.Unmarshal(o.ExtraDetection, &det)
		ov = ovView{SilentArgs: nzs(o.SilentArgs), ExtraDetection: nzdet(det), Pin: o.Pin, Excluded: o.Excluded, UserScopePolicy: o.UserScopePolicy, SelfUpdate: o.SelfUpdatePolicy, Processes: nzs(o.Processes)}
	}
	orgPolicy := "report_only"
	if os, err := q.GetOrgSettings(r.Context(), pkg.OrgID); err == nil {
		orgPolicy = os.UserScopePolicy
	}
	effective, from := orgPolicy, "organization default"
	if ov.UserScopePolicy != "" {
		effective, from = ov.UserScopePolicy, "this package"
	}
	// Who vouched for the package, when, and for which version (an administrator's mark).
	type verView struct {
		By      string     `json:"by,omitempty"`
		At      *time.Time `json:"at,omitempty"`
		Version string     `json:"version,omitempty"`
	}
	var ver *verView
	if pkg.VerifiedByOrg {
		ver = &verView{At: pkg.VerifiedAt, Version: pkg.VerifiedVersion}
		if pkg.VerifiedBy != nil {
			if u, err := q.GetUserInOrg(r.Context(), dbq.GetUserInOrgParams{ID: *pkg.VerifiedBy, OrgID: pkg.OrgID}); err == nil {
				ver.By = u.DisplayName
			}
		}
	}
	// What a signed overlay says about the package (D122); null when none does.
	type overlayView struct {
		Source         string   `json:"source"`
		Note           string   `json:"note"`
		SelfUpdating   *bool    `json:"self_updating"`
		Verified       bool     `json:"verified"`
		VerifiedNote   string   `json:"verified_note"`
		SilentArgs     []string `json:"silent_args"`
		DetectionRules int      `json:"detection_rules"`
		Processes      []string `json:"processes"`
	}
	var ovl *overlayView
	if s.Catalog != nil && s.Catalog.Overlay != nil {
		if e, ok := s.Catalog.Overlay.EntryFor(pkg.OrgID, pkg.Identifier); ok && e.Source != "" {
			ovl = &overlayView{Source: e.Source, Note: e.Note, Verified: e.Verified, VerifiedNote: e.VerifiedNote, SilentArgs: nzs(e.SilentArgs), DetectionRules: len(e.ExtraDetection), Processes: nzs(e.Processes)}
			if e.SelfUpdatingSet {
				v := e.SelfUpdating
				ovl.SelfUpdating = &v
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"package": viewPackage(pkg, int32(len(vs))), "versions": views, "override": ov, // #nosec G115 -- small
		"effective_user_scope_policy": effective, "effective_user_scope_policy_source": from, "verification": ver, "overlay": ovl})
}

func nzs(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nzdet(d []catalog.Detection) []catalog.Detection {
	if d == nil {
		return []catalog.Detection{}
	}
	return d
}

func (s *server) putOverrides(w http.ResponseWriter, r *http.Request) {
	if !s.catalogSvc(w) {
		return
	}
	pkg, ok := s.packageFromURL(w, r)
	if !ok {
		return
	}
	var o catalog.Override
	if !decode(w, r, &o) {
		return
	}
	p := principalFrom(r)
	if err := s.Catalog.SetOverride(r.Context(), p.OrgID, p.UserID, pkg.ID, o); err != nil {
		if errors.Is(err, catalog.ErrInvalid) {
			writeError(w, http.StatusUnprocessableEntity, "invalid_override", strings.TrimPrefix(err.Error(), catalog.ErrInvalid.Error()+": "))
			return
		}
		internalError(w)
		return
	}
	_ = audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r),
		Action: "catalog.override", TargetType: "package", TargetIDs: []string{pkg.ID.String()}, Outcome: audit.Success,
		Details: map[string]any{"identifier": pkg.Identifier, "silent_args": o.SilentArgs, "pin": o.Pin, "excluded": o.Excluded,
			"user_scope_policy": o.UserScopePolicy, "extra_detection_rules": len(o.ExtraDetection)}})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) deletePackage(w http.ResponseWriter, r *http.Request) {
	pkg, ok := s.packageFromURL(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	n, err := s.q().DeleteCatalogPackage(r.Context(), dbq.DeleteCatalogPackageParams{ID: pkg.ID, OrgID: p.OrgID})
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23503" {
		writeError(w, http.StatusConflict, "in_use", "This package is used by a deployment and cannot be removed.")
		return
	} else if err != nil || n == 0 {
		internalError(w)
		return
	}
	_ = audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r),
		Action: "catalog.remove", TargetType: "package", TargetIDs: []string{pkg.ID.String()}, Outcome: audit.Success, Details: map[string]any{"identifier": pkg.Identifier}})
	w.WriteHeader(http.StatusNoContent)
}

// uploadContent: POST /catalog/content — the installer file as the raw request body.
func (s *server) uploadContent(w http.ResponseWriter, r *http.Request) {
	if !s.catalogSvc(w) {
		return
	}
	if s.Catalog.Content == nil {
		writeError(w, http.StatusServiceUnavailable, "no_storage", "Custom packages are disabled: LIBREPATCH_CONTENT_DIR is not set.")
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/octet-stream") {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Send the file as application/octet-stream.")
		return
	}
	name := strings.TrimSpace(r.Header.Get("X-File-Name"))
	if len(name) == 0 || len(name) > 128 || strings.ContainsAny(name, `/\:`) || strings.Contains(name, "..") {
		badRequest(w, "X-File-Name must be a plain file name")
		return
	}
	// A large installer outlives the server's default request timeouts.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(45 * time.Minute))
	_ = rc.SetWriteDeadline(time.Now().Add(46 * time.Minute))
	p := principalFrom(r)
	sha, size, err := s.Catalog.Content.Put(p.OrgID, http.MaxBytesReader(w, r.Body, maxUpload), maxUpload)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.Is(err, catalog.ErrTooLarge) || errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "The file is larger than 2 GiB.")
			return
		}
		s.Log.Warn("content upload", "err", err)
		badRequest(w, "The upload failed: "+err.Error())
		return
	}
	if err := s.q().InsertContentBlob(r.Context(), dbq.InsertContentBlobParams{OrgID: p.OrgID, Sha256: sha, Size: size, FileName: name, UploadedBy: &p.UserID}); err != nil {
		internalError(w)
		return
	}
	_ = audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r),
		Action: "catalog.upload", TargetType: "content", TargetIDs: []string{hex.EncodeToString(sha)}, Outcome: audit.Success,
		Details: map[string]any{"file_name": name, "size": size}})
	writeJSON(w, http.StatusCreated, map[string]any{"sha256": hex.EncodeToString(sha), "size": size, "file_name": name})
}

func (s *server) createCustom(w http.ResponseWriter, r *http.Request) {
	if !s.catalogSvc(w) {
		return
	}
	var c catalog.CustomSpec
	if !decode(w, r, &c) {
		return
	}
	p := principalFrom(r)
	res, err := s.Catalog.AddCustom(r.Context(), p.OrgID, p.UserID, c)
	if errors.Is(err, catalog.ErrInvalid) {
		writeError(w, http.StatusUnprocessableEntity, "invalid_package", strings.TrimPrefix(err.Error(), catalog.ErrInvalid.Error()+": "))
		return
	} else if err != nil {
		s.Log.Error("custom package", "err", err)
		internalError(w)
		return
	}
	_ = audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r),
		Action: "catalog.custom", TargetType: "package", TargetIDs: []string{res.PackageID.String()}, Outcome: audit.Success,
		Details: map[string]any{"identifier": res.Identifier, "version": res.Version, "sha256": c.SHA256}})
	writeJSON(w, http.StatusCreated, res)
}

// ---- organization settings ----

func (s *server) getSettings(w http.ResponseWriter, r *http.Request) {
	pol := "report_only"
	if os, err := s.q().GetOrgSettings(r.Context(), principalFrom(r).OrgID); err == nil {
		pol = os.UserScopePolicy
	}
	writeJSON(w, http.StatusOK, map[string]any{"user_scope_policy": pol})
}

func (s *server) putSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserScopePolicy string `json:"user_scope_policy"`
	}
	if !decode(w, r, &req) {
		return
	}
	ok := false
	for _, v := range catalog.UserPolicies {
		ok = ok || v == req.UserScopePolicy
	}
	if !ok {
		badRequest(w, "user_scope_policy must be one of "+strings.Join(catalog.UserPolicies, ", "))
		return
	}
	p := principalFrom(r)
	if err := s.q().UpsertOrgSettings(r.Context(), dbq.UpsertOrgSettingsParams{OrgID: p.OrgID, UserScopePolicy: req.UserScopePolicy}); err != nil {
		internalError(w)
		return
	}
	_ = audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r),
		Action: "settings.update", TargetType: "organization", TargetIDs: []string{p.OrgID.String()}, Outcome: audit.Success,
		Details: map[string]any{"user_scope_policy": req.UserScopePolicy}})
	w.WriteHeader(http.StatusNoContent)
}

// GET /catalog/index: how recent the winget index is.
func (s *server) wingetIndexStatus(w http.ResponseWriter, r *http.Request) {
	if s.Winget == nil {
		writeJSON(w, http.StatusOK, wingetindex.Status{Enabled: false})
		return
	}
	st, err := s.Winget.Status(r.Context())
	if err != nil {
		s.Log.Error("winget index status", "err", err)
		internalError(w)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// POST /catalog/index/refresh: download the index now.
func (s *server) refreshWingetIndex(w http.ResponseWriter, r *http.Request) {
	if s.Winget == nil {
		writeError(w, http.StatusConflict, "winget_off", "The winget source is turned off on this server (LIBREPATCH_WINGET_SOURCE).")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	updated, err := s.Winget.Refresh(ctx, true)
	p := principalFrom(r)
	outcome := audit.Success
	if err != nil {
		outcome = audit.Error
	}
	_ = audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r),
		Action: "catalog.index_refresh", TargetType: "catalog", Outcome: outcome, Details: map[string]any{"updated": updated}})
	if err != nil {
		writeError(w, http.StatusBadGateway, "index_failed", "The winget index could not be downloaded: "+err.Error())
		return
	}
	st, _ := s.Winget.Status(r.Context())
	writeJSON(w, http.StatusOK, st)
}

// PUT /catalog/packages/{id}/verification: an administrator marks a winget package verified after testing it, or removes
// the mark. Verified packages deploy without the confirmation; the change is audited with its before and after.
func (s *server) setPackageVerification(w http.ResponseWriter, r *http.Request) {
	if !s.catalogSvc(w) {
		return
	}
	pkg, ok := s.packageFromURL(w, r)
	if !ok {
		return
	}
	var req struct {
		Verified bool `json:"verified"`
	}
	if !decode(w, r, &req) {
		return
	}
	p := principalFrom(r)
	ch, err := s.Catalog.SetOrgVerified(r.Context(), p.OrgID, p.UserID, pkg.ID, req.Verified)
	if err != nil {
		if errors.Is(err, catalog.ErrInvalid) {
			writeError(w, http.StatusUnprocessableEntity, "invalid_verification", strings.TrimPrefix(err.Error(), catalog.ErrInvalid.Error()+": "))
			return
		}
		s.Log.Error("package verification", "err", err)
		internalError(w)
		return
	}
	action := "catalog.verify"
	if !req.Verified {
		action = "catalog.unverify"
	}
	_ = audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r),
		Action: action, TargetType: "package", TargetIDs: []string{pkg.ID.String()}, Outcome: audit.Success,
		Details: map[string]any{"identifier": ch.Identifier, "version": ch.Version, "tests_passed": ch.TestsPassed,
			"before": map[string]any{"verified": ch.BeforeVerified, "by_organization": ch.BeforeByOrg}, "after": map[string]any{"verified": ch.AfterVerified, "by_organization": req.Verified}}})
	w.WriteHeader(http.StatusNoContent)
}
