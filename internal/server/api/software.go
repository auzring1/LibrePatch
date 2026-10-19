package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

// queryText reads a free-text search parameter: trimmed, lower-cased, bounded.
func queryText(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(r.URL.Query().Get(name)))
	if len(v) > 200 || strings.ContainsRune(v, 0) {
		badRequest(w, name+" must be at most 200 characters")
		return "", false
	}
	return v, true
}

type titleView struct {
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"name"`
	Publisher    string    `json:"publisher"`
	DeviceCount  int32     `json:"device_count"`
	VersionCount int32     `json:"version_count"`
}

// searchSoftware lists products across the fleet: GET /software?q=&include_system=
func (s *server) searchSoftware(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := paging(w, r, 50, 200)
	if !ok {
		return
	}
	q, ok := queryText(w, r, "q")
	if !ok {
		return
	}
	org := principalFrom(r).OrgID
	var rows []dbq.SearchSoftwareTitlesRow
	var err error
	if r.URL.Query().Get("include_system") == "true" {
		rows, err = s.q().SearchSoftwareTitles(r.Context(), dbq.SearchSoftwareTitlesParams{OrgID: org, IncludeSystem: true, Q: q, RowLimit: limit, RowOffset: offset})
	} else {
		var plain []dbq.SearchSoftwareTitlesNoSystemRow
		plain, err = s.q().SearchSoftwareTitlesNoSystem(r.Context(), dbq.SearchSoftwareTitlesNoSystemParams{OrgID: org, Q: q, RowLimit: limit, RowOffset: offset})
		for _, p := range plain {
			rows = append(rows, dbq.SearchSoftwareTitlesRow(p))
		}
	}
	if err != nil {
		s.Log.Error("search software", "err", err)
		internalError(w)
		return
	}
	items, total := make([]titleView, 0, len(rows)), int64(0)
	for _, t := range rows {
		total = t.Total
		items = append(items, titleView{ID: t.ID, Name: t.DisplayName, Publisher: t.DisplayPublisher,
			DeviceCount: t.DeviceCount, VersionCount: t.VersionCount})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func (s *server) titleFromURL(w http.ResponseWriter, r *http.Request) (dbq.SoftwareTitle, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Software not found.")
		return dbq.SoftwareTitle{}, false
	}
	t, err := s.q().GetSoftwareTitle(r.Context(), dbq.GetSoftwareTitleParams{ID: id, OrgID: principalFrom(r).OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "not_found", "Software not found.")
		return t, false
	} else if err != nil {
		internalError(w)
		return t, false
	}
	return t, true
}

// getSoftware returns one product and its versions: GET /software/{id}
func (s *server) getSoftware(w http.ResponseWriter, r *http.Request) {
	t, ok := s.titleFromURL(w, r)
	if !ok {
		return
	}
	vers, err := s.q().ListTitleVersions(r.Context(), dbq.ListTitleVersionsParams{TitleID: t.ID, OrgID: t.OrgID})
	if err != nil {
		internalError(w)
		return
	}
	type verView struct {
		Version     string `json:"version"`
		DeviceCount int32  `json:"device_count"`
	}
	vv := make([]verView, 0, len(vers))
	for _, v := range vers {
		vv = append(vv, verView{Version: v.Version, DeviceCount: v.DeviceCount})
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": t.ID, "name": t.DisplayName, "publisher": t.DisplayPublisher,
		"versions": vv})
}

// titleInstalls lists the devices that have a product:
// GET /software/{id}/installs?version=&older_than=
func (s *server) titleInstalls(w http.ResponseWriter, r *http.Request) {
	t, ok := s.titleFromURL(w, r)
	if !ok {
		return
	}
	limit, offset, ok := paging(w, r, 100, 500)
	if !ok {
		return
	}
	// An exact, case-sensitive match on the stored version string.
	version := strings.TrimSpace(r.URL.Query().Get("version"))
	if len(version) > 128 || strings.ContainsRune(version, 0) {
		badRequest(w, "version is too long")
		return
	}
	var olderThan []byte
	if v := strings.TrimSpace(r.URL.Query().Get("older_than")); v != "" {
		if len(v) > 128 {
			badRequest(w, "older_than is too long")
			return
		}
		if olderThan = vercmp.Key(v); olderThan == nil {
			badRequest(w, "older_than is not a comparable version")
			return
		}
	}
	rows, err := s.q().ListTitleInstalls(r.Context(), dbq.ListTitleInstallsParams{TitleID: t.ID, OrgID: t.OrgID,
		Version: version, OlderThan: olderThan, RowLimit: limit, RowOffset: offset})
	if err != nil {
		s.Log.Error("title installs", "err", err)
		internalError(w)
		return
	}
	type view struct {
		DeviceID        uuid.UUID `json:"device_id"`
		Hostname        string    `json:"hostname"`
		Online          bool      `json:"online"`
		Version         string    `json:"version"`
		Scope           string    `json:"scope"`
		UserSID         string    `json:"user_sid"`
		Source          string    `json:"source"`
		InstallDate     string    `json:"install_date"`
		InstallLocation string    `json:"install_location"`
		LastSeenAt      time.Time `json:"last_seen_at"`
	}
	items, total := make([]view, 0, len(rows)), int64(0)
	for _, x := range rows {
		total = x.Total
		items = append(items, view{x.DeviceID, x.Hostname, x.Online, x.Version, x.Scope, x.UserSid, x.Source,
			x.InstallDate, x.InstallLocation, x.LastSeenAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

// deviceSoftware: GET /devices/{id}/software?include_system=
func (s *server) deviceSoftware(w http.ResponseWriter, r *http.Request) {
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	rows, err := s.q().ListDeviceSoftware(r.Context(), dbq.ListDeviceSoftwareParams{DeviceID: d.ID,
		IncludeSystem: r.URL.Query().Get("include_system") == "true"})
	if err != nil {
		s.Log.Error("device software", "err", err)
		internalError(w)
		return
	}
	type view struct {
		TitleID         uuid.UUID `json:"title_id"`
		Name            string    `json:"name"`
		Version         string    `json:"version"`
		Publisher       string    `json:"publisher"`
		Source          string    `json:"source"`
		Scope           string    `json:"scope"`
		UserSID         string    `json:"user_sid"`
		ItemKey         string    `json:"item_key"`
		InstallDate     string    `json:"install_date"`
		InstallLocation string    `json:"install_location"`
		ProductCode     string    `json:"product_code"`
		SystemComponent bool      `json:"system_component"`
		FirstSeenAt     time.Time `json:"first_seen_at"`
		LastSeenAt      time.Time `json:"last_seen_at"`
	}
	items := make([]view, 0, len(rows))
	for _, x := range rows {
		items = append(items, view{x.TitleID, x.Name, x.Version, x.Publisher, x.Source, x.Scope, x.UserSid, x.ItemKey, x.InstallDate,
			x.InstallLocation, x.ProductCode, x.SystemComponent, x.FirstSeenAt, x.LastSeenAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items), "revision": d.SoftwareRev,
		"updated_at": d.SoftwareUpdatedAt, "truncated": d.InventoryTruncated})
}

// deviceSoftwareHistory: GET /devices/{id}/software/history?before=<id>
func (s *server) deviceSoftwareHistory(w http.ResponseWriter, r *http.Request) {
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	limit, _, ok := paging(w, r, 100, 500)
	if !ok {
		return
	}
	var before int64
	if v := r.URL.Query().Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			badRequest(w, "before must be a non-negative integer")
			return
		}
		before = n
	}
	rows, err := s.q().ListDeviceSoftwareHistory(r.Context(), dbq.ListDeviceSoftwareHistoryParams{DeviceID: d.ID,
		BeforeID: before, RowLimit: limit})
	if err != nil {
		internalError(w)
		return
	}
	type view struct {
		ID         int64     `json:"id"`
		Name       string    `json:"name"`
		Scope      string    `json:"scope"`
		UserSID    string    `json:"user_sid"`
		Change     string    `json:"change"`
		OldVersion string    `json:"old_version"`
		NewVersion string    `json:"new_version"`
		ObservedAt time.Time `json:"observed_at"`
	}
	items := make([]view, 0, len(rows))
	for _, x := range rows {
		items = append(items, view{x.ID, x.Name, x.Scope, x.UserSid, x.Change, x.OldVersion, x.NewVersion, x.ObservedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// deviceUsers: GET /devices/{id}/users
func (s *server) deviceUsers(w http.ResponseWriter, r *http.Request) {
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	rows, err := s.q().ListDeviceUsers(r.Context(), d.ID)
	if err != nil {
		internalError(w)
		return
	}
	type view struct {
		SID         string     `json:"sid"`
		Username    string     `json:"username"`
		Domain      string     `json:"domain"`
		ProfilePath string     `json:"profile_path"`
		LastLogonAt *time.Time `json:"last_logon_at"`
		Loaded      bool       `json:"loaded"`
		IsAdmin     bool       `json:"is_admin"`
	}
	items := make([]view, 0, len(rows))
	for _, x := range rows {
		items = append(items, view{x.Sid, x.Username, x.Domain, x.ProfilePath, x.LastLogonAt, x.Loaded, x.IsAdmin})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
