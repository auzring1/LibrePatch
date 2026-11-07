package api

import (
	"encoding/csv"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/groups"
)

// maxExportRows bounds one CSV download.
const maxExportRows = 2_000_000

// CSVSafe neutralizes spreadsheet formula injection (OWASP "CSV Injection"):
// a cell starting with = + - @ tab or CR is prefixed with an apostrophe so
// Excel and LibreOffice treat it as text. Values come from endpoints and are
// untrusted.
func CSVSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func csvRow(cw *csv.Writer, cells ...string) error {
	out := make([]string, len(cells))
	for i, c := range cells {
		out[i] = CSVSafe(c)
	}
	return cw.Write(out)
}

// startCSV audits the export, then writes headers and the UTF-8 BOM Excel needs.
func (s *server) startCSV(w http.ResponseWriter, r *http.Request, kind string, details map[string]any) (*csv.Writer, bool) {
	p := principalFrom(r)
	details["kind"] = kind
	if err := audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(),
		ActorIP: clientIP(r), Action: "inventory.export", TargetType: "report", TargetIDs: []string{kind},
		Outcome: audit.Success, Details: details}); err != nil {
		s.Log.Error("audit export", "err", err)
		internalError(w)
		return nil, false
	}
	stamp := s.now().UTC().Format("20060102-150405")
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+brand.Slug+`-`+kind+`-`+stamp+`.csv"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("\xEF\xBB\xBF"))
	return csv.NewWriter(w), true
}

// softwareCSV: GET /reports/software.csv?q=&title_id= — every install on active devices.
func (s *server) softwareCSV(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	q, ok := queryText(w, r, "q")
	if !ok {
		return
	}
	var title *uuid.UUID
	if v := r.URL.Query().Get("title_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			badRequest(w, "title_id must be a UUID")
			return
		}
		title = &id
	}
	includeSystem := r.URL.Query().Get("include_system") == "true"
	rows, err := s.Pool.Query(r.Context(), `
		SELECT d.hostname, si.name, si.version, si.publisher, st.display_name, si.source, si.scope, si.user_sid,
		       COALESCE(du.username, ''), si.install_date, si.install_location, si.last_seen_at
		FROM software_installs si
		JOIN devices d ON d.id = si.device_id AND d.status = 'active'
		JOIN software_titles st ON st.id = si.title_id
		LEFT JOIN device_users du ON du.device_id = si.device_id AND du.sid = si.user_sid
		WHERE d.org_id = $1
		  AND ($2::uuid IS NULL OR si.title_id = $2)
		  AND ($3::text = '' OR strpos(st.normalized_name, $3) > 0 OR strpos(st.normalized_publisher, $3) > 0)
		  AND ($4::boolean OR NOT si.system_component)
		ORDER BY lower(d.hostname), d.id, lower(si.name), si.source, si.item_key
		LIMIT $5`, p.OrgID, title, q, includeSystem, maxExportRows)
	if err != nil {
		s.Log.Error("software export", "err", err)
		internalError(w)
		return
	}
	defer rows.Close()
	cw, ok := s.startCSV(w, r, "software", map[string]any{"q": q, "title_id": r.URL.Query().Get("title_id"), "include_system": includeSystem})
	if !ok {
		return
	}
	_ = csvRow(cw, "hostname", "name", "version", "publisher", "product", "source", "scope", "user_sid", "user", "install_date", "install_location", "last_seen")
	for rows.Next() {
		var host, name, ver, pub, product, src, scope, sid, user, date, loc string
		var seen time.Time
		if err := rows.Scan(&host, &name, &ver, &pub, &product, &src, &scope, &sid, &user, &date, &loc, &seen); err != nil {
			break
		}
		if csvRow(cw, host, name, ver, pub, product, src, scope, sid, user, date, loc, seen.UTC().Format(time.RFC3339)) != nil {
			return // client went away
		}
	}
	cw.Flush()
}

// devicesCSV: GET /reports/devices.csv?group_id= — devices (optionally one group's members).
func (s *server) devicesCSV(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	var filter *groups.Node
	if v := r.URL.Query().Get("group_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			badRequest(w, "group_id must be a UUID")
			return
		}
		g, err := s.q().GetGroup(r.Context(), dbq.GetGroupParams{ID: id, OrgID: p.OrgID})
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "Group not found.")
			return
		}
		if filter, err = groups.Parse(g.Filter); err != nil {
			writeFilterError(w, err)
			return
		}
	}
	type rec struct {
		host, os, build, chassis, maker, model, serial, user string
		online                                               bool
		seen                                                 *time.Time
		sw                                                   int32
	}
	var recs []rec
	if filter != nil {
		ms, _, err := groups.Evaluate(r.Context(), s.Pool, p.OrgID, filter, 100000, 0)
		if err != nil {
			s.Log.Error("devices export (group)", "err", err)
			internalError(w)
			return
		}
		for _, m := range ms {
			recs = append(recs, rec{host: m.Hostname, os: m.OSCaption, build: m.OSBuild, chassis: m.Chassis, maker: m.Manufacturer,
				model: m.Model, online: m.Online, seen: m.LastSeenAt, sw: m.SoftwareCount})
		}
	} else {
		rows, err := s.Pool.Query(r.Context(), `SELECT hostname, os_caption, os_build, chassis, manufacturer, model, serial,
			logged_on_user, online, last_seen_at, software_count FROM devices
			WHERE org_id = $1 AND status = 'active' ORDER BY lower(hostname), id LIMIT $2`, p.OrgID, maxExportRows)
		if err != nil {
			internalError(w)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var x rec
			if err := rows.Scan(&x.host, &x.os, &x.build, &x.chassis, &x.maker, &x.model, &x.serial, &x.user, &x.online, &x.seen, &x.sw); err != nil {
				internalError(w)
				return
			}
			recs = append(recs, x)
		}
	}
	cw, ok := s.startCSV(w, r, "devices", map[string]any{"group_id": r.URL.Query().Get("group_id")})
	if !ok {
		return
	}
	_ = csvRow(cw, "hostname", "os", "os_build", "chassis", "manufacturer", "model", "serial", "logged_on_user", "online", "last_seen", "software_count")
	for _, x := range recs {
		seen := ""
		if x.seen != nil {
			seen = x.seen.UTC().Format(time.RFC3339)
		}
		if csvRow(cw, x.host, x.os, x.build, x.chassis, x.maker, x.model, x.serial, x.user, strconv.FormatBool(x.online), seen, strconv.Itoa(int(x.sw))) != nil {
			return
		}
	}
	cw.Flush()
}
