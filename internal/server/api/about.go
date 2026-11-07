package api

import (
	"archive/zip"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"github.com/auzring1/librepatch/internal/shared/version"
)

var startedAt = time.Now()

// configShown lists the environment settings whose value is safe to put in a support bundle. Every other LIBREPATCH_
// variable is reported only as set or not set, because it can hold a key, a token or a password.
var configShown = map[string]bool{
	"LIBREPATCH_HTTP_ADDR": true, "LIBREPATCH_GATEWAY_ADDR": true, "LIBREPATCH_GATEWAY_PUBLIC_ADDR": true, "LIBREPATCH_PUBLIC_URL": true,
	"LIBREPATCH_TRUSTED_PROXIES": true, "LIBREPATCH_LOG_LEVEL": true, "LIBREPATCH_DEV_MODE": true, "LIBREPATCH_HEARTBEAT_INTERVAL": true,
	"LIBREPATCH_SESSION_IDLE_TIMEOUT": true, "LIBREPATCH_SESSION_ABSOLUTE_TIMEOUT": true, "LIBREPATCH_MIGRATE_ON_START": true,
	"LIBREPATCH_WINGET_SOURCE": true, "LIBREPATCH_WINGET_INDEX_URL": true, "LIBREPATCH_DEVICE_CERT_LIFETIME": true, "LIBREPATCH_DEVICE_RENEW_GRACE": true,
	"LIBREPATCH_ENROLL_POLL_INTERVAL": true, "LIBREPATCH_ENROLL_RATE_PER_IP": true, "LIBREPATCH_ENROLL_RATE_PER_TOKEN": true,
	"LIBREPATCH_GATEWAY_SANS": true, "LIBREPATCH_IGNORE_IP_ALLOWLIST": true,
}

// redactedConfig reports the server's environment configuration without secrets.
func redactedConfig() map[string]string {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(k, "LIBREPATCH_") {
			continue
		}
		switch {
		case configShown[k]:
			out[k] = v
		case k == "LIBREPATCH_DATABASE_URL" || k == "LIBREPATCH_MIGRATE_DATABASE_URL":
			out[k] = redactURL(v)
		case v == "":
			out[k] = "(empty)"
		default:
			out[k] = "(set)"
		}
	}
	return out
}

// redactURL keeps host and database name and drops the credentials and query.
func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "(set)"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

func (s *server) aboutInfo(r *http.Request) map[string]any {
	ctx := r.Context()
	info := map[string]any{
		"product": brand.Name, "company": brand.Company, "version": version.Version, "commit": version.Commit,
		"go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH,
		"started_at": startedAt.UTC().Format(time.RFC3339), "uptime_seconds": int64(time.Since(startedAt).Seconds()),
		"time": s.now().UTC().Format(time.RFC3339),
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		mods := len(bi.Deps)
		info["modules"] = mods
		for _, kv := range bi.Settings {
			switch kv.Key {
			case "vcs.revision", "vcs.time", "vcs.modified", "CGO_ENABLED", "GOARM64", "GOAMD64":
				info["build_"+strings.ReplaceAll(kv.Key, ".", "_")] = kv.Value
			}
		}
	}
	var mig int64
	if err := s.Pool.QueryRow(ctx, `SELECT COALESCE(max(version_id), 0) FROM goose_db_version WHERE is_applied`).Scan(&mig); err == nil {
		info["database_migration"] = mig
	}
	var pg string
	if err := s.Pool.QueryRow(ctx, `SHOW server_version`).Scan(&pg); err == nil {
		info["postgres"] = pg
	}
	info["database_ok"] = s.Pool.Ping(ctx) == nil
	if s.Settings != nil {
		info["settings_schema_version"] = 1
	}
	org := principalFrom(r).OrgID
	counts := map[string]int64{}
	rows, err := s.Pool.Query(ctx, `SELECT status, count(*) FROM devices WHERE org_id = $1 GROUP BY status`, org)
	if err == nil {
		for rows.Next() {
			var st string
			var n int64
			if rows.Scan(&st, &n) == nil {
				counts["devices_"+st] = n
			}
		}
		rows.Close()
	}
	var users int64
	if s.Pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE org_id = $1 AND status = 'active'`, org).Scan(&users) == nil {
		counts["users_active"] = users
	}
	info["counts"] = counts
	return info
}

// GET /settings/about: version, license and build information (administrators).
func (s *server) settingsAbout(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.aboutInfo(r))
}

const bundleReadme = `This support bundle was made by the console (Settings > About). It is meant to be sent to whoever supports this installation.

Included: version and build information, the license state, device and user counts, the server's configuration with every
secret replaced by "(set)", the settings as the settings export writes them (never any secret), the database state, the
last 200 audit entries (who, when, what and the outcome, without their details) and the last 100 notification deliveries
(without their content).

Not included: the master key, passwords, API tokens, session cookies, certificates and private keys, device inventory,
software lists, the contents of audit details, anything stored in the database other than counts, and the log file.
Read the files before sending them if you want to check.
`

// GET /settings/support-bundle: a zip with what support needs and nothing secret (administrators; audited).
func (s *server) supportBundle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := principalFrom(r)
	now := s.now().UTC()
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="support-bundle-`+now.Format("20060102-150405")+`.zip"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	zw := zip.NewWriter(w)
	add := func(name string, v any) {
		f, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: now})
		if err != nil {
			return
		}
		if str, ok := v.(string); ok {
			_, _ = f.Write([]byte(str))
			return
		}
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
	}
	add("README.txt", bundleReadme)
	add("about.json", s.aboutInfo(r))
	add("config.json", redactedConfig())
	if s.Settings != nil {
		if doc, err := s.Settings.Export(ctx, p.OrgID); err == nil {
			add("settings.json", doc)
		}
	}
	org := p.OrgID
	if rows, err := s.q().ListAudit(ctx, dbq.ListAuditParams{OrgID: &org, Limit: 200}); err == nil {
		type entry struct {
			ID      int64     `json:"id"`
			Time    time.Time `json:"time"`
			Actor   string    `json:"actor_type"`
			Action  string    `json:"action"`
			Target  string    `json:"target_type"`
			Outcome string    `json:"outcome"`
		}
		out := make([]entry, 0, len(rows))
		for _, a := range rows {
			out = append(out, entry{a.ID, a.Ts, a.ActorType, a.Action, a.TargetType, a.Outcome})
		}
		add("audit-tail.json", out)
	}
	if rows, err := s.q().ListNotificationLog(ctx, dbq.ListNotificationLogParams{OrgID: org, Limit: 100}); err == nil {
		type entry struct {
			Time    time.Time `json:"time"`
			Channel string    `json:"channel"`
			Event   string    `json:"event"`
			Status  string    `json:"status"`
			Tries   int32     `json:"attempts"`
			Error   string    `json:"error"`
		}
		out := make([]entry, 0, len(rows))
		for _, n := range rows {
			out = append(out, entry{n.CreatedAt, n.Channel, n.Event, n.Status, n.Attempts, n.LastError})
		}
		add("notification-log.json", out)
	}
	_ = zw.Close()
	_ = s.auditSimple(r, "settings.support_bundle", "settings", []string{"support-bundle"}, map[string]any{})
}
