// Package app wires the server together and owns its lifecycle.
package app

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"github.com/google/uuid"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/agentdl"
	"github.com/auzring1/librepatch/internal/server/agentrel"
	"github.com/auzring1/librepatch/internal/server/api"
	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/server/branding"
	"github.com/auzring1/librepatch/internal/server/catalog"
	"github.com/auzring1/librepatch/internal/server/config"
	"github.com/auzring1/librepatch/internal/server/dashboard"
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/events"
	"github.com/auzring1/librepatch/internal/server/gateway"
	"github.com/auzring1/librepatch/internal/server/kek"
	"github.com/auzring1/librepatch/internal/server/keyack"
	"github.com/auzring1/librepatch/internal/server/maintenance"
	"github.com/auzring1/librepatch/internal/server/notify"
	"github.com/auzring1/librepatch/internal/server/pki"
	"github.com/auzring1/librepatch/internal/server/policies"
	"github.com/auzring1/librepatch/internal/server/reportsched"
	"github.com/auzring1/librepatch/internal/server/scripts"
	"github.com/auzring1/librepatch/internal/server/settings"
	"github.com/auzring1/librepatch/internal/server/sso"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/server/updates"
	"github.com/auzring1/librepatch/internal/server/vulns"
	"github.com/auzring1/librepatch/internal/server/webui"
	"github.com/auzring1/librepatch/internal/server/wingetindex"
	"github.com/auzring1/librepatch/internal/shared/release"
	"github.com/auzring1/librepatch/internal/shared/version"
)

// App is a running server.
type App struct {
	Cfg       *config.Config
	Log       *slog.Logger
	Pool      *pgxpool.Pool
	Sealer    *kek.Sealer
	KeyAck    *keyack.State
	Events    *events.Broker
	Hub       *gateway.Hub
	Deploy    *deploy.Service
	Updates   *updates.Service
	Releases  *agentrel.Service
	Policies  *policies.Service
	Scripts   *scripts.Service
	SSO       *sso.Provider
	Vulns     *vulns.Service
	Dashboard *dashboard.Service
	Settings  *settings.Service
	Notify    *notify.Service
	Maint     *maintenance.Service
	Sched     *reportsched.Service
	Catalog   *catalog.Service
	// AgentDL fetches and serves the agent installers (decision D112).
	AgentDL *agentdl.Service
	// Winget keeps the winget community index (what installed programs are and their newest versions); nil when
	// LIBREPATCH_WINGET_SOURCE=off.
	Winget *wingetindex.Service
	// Branding holds the per-deployment names, colors, login texts and images.
	Branding *branding.Service

	authority atomic.Pointer[pki.Authority]

	mu         sync.Mutex
	setupToken string
	runCtx     context.Context
	gwStarted  bool
	gwLis      net.Listener
	httpLis    net.Listener

	// GatewayReady is closed when the agent gateway is listening.
	GatewayReady chan struct{}
}

// New migrates the database (if configured), connects and loads the CA.
func New(ctx context.Context, cfg *config.Config, log *slog.Logger) (*App, error) {
	if cfg.MigrateOnStart {
		url := cfg.MigrateDatabaseURL
		if url == "" {
			url = cfg.DatabaseURL
		}
		if err := store.Migrate(ctx, url, log); err != nil {
			return nil, err
		}
	}
	pool, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	store.CheckLeastPrivilege(ctx, pool, log)
	sealer, err := kek.New(cfg.MasterKey)
	if err != nil {
		pool.Close()
		return nil, err
	}
	keyAck, err := keyack.Load(ctx, pool, cfg.MasterKey)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("read the master key state: %w", err)
	}
	if keyAck.Pending() {
		log.Warn("the master key has not been saved yet: the console asks the first administrator to save it before anything else works")
	}
	a := &App{Cfg: cfg, Log: log, Pool: pool, Sealer: sealer, KeyAck: keyAck, Events: events.NewBroker(), Hub: gateway.NewHub(),
		GatewayReady: make(chan struct{})}
	a.Deploy = &deploy.Service{Pool: pool, Authority: a.Authority, Dispatcher: a.Hub, Events: a.Events, Log: log.With("component", "deploy")}
	a.Updates = &updates.Service{Pool: pool, Deploy: a.Deploy, Events: a.Events, Log: log.With("component", "updates")}
	a.Catalog = newCatalog(cfg, pool)
	if cfg.WingetSource == "github" {
		a.Winget = &wingetindex.Service{Pool: pool, URL: cfg.WingetIndexURL, Log: log.With("component", "winget-index")}
		a.Deploy.Winget = a.Winget
	}
	a.AgentDL = &agentdl.Service{Version: version.Version, BaseURL: cfg.AgentDownloadBaseURL, Off: cfg.AgentDownloads == "off", AllowHTTP: cfg.DevMode,
		Log: log.With("component", "agentdl")}
	if cfg.ContentDir != "" {
		// A dot-folder: backups skip it (the files are fetched again from the release, nothing to back up).
		a.AgentDL.Dir = filepath.Join(cfg.ContentDir, ".agent-downloads")
	}
	a.Deploy.Overlay = a.Catalog.Overlay
	// The signed catalog overlays an administrator added (D122) are read back into memory and applied to the catalog.
	if err := a.Catalog.LoadOverlays(ctx); err != nil {
		log.Error("catalog overlays could not be loaded", "err", err)
	}
	a.Releases = &agentrel.Service{Pool: pool, Deploy: a.Deploy, Content: a.Catalog.Content, Events: a.Events, Log: log.With("component", "agentrel"), BundledDir: cfg.AgentReleaseDir}
	if extra, err := release.ParseKeys(cfg.ReleasePublicKeys); err == nil && len(extra) > 0 {
		a.Releases.Keys = append(release.TrustedKeys(), extra...)
	}
	a.Branding = &branding.Service{Pool: pool, Log: log.With("component", "branding")}
	a.Dashboard = &dashboard.Service{Pool: pool, Log: log.With("component", "dashboard")}
	a.Settings = &settings.Service{Pool: pool, Sealer: sealer, Log: log.With("component", "settings")}
	a.Updates.Enabled = func(ctx context.Context, org uuid.UUID) bool {
		return a.Settings.Peek(ctx, org, "updates").Bool("windows_updates_enabled")
	}
	a.Updates.IgnoreWSUS = func(ctx context.Context, org uuid.UUID) bool {
		u := a.Settings.Peek(ctx, org, "updates")
		return u.Bool("windows_updates_enabled") && u.Bool("ignore_wsus")
	}
	a.Settings.OnChange = func(ctx context.Context, org uuid.UUID, section string, changes map[string]any) {
		if _, ok := changes["ignore_wsus"]; ok && section == "updates" {
			a.Updates.SettingsChanged(ctx, org) // every online device gets a scan from the new source
		}
	}
	a.Deploy.PeerCache = func(ctx context.Context, org uuid.UUID) bool {
		return a.Settings.Peek(ctx, org, "downloads").Bool("peer_cache")
	}
	a.Scripts = &scripts.Service{Pool: pool, Deploy: a.Deploy, Settings: a.Settings, Log: log.With("component", "scripts")}
	a.SSO = &sso.Provider{}
	a.Vulns = &vulns.Service{Store: &vulns.Store{Pool: pool}, Settings: a.Settings, Log: log.With("component", "vulns")}
	a.Maint = &maintenance.Service{Pool: pool, Settings: a.Settings, Log: log.With("component", "maintenance")}
	a.Notify = &notify.Service{Pool: pool, Settings: a.Settings, Branding: a.Branding, Log: log.With("component", "notify")}
	a.Sched = &reportsched.Service{Pool: pool, Settings: a.Settings, Mail: a.Notify, Log: log.With("component", "reports"), Names: func(ctx context.Context) (string, string, string) {
		if p, err := a.Branding.Public(ctx); err == nil {
			return p.OrgName, p.ProductName, p.AccentColor
		}
		return "", brand.Name, "#1971c2"
	}, Logo: func(ctx context.Context, org uuid.UUID) []byte {
		if rb, err := a.Branding.ForReport(ctx, org); err == nil {
			return rb.LogoPNG
		}
		return nil
	}}
	a.Policies = &policies.Service{Pool: pool, Deploy: a.Deploy, Log: log.With("component", "policies")}
	a.Updates.OnHold = func(ctx context.Context, org uuid.UUID, title, ring, reason string) {
		a.Notify.Emit(ctx, org, notify.Event{Name: "update_held", Key: "hold:" + title + ":" + ring, Subject: title + " is held after ring " + ring,
			Text: "The update \"" + title + "\" was held because ring " + ring + " missed its success threshold: " + reason,
			Data: map[string]any{"update": map[string]any{"title": title}, "ring": ring, "reason": reason}})
	}
	a.Policies.OnHold = a.Updates.OnHold
	a.Policies.Import = func(ctx context.Context, org, user uuid.UUID, wingetID string) (uuid.UUID, error) {
		res, err := a.Catalog.Import(ctx, org, user, wingetID, "")
		if err != nil {
			return uuid.Nil, err
		}
		return res.PackageID, nil
	}
	a.Policies.OnApprovalNeeded = func(ctx context.Context, org uuid.UUID, pkg, version string) {
		a.Notify.Emit(ctx, org, notify.Event{Name: "software_approval_needed", Key: "approval:" + pkg + ":" + version, Subject: pkg + " " + version + " is waiting for approval",
			Text: "A new version of " + pkg + " (" + version + ") is available and a software policy needs your approval before it is rolled out.",
			Data: map[string]any{"package": map[string]any{"name": pkg}, "version": version}})
	}
	a.Deploy.AfterTerminal = func(ctx context.Context, j dbq.Job, status string, u *agentv1.JobUpdate) {
		if status == "failed" {
			host := ""
			if d, err := dbq.New(pool).GetDevice(ctx, j.DeviceID); err == nil {
				host = d.Hostname
			}
			a.Notify.Emit(ctx, j.OrgID, notify.Event{Name: "failed_install", Key: "job:" + j.ID.String(), Subject: j.Title + " failed on " + host,
				Text: j.Title + " failed on " + host + ": " + j.StatusReason,
				Data: map[string]any{"device": map[string]any{"id": j.DeviceID.String(), "hostname": host}, "job": map[string]any{"id": j.ID.String(), "title": j.Title, "reason": j.StatusReason}}})
		}
		a.Updates.AfterJob(ctx, j, status, u)
		a.Releases.AfterJob(ctx, j, status, u)
	}
	q := dbq.New(pool)
	if err := q.MarkAllDevicesOffline(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	auth, err := pki.LoadAuthority(ctx, q, sealer)
	switch {
	case err == nil:
		a.authority.Store(auth)
	case errors.Is(err, pki.ErrNotInitialized):
		n, cerr := q.CountUsers(ctx)
		if cerr != nil {
			pool.Close()
			return nil, cerr
		}
		if n > 0 {
			pool.Close()
			return nil, errors.New("users exist but the certificate authority is missing; restore from backup")
		}
		if err := a.newSetupToken(); err != nil {
			pool.Close()
			return nil, err
		}
	default:
		pool.Close()
		return nil, fmt.Errorf("load certificate authority: %w", err)
	}
	return a, nil
}

// Close releases resources.
func (a *App) Close() { a.Pool.Close() }

func (a *App) newSetupToken() error {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	a.mu.Lock()
	a.setupToken = base64.RawURLEncoding.EncodeToString(b)
	tok := a.setupToken
	a.mu.Unlock()
	// Same stream as the JSON log lines, so that the container runtime cannot interleave them with the banner (it reads
	// stdout and stderr separately, which once split the token from its heading and made `grep -A2` miss it).
	fmt.Fprintf(os.Stdout, "\n"+
		"==================================================================\n"+
		"  "+brand.Name+" first-run setup is pending.\n"+
		"  Open %s and enter this one-time setup token:\n\n"+
		"      %s\n\n"+
		"  The token changes every time the server restarts until setup is done.\n"+
		"==================================================================\n\n", a.Cfg.Origin(), tok)
	a.Log.Info("first-run setup pending; setup token printed above")
	return nil
}

// SetupToken returns the current setup token (tests only).
func (a *App) SetupToken() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.setupToken
}

// Authority returns the loaded CA (nil before setup).
func (a *App) Authority() *pki.Authority { return a.authority.Load() }

// --- api.SetupController ---

type setupCtl struct{ a *App }

func (s setupCtl) Required(ctx context.Context) (bool, error) {
	n, err := dbq.New(s.a.Pool).CountUsers(ctx)
	return n == 0, err
}

func (s setupCtl) CheckToken(tok string) bool {
	s.a.mu.Lock()
	defer s.a.mu.Unlock()
	return s.a.setupToken != "" && len(tok) == len(s.a.setupToken) &&
		subtle.ConstantTimeCompare([]byte(tok), []byte(s.a.setupToken)) == 1
}

func (s setupCtl) Completed(ctx context.Context) error {
	auth, err := pki.LoadAuthority(ctx, dbq.New(s.a.Pool), s.a.Sealer)
	if err != nil {
		return err
	}
	s.a.authority.Store(auth)
	s.a.mu.Lock()
	s.a.setupToken = ""
	s.a.mu.Unlock()
	return s.a.startGateway()
}

// Handler builds the HTTP handler (exposed for tests).
func (a *App) Handler() http.Handler {
	sessions := &auth.Sessions{
		Q:      func(context.Context) *dbq.Queries { return dbq.New(a.Pool) },
		Idle:   a.Cfg.SessionIdleTimeout,
		Abs:    a.Cfg.SessionAbsTimeout,
		Secure: a.Cfg.SecureCookies(),
	}
	deps := api.Deps{
		Cfg: a.Cfg, Pool: a.Pool, Sealer: a.Sealer, Sessions: sessions, Events: a.Events,
		Setup: setupCtl{a}, Devices: a.Hub, Authority: a.Authority, Log: a.Log, Deploy: a.Deploy, Catalog: a.Catalog, Winget: a.Winget, AgentDL: a.AgentDL, Updates: a.Updates, Releases: a.Releases, Policies: a.Policies, Scripts: a.Scripts, SSO: a.SSO, Vulns: a.Vulns, Branding: a.Branding, Settings: a.Settings, Notify: a.Notify, Maint: a.Maint, Sched: a.Sched, KeyAck: a.KeyAck,
	}
	sessions.Timeouts = api.SessionLimits(deps)
	return api.NewHandler(deps, webui.Handler(a.pageHead))
}

// Run serves HTTP and (once the CA exists) the agent gateway until ctx ends.
func (a *App) Run(ctx context.Context) error {
	a.mu.Lock()
	a.runCtx = ctx
	a.mu.Unlock()

	lis, err := net.Listen("tcp", a.Cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", a.Cfg.HTTPAddr, err)
	}
	a.mu.Lock()
	a.httpLis = lis
	a.mu.Unlock()
	srv := &http.Server{
		Handler:           a.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(a.Log.Handler(), slog.LevelWarn),
	}
	if a.Authority() != nil {
		if err := a.startGateway(); err != nil {
			return err
		}
	}
	go a.housekeeping(ctx)
	go a.AgentDL.Run(ctx)
	if a.Winget != nil {
		go a.Winget.Run(ctx)
	}

	errCh := make(chan error, 1)
	go func() {
		a.Log.Info("http listening", "addr", lis.Addr().String())
		errCh <- srv.Serve(lis)
	}()
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
	return nil
}

// HTTPAddr returns the bound HTTP address (useful with :0 in tests).
func (a *App) HTTPAddr() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.httpLis == nil {
		return ""
	}
	return a.httpLis.Addr().String()
}

// GatewayAddr returns the bound gateway address.
func (a *App) GatewayAddr() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.gwLis == nil {
		return ""
	}
	return a.gwLis.Addr().String()
}

func (a *App) startGateway() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.gwStarted || a.runCtx == nil {
		return nil
	}
	ctx := a.runCtx
	gw := gateway.New(gateway.Options{Config: a.Cfg, Pool: a.Pool, Sealer: a.Sealer, Authority: a.Authority(),
		Events: a.Events, Hub: a.Hub, Log: a.Log.With("component", "gateway"), Deploy: a.Deploy, Updates: a.Updates, Content: a.Catalog.Content, Settings: a.Settings})
	if err := gw.RefreshCertificate(ctx); err != nil {
		return fmt.Errorf("gateway certificate: %w", err)
	}
	lis, err := net.Listen("tcp", a.Cfg.GatewayAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", a.Cfg.GatewayAddr, err)
	}
	a.gwLis = lis
	a.gwStarted = true
	go func() {
		a.Log.Info("agent gateway listening", "addr", lis.Addr().String(), "public", a.Cfg.GatewayPublicAddr)
		if err := gw.Serve(ctx, lis); err != nil {
			a.Log.Error("gateway stopped", "err", err)
		}
	}()
	close(a.GatewayReady)
	return nil
}

func (a *App) housekeeping(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.Deploy.Sweep(ctx)
			a.Updates.Tick(ctx)
			a.Releases.SyncBundled(ctx) // the agent release that came with the image (D149); cheap once every organization has it
			a.Releases.Tick(ctx)
			a.Notify.Tick(ctx)
			a.Sched.Tick(ctx)
			if n%5 == 0 {
				a.Policies.Tick(ctx)
			}
			if n%60 == 11 {
				// A download can take minutes (the NVD allows a few requests per half minute), so it runs on its own; the
				// service lets only one run at a time and asks each feed only when it is due.
				go a.Vulns.Tick(ctx)
			}
			if n%60 == 3 {
				go a.Catalog.RefreshStaleMSIX(ctx) // packages imported before MSIX could be deployed; a no-op once none is left
			}
			if n%60 == 7 {
				a.Catalog.RefreshDueOverlays(ctx) // asks each overlay URL at most every 12 hours
			}
			n++
			if n%60 == 1 {
				a.Dashboard.Tick(ctx) // the first minute after start, then hourly
			}
			if n%1440 == 0 {
				a.Updates.Prune(ctx)
				a.Maint.Tick(ctx)
			}
			if n%10 != 0 {
				continue
			}
			if n, err := dbq.New(a.Pool).DeleteExpiredSessions(ctx, time.Now()); err != nil {
				a.Log.Error("session cleanup", "err", err)
			} else if n > 0 {
				a.Log.Debug("expired sessions removed", "count", n)
			}
		}
	}
}

// newCatalog builds the catalog service from the configuration.
func newCatalog(cfg *config.Config, pool *pgxpool.Pool) *catalog.Service {
	s := &catalog.Service{Pool: pool, Overlay: catalog.LoadOverlay()}
	if cfg.WingetSource == "github" {
		s.Source = &catalog.GitHubSource{Token: cfg.GitHubToken}
	}
	if cfg.ContentDir != "" {
		s.Content = &catalog.Store{Dir: cfg.ContentDir}
	}
	return s
}

// pageHead supplies the per-deployment <title>, favicon and branding data for
// the console's HTML shell. Errors fall back to the product defaults.
func (a *App) pageHead(ctx context.Context) webui.Head {
	p, err := a.Branding.Public(ctx)
	if err != nil {
		return webui.Head{}
	}
	h := webui.Head{Title: p.Title}
	if f := p.Assets[branding.KindFavicon]; f != nil {
		h.Favicon = f.URL
	}
	if j, err := json.Marshal(p); err == nil {
		h.JSON = string(j)
	}
	return h
}
