// Package api implements the REST API used by the web console.
// The contract is api/openapi.yaml; TestRoutesMatchSpec keeps them in sync.
package api

import (
	"context"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/agentdl"
	"github.com/auzring1/librepatch/internal/server/agentrel"
	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/server/branding"
	"github.com/auzring1/librepatch/internal/server/catalog"
	"github.com/auzring1/librepatch/internal/server/config"
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/events"
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
	"github.com/auzring1/librepatch/internal/server/updates"
	"github.com/auzring1/librepatch/internal/server/vulns"
	"github.com/auzring1/librepatch/internal/server/wingetindex"
)

// SetupController is implemented by the app to drive first-run setup.
type SetupController interface {
	// Required reports whether first-run setup is still pending.
	Required(ctx context.Context) (bool, error)
	// CheckToken validates the one-time setup token printed at startup.
	CheckToken(tok string) bool
	// Completed is called after setup commits (loads the CA, starts the gateway).
	Completed(ctx context.Context) error
}

// DeviceController lets handlers act on live agent connections.
type DeviceController interface {
	Disconnect(deviceID uuid.UUID, reason string)
}

// Deps are the API's dependencies.
type Deps struct {
	Cfg       *config.Config
	Pool      *pgxpool.Pool
	Sealer    *kek.Sealer
	Sessions  *auth.Sessions
	Events    *events.Broker
	Setup     SetupController
	Devices   DeviceController
	Authority func() *pki.Authority
	Deploy    *deploy.Service
	Catalog   *catalog.Service
	Winget    *wingetindex.Service
	AgentDL   *agentdl.Service // nil: the agent installers are not offered
	Updates   *updates.Service
	Releases  *agentrel.Service
	Policies  *policies.Service
	Scripts   *scripts.Service
	SSO       *sso.Provider // single sign-on (D128); nil = not available
	Vulns     *vulns.Service
	Branding  *branding.Service
	Settings  *settings.Service
	Notify    *notify.Service
	Maint     *maintenance.Service
	Sched     *reportsched.Service
	KeyAck    *keyack.State // nil when the key was supplied by hand: nothing to confirm
	Log       *slog.Logger
	Now       func() time.Time
}

type server struct {
	Deps
	loginIP    *auth.Limiter
	loginEmail *auth.Limiter
	setupIP    *auth.Limiter
	apiIP      *auth.Limiter
	sse        *sseLimiter
	verifying  sync.Mutex
	adminMu    sync.Mutex         // last-administrator guard
	webauthn   *webauthn.WebAuthn // nil when the public URL cannot host WebAuthn
}

func (s *server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *server) q() *dbq.Queries { return dbq.New(s.Pool) }

// NewHandler builds the full HTTP handler: /api/v1, health endpoints and the GUI.
func NewHandler(d Deps, gui http.Handler) http.Handler {
	s := &server{
		Deps:       d,
		loginIP:    auth.NewLimiter(10, time.Minute, 10),
		loginEmail: auth.NewLimiter(5, time.Minute, 5),
		setupIP:    auth.NewLimiter(5, time.Minute, 10),
		apiIP:      auth.NewLimiter(20, time.Second, 60),
		sse:        newSSELimiter(5),
	}
	if d.Cfg != nil && d.Cfg.PublicURL != nil {
		if wa, err := webauthn.New(&webauthn.Config{RPDisplayName: brand.Name, RPID: d.Cfg.PublicURL.Hostname(), RPOrigins: []string{d.Cfg.Origin()}}); err == nil {
			s.webauthn = wa
		} else if d.Log != nil {
			d.Log.Warn("security keys disabled", "err", err)
		}
	}
	go s.sweepLimiters()

	r := chi.NewRouter()
	r.Use(s.recoverer, s.realIP, securityHeaders(d.Cfg))
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	r.Get("/readyz", s.readyz)
	// The agent installers are public by design (the same files are on the project's release page, and nothing in them is
	// secret: the enrollment token and the CA pin come with the install command), so an endpoint can fetch them with
	// curl. They are rate limited per address but not covered by the console's IP allow-list.
	r.With(s.rateLimit).Get("/download/{name}", s.downloadAgent)
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(apiHeaders, s.ipAllow, s.rateLimit, s.requestLog, s.originCheck, s.loadSession, s.csrfCheck)
		s.routes(r)
	})
	if gui != nil {
		r.NotFound(gui.ServeHTTP)
	}
	return r
}

// routes registers every API route. Keep in sync with api/openapi.yaml.
func (s *server) routes(r chi.Router) {
	r.Get("/branding", s.getPublicBranding)
	r.Get("/branding/assets/{kind}", s.getBrandingAsset)
	r.Get("/auth/notice", s.authNotice)
	r.Get("/setup/status", s.setupStatus)
	r.Post("/setup/begin", s.setupBegin)
	r.Post("/setup/complete", s.setupComplete)

	r.Get("/auth/sso/info", s.ssoInfo)
	r.Get("/auth/sso/start", s.ssoStart)
	r.Get("/auth/sso/callback", s.ssoCallback)
	r.Get("/auth/sso/continue", s.ssoContinue)
	r.Post("/auth/login", s.login)
	r.Post("/auth/mfa", s.mfaVerify)
	r.Post("/auth/mfa/enroll", s.mfaEnroll)
	r.Post("/auth/logout", s.logout)
	r.Post("/auth/change-password", s.changePassword)
	r.Post("/auth/webauthn/begin", s.beginKeyLogin)
	r.Post("/auth/webauthn/finish", s.finishKeyLogin)
	r.Get("/auth/session", s.session)

	r.With(s.requireAny(auth.PermDevicesRead)).Get("/devices", s.listDevices)
	r.With(s.requireDevice(auth.PermDevicesRead)).Get("/devices/{id}", s.getDevice)
	r.With(s.requireDevice(auth.PermDevicesWrite)).Post("/devices/{id}/approve", s.approveDevice)
	r.With(s.requireDevice(auth.PermDevicesWrite)).Post("/devices/{id}/revoke", s.revokeDevice)
	r.With(s.requireDevice(auth.PermDevicesWrite)).Delete("/devices/{id}", s.deleteDevice)
	r.With(s.requireDevice(auth.PermDevicesRead)).Get("/devices/{id}/fields", s.getDeviceFields)
	r.With(s.requireDevice(auth.PermDevicesWrite)).Put("/devices/{id}/fields", s.putDeviceFields)
	r.With(s.requireAny(auth.PermDevicesWrite)).Post("/devices/delete", s.deleteDevices)

	r.With(s.requireDevice(auth.PermDevicesRead)).Get("/devices/{id}/software", s.deviceSoftware)
	r.With(s.requireDevice(auth.PermDevicesRead)).Get("/devices/{id}/software/history", s.deviceSoftwareHistory)
	r.With(s.requireDevice(auth.PermDevicesRead)).Get("/devices/{id}/users", s.deviceUsers)

	r.With(s.require(auth.PermDevicesRead)).Get("/software", s.searchSoftware)
	r.With(s.require(auth.PermDeploymentsRead)).Get("/software/updates", s.fleetSoftwareUpdates)
	r.With(s.require(auth.PermDevicesRead)).Get("/software/{id}", s.getSoftware)
	r.With(s.require(auth.PermDevicesRead)).Get("/software/{id}/installs", s.titleInstalls)

	r.With(s.require(auth.PermGroupsRead)).Get("/groups", s.listGroups)
	r.With(s.require(auth.PermGroupsWrite)).Post("/groups", s.createGroup)
	r.With(s.require(auth.PermGroupsRead)).Post("/groups/preview", s.previewGroup)
	r.With(s.require(auth.PermGroupsRead)).Get("/groups/{id}", s.getGroup)
	r.With(s.require(auth.PermGroupsWrite)).Put("/groups/{id}", s.updateGroup)
	r.With(s.require(auth.PermGroupsWrite)).Delete("/groups/{id}", s.deleteGroup)
	r.With(s.require(auth.PermGroupsRead)).Get("/groups/{id}/devices", s.groupDevices)

	r.With(s.require(auth.PermInventoryExport)).Get("/reports/software.csv", s.softwareCSV)
	r.With(s.require(auth.PermInventoryExport)).Get("/reports/devices.csv", s.devicesCSV)

	r.With(s.requireDevice(auth.PermDeploymentsRead)).Get("/devices/{id}/jobs", s.deviceJobs)

	r.With(s.require(auth.PermUpdatesRead)).Get("/updates", s.listUpdates)
	r.With(s.require(auth.PermUpdatesWrite)).Post("/updates/decision", s.decideUpdates)
	r.With(s.require(auth.PermUpdatesRead)).Get("/updates/{id}/devices", s.updateDevices)
	r.With(s.require(auth.PermUpdatesWrite)).Post("/updates/{id}/install", s.installUpdate)
	r.With(s.require(auth.PermUpdatesRead)).Get("/update-settings", s.getUpdateSettings)
	r.With(s.require(auth.PermUpdatesPolicy)).Put("/update-settings", s.putUpdateSettings)
	r.With(s.require(auth.PermUpdatesRead)).Get("/update-rules", s.listUpdateRules)
	r.With(s.require(auth.PermUpdatesPolicy)).Post("/update-rules", s.createUpdateRule)
	r.With(s.require(auth.PermUpdatesPolicy)).Put("/update-rules/{id}", s.putUpdateRule)
	r.With(s.require(auth.PermUpdatesPolicy)).Delete("/update-rules/{id}", s.deleteUpdateRule)
	r.With(s.require(auth.PermUpdatesRead)).Get("/update-rings", s.listUpdateRings)
	r.With(s.require(auth.PermUpdatesPolicy)).Post("/update-rings", s.createUpdateRing)
	r.With(s.require(auth.PermUpdatesPolicy)).Put("/update-rings/{id}", s.putUpdateRing)
	r.With(s.require(auth.PermUpdatesPolicy)).Delete("/update-rings/{id}", s.deleteUpdateRing)
	r.With(s.require(auth.PermUpdatesRead)).Get("/update-holds", s.listUpdateHolds)
	r.With(s.require(auth.PermUpdatesPolicy)).Post("/update-holds/{id}/release", s.releaseUpdateHold)
	r.With(s.require(auth.PermUpdatesRead)).Get("/update-conflicts", s.updateConflicts)
	r.With(s.requireDevice(auth.PermUpdatesRead)).Get("/devices/{id}/windows-updates", s.deviceWindowsUpdates)
	r.With(s.requireDevice(auth.PermUpdatesWrite)).Post("/devices/{id}/windows-updates/scan", s.scanDeviceUpdates)
	r.With(s.requireDevice(auth.PermUpdatesWrite)).Post("/devices/{id}/windows-updates/install", s.installDeviceUpdates)
	// Going around WSUS or Configuration Manager is a policy decision, so it needs the policy permission (D105).
	r.With(s.requireDevice(auth.PermUpdatesPolicy)).Post("/devices/{id}/windows-updates/scan-online", s.scanDeviceUpdatesOnline)
	r.With(s.requireDevice(auth.PermUpdatesPolicy)).Post("/devices/{id}/windows-updates/install-online", s.installDeviceUpdatesOnline)
	r.With(s.requireDevice(auth.PermUpdatesWrite)).Post("/devices/{id}/windows-updates/hide", s.hideDeviceUpdates)
	r.With(s.requireDevice(auth.PermUpdatesWrite)).Post("/devices/{id}/reboot", s.rebootDevice)
	r.With(s.requireDevice(auth.PermDevicesWake)).Post("/devices/{id}/wake", s.wakeDevice)
	r.With(s.requireDevice(auth.PermDevicesInspect)).Post("/devices/{id}/inspect", s.inspectDevice)
	r.With(s.requireDevice(auth.PermDevicesInspect)).Get("/devices/{id}/views/{job}", s.deviceView)
	r.With(s.require(auth.PermReleasesRead)).Get("/agent-releases", s.listAgentReleases)
	r.With(s.require(auth.PermReleasesWrite)).Post("/agent-releases", s.uploadAgentRelease)
	r.With(s.require(auth.PermReleasesWrite)).Post("/agent-releases/{id}/status", s.setAgentReleaseStatus)
	r.With(s.require(auth.PermReleasesWrite)).Delete("/agent-releases/{id}", s.deleteAgentRelease)
	r.With(s.require(auth.PermReleasesRead)).Get("/agent-rollout", s.getAgentRollout)
	r.With(s.require(auth.PermReleasesWrite)).Put("/agent-rollout", s.putAgentRollout)
	r.With(s.requireDevice(auth.PermDeploymentsRead)).Get("/devices/{id}/updates", s.deviceUpdates)
	r.With(s.requireDevice(auth.PermDeploymentsWrite)).Post("/devices/{id}/software/uninstall", s.uninstallDeviceSoftware)
	r.With(s.requireDevice(auth.PermDevicesProfiles)).Post("/devices/{id}/users/{sid}/remove-profile", s.removeDeviceProfile)
	r.With(s.requireDevice(auth.PermDevicesWrite)).Post("/devices/{id}/refresh", s.refreshDevice)

	r.With(s.require(auth.PermCatalogRead)).Get("/catalog/packages", s.listPackages)
	r.With(s.require(auth.PermCatalogRead)).Get("/catalog/search", s.searchCatalog)
	r.With(s.require(auth.PermCatalogRead)).Get("/catalog/packages/{id}", s.getPackage)
	r.With(s.require(auth.PermCatalogRead)).Get("/catalog/index", s.wingetIndexStatus)
	r.With(s.require(auth.PermCatalogWrite)).Post("/catalog/index/refresh", s.refreshWingetIndex)
	r.With(s.require(auth.PermCatalogWrite)).Post("/catalog/import", s.importPackage)
	r.With(s.require(auth.PermCatalogWrite)).Post("/catalog/content", s.uploadContent)
	r.With(s.require(auth.PermCatalogWrite)).Post("/catalog/custom", s.createCustom)
	r.With(s.require(auth.PermCatalogOverride)).Put("/catalog/packages/{id}/overrides", s.putOverrides)
	r.With(s.require(auth.PermCatalogOverride)).Put("/catalog/packages/{id}/verification", s.setPackageVerification)
	r.With(s.require(auth.PermCatalogWrite)).Delete("/catalog/packages/{id}", s.deletePackage)
	r.With(s.require(auth.PermCatalogRead)).Get("/catalog/overlays", s.listOverlays)
	r.With(s.require(auth.PermCatalogOverride)).Post("/catalog/overlays", s.addOverlay)
	r.With(s.require(auth.PermCatalogOverride)).Put("/catalog/overlays/{id}", s.updateOverlay)
	r.With(s.require(auth.PermCatalogOverride)).Post("/catalog/overlays/{id}/upload", s.uploadOverlay)
	r.With(s.require(auth.PermCatalogOverride)).Post("/catalog/overlays/{id}/refresh", s.refreshOverlay)
	r.With(s.require(auth.PermCatalogOverride)).Delete("/catalog/overlays/{id}", s.deleteOverlay)
	r.With(s.require(auth.PermCatalogOverride)).Get("/catalog/overlay-template", s.overlayTemplate)
	r.With(s.require(auth.PermCatalogRead)).Get("/settings", s.getSettings)
	r.With(s.require(auth.PermSettingsWrite)).Put("/settings", s.putSettings)

	r.With(s.require(auth.PermDeploymentsRead)).Get("/deployments", s.listDeployments)
	r.With(s.require(auth.PermDeploymentsWrite)).Post("/deployments", s.createDeployment)
	r.With(s.require(auth.PermDeploymentsRead)).Get("/deployments/{id}", s.getDeployment)
	r.With(s.require(auth.PermDeploymentsRead)).Get("/deployments/{id}/jobs", s.deploymentJobs)
	r.With(s.require(auth.PermDeploymentsWrite)).Post("/deployments/{id}/cancel", s.cancelDeployment)
	r.With(s.requireAny(auth.PermDeploymentsRead)).Get("/jobs/{id}", s.getJob)
	r.With(s.requireAny(auth.PermDeploymentsWrite)).Post("/jobs/{id}/retry", s.retryJob)
	r.With(s.requireAny(auth.PermDeploymentsWrite)).Post("/jobs/{id}/cancel", s.cancelJob)
	r.With(s.require(auth.PermGroupsWrite)).Post("/groups/{id}/members", s.changeGroupMembers)

	r.With(s.require(auth.PermEnrollmentRead)).Get("/agent-downloads", s.agentDownloads)
	r.With(s.require(auth.PermEnrollmentRead)).Get("/enrollment-tokens", s.listTokens)
	r.With(s.require(auth.PermEnrollmentWrite)).Post("/enrollment-tokens", s.createToken)
	r.With(s.require(auth.PermSettingsWrite)).Get("/security/master-key", s.getMasterKey)
	r.With(s.require(auth.PermSettingsWrite)).Post("/security/master-key/acknowledge", s.acknowledgeMasterKey)
	r.With(s.require(auth.PermEnrollmentWrite)).Post("/enrollment-tokens/{id}/revoke", s.revokeToken)
	r.With(s.require(auth.PermEnrollmentWrite)).Delete("/enrollment-tokens/{id}", s.deleteToken)

	r.With(s.require(auth.PermAuditRead)).Get("/audit", s.listAudit)
	r.With(s.require(auth.PermAuditRead)).Post("/audit/verify", s.verifyAudit)
	r.With(s.require(auth.PermAuditRead)).Get("/audit.csv", s.auditCSV)
	r.With(s.requireAny(auth.PermDevicesRead)).Get("/events", s.events)

	r.With(s.require(auth.PermScriptsRead)).Get("/scripts", s.listScripts)
	r.With(s.require(auth.PermScriptsWrite)).Post("/scripts", s.createScript)
	r.With(s.require(auth.PermScriptsRead)).Get("/scripts/status", s.scriptStatus)
	r.With(s.require(auth.PermScriptsRun)).Post("/scripts/runs", s.requestScriptRun)
	r.With(s.require(auth.PermScriptsRead)).Get("/scripts/runs", s.listScriptRuns)
	r.With(s.require(auth.PermScriptsRead)).Get("/scripts/runs/{id}", s.getScriptRun)
	r.With(s.require(auth.PermScriptsApprove)).Post("/scripts/runs/{id}/approve", s.approveScriptRun)
	r.With(s.require(auth.PermScriptsApprove)).Post("/scripts/runs/{id}/reject", s.rejectScriptRun)
	r.With(s.require(auth.PermScriptsRun)).Post("/scripts/runs/{id}/cancel", s.cancelScriptRun)
	r.With(s.require(auth.PermScriptsRead)).Get("/scripts/runs/{id}/jobs/{job}/output", s.scriptRunOutput)
	r.With(s.require(auth.PermScriptsRead)).Get("/scripts/{id}", s.getScript)
	r.With(s.require(auth.PermScriptsWrite)).Put("/scripts/{id}", s.updateScript)
	r.With(s.require(auth.PermScriptsWrite)).Delete("/scripts/{id}", s.deleteScript)
	r.With(s.require(auth.PermPoliciesRead)).Get("/policies", s.listPolicies)
	r.With(s.require(auth.PermPoliciesWrite)).Post("/policies", s.createPolicy)
	r.With(s.require(auth.PermPoliciesRead)).Post("/policies/preview", s.previewPolicy)
	r.With(s.require(auth.PermPoliciesRead)).Get("/policies/{id}/apps", s.policyApps)
	r.With(s.require(auth.PermPoliciesWrite)).Put("/policies/{id}", s.updatePolicy)
	r.With(s.require(auth.PermPoliciesWrite)).Delete("/policies/{id}", s.deletePolicy)
	r.With(s.require(auth.PermDeploymentsRead)).Get("/software/approvals", s.softwareApprovals)
	r.With(s.require(auth.PermDeploymentsWrite)).Post("/software/approvals", s.decideSoftware)
	r.With(s.require(auth.PermPoliciesWrite)).Post("/software/holds/{id}/release", s.releaseSoftwareHold)
	r.With(s.require(auth.PermReportsRead)).Get("/reports/overview", s.reportOverview)
	r.With(s.require(auth.PermReportsRead)).Get("/reports/compliance", s.reportCompliance)
	r.With(s.require(auth.PermInventoryExport)).Get("/reports/compliance.csv", s.complianceCSV)
	r.With(s.require(auth.PermReportsRead)).Get("/vulnerabilities", s.listVulnerabilities)
	r.With(s.require(auth.PermReportsRead)).Get("/vulnerabilities/products", s.listVulnProducts)
	r.With(s.require(auth.PermReportsRead)).Get("/vulnerabilities/{cve}/devices", s.vulnerabilityDevices)
	r.With(s.require(auth.PermInventoryExport)).Get("/vulnerabilities.csv", s.vulnerabilitiesCSV)
	r.With(s.require(auth.PermSettingsIntegrations)).Post("/vulnerabilities/sync", s.syncVulnerabilities)
	r.With(s.require(auth.PermSettingsIntegrations)).Post("/vulnerabilities/import", s.importVulnerabilities)
	r.With(s.require(auth.PermSettingsIntegrations)).Post("/vulnerabilities/products", s.addVulnProduct)
	r.With(s.require(auth.PermSettingsIntegrations)).Put("/vulnerabilities/products/{id}", s.setVulnProduct)
	r.With(s.require(auth.PermSettingsIntegrations)).Delete("/vulnerabilities/products/{id}", s.deleteVulnProduct)
	r.With(s.requireDevice(auth.PermDevicesRead)).Get("/devices/{id}/vulnerabilities", s.deviceVulnerabilities)
	r.With(s.require(auth.PermReportsRead)).Get("/reports/lifecycle", s.reportLifecycle)
	r.With(s.require(auth.PermInventoryExport)).Get("/reports/lifecycle.csv", s.lifecycleCSV)
	r.With(s.require(auth.PermInventoryExport)).Get("/reports/compliance.html", s.complianceHTML)

	r.With(s.require(auth.PermBrandingWrite)).Get("/settings/branding", s.getBranding)
	r.With(s.require(auth.PermBrandingWrite)).Put("/settings/branding", s.putBranding)
	r.With(s.require(auth.PermBrandingWrite)).Put("/settings/branding/assets/{kind}", s.putBrandingAsset)
	r.With(s.require(auth.PermBrandingWrite)).Delete("/settings/branding/assets/{kind}", s.deleteBrandingAsset)
	r.With(s.require(auth.PermBrandingWrite)).Post("/settings/branding/reset", s.resetBranding)

	r.With(s.requireAny(auth.PermSitesRead)).Get("/sites", s.listSites)
	r.With(s.require(auth.PermSitesWrite)).Post("/sites", s.createSite)
	r.With(s.require(auth.PermSitesWrite)).Put("/sites/{id}", s.updateSite)
	r.With(s.require(auth.PermSitesWrite)).Delete("/sites/{id}", s.deleteSite)

	r.With(s.require(auth.PermUsersRead)).Get("/users", s.listUsers)
	r.With(s.require(auth.PermUsersWrite)).Post("/users", s.createUser)
	r.With(s.require(auth.PermUsersWrite)).Put("/users/{id}", s.updateUser)
	r.With(s.require(auth.PermUsersWrite)).Post("/users/{id}/roles", s.addBinding)
	r.With(s.require(auth.PermUsersWrite)).Delete("/users/{id}/roles/{bid}", s.removeBinding)
	r.With(s.require(auth.PermUsersWrite)).Post("/users/{id}/reset-password", s.resetUserPassword)
	r.With(s.require(auth.PermUsersWrite)).Post("/users/{id}/reset-mfa", s.resetUserMFA)
	r.With(s.require(auth.PermUsersWrite)).Delete("/users/{id}", s.deleteUser)
	r.With(s.require(auth.PermUsersRead)).Get("/api-tokens", s.listAllAPITokens)
	r.With(s.require(auth.PermUsersWrite)).Delete("/api-tokens/{id}", s.revokeAnyAPIToken)

	r.With(s.requireSelf).Get("/me/security", s.mySecurity)
	r.With(s.requireSelf).Get("/settings/schema", s.settingsSchema)
	r.With(s.requireSelf).Get("/settings/effective", s.settingsEffective)
	r.With(s.requireSelf).Get("/settings/sections/{section}", s.getSettingsSection)
	r.With(s.requireSelf).Put("/settings/sections/{section}", s.putSettingsSection)
	r.With(s.require(auth.PermSettingsWrite)).Get("/settings/export", s.exportSettings)
	r.With(s.require(auth.PermSettingsWrite)).Post("/settings/import", s.importSettings)
	r.With(s.require(auth.PermSettingsWrite)).Get("/settings/about", s.settingsAbout)
	r.With(s.require(auth.PermSettingsWrite)).Get("/settings/support-bundle", s.supportBundle)
	r.With(s.require(auth.PermSettingsData)).Get("/settings/data/status", s.dataStatus)
	r.With(s.require(auth.PermSettingsData)).Post("/settings/data/run-retention", s.runRetention)
	r.With(s.require(auth.PermSettingsReports)).Post("/settings/reports/schedules/{id}/send-now", s.sendReportNow)
	r.With(s.require(auth.PermSettingsReports)).Get("/settings/reports/runs", s.reportRuns)
	r.With(s.require(auth.PermSettingsNotifications)).Post("/settings/notifications/test-email", s.testEmail)
	r.With(s.require(auth.PermSettingsNotifications)).Get("/settings/notifications/log", s.notificationLog)
	r.With(s.require(auth.PermSettingsIntegrations)).Post("/settings/integrations/webhooks/{id}/test", s.testWebhook)
	r.With(s.require(auth.PermSettingsIntegrations)).Get("/settings/events", s.settingsEvents)
	r.With(s.requireSelf).Get("/dashboard", s.dashboard)
	r.With(s.requireSelf).Get("/notifications", s.notifications)
	r.With(s.requireSelf).Post("/notifications/dismiss", s.dismissNotifications)
	r.With(s.requireSelf).Get("/me/preferences", s.getPreferences)
	r.With(s.requireSelf).Put("/me/preferences", s.putPreferences)
	r.With(s.requireSelf).Post("/me/api-tokens", s.createAPIToken)
	r.With(s.requireSelf).Delete("/me/api-tokens/{id}", s.revokeOwnAPIToken)
	r.With(s.requireSelf).Post("/me/security-keys/begin", s.beginSecurityKey)
	r.With(s.requireSelf).Post("/me/security-keys/finish", s.finishSecurityKey)
	r.With(s.requireSelf).Delete("/me/security-keys/{id}", s.deleteSecurityKey)
}

func (s *server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Pool.Ping(ctx); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) sweepLimiters() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		for _, l := range []*auth.Limiter{s.loginIP, s.loginEmail, s.setupIP, s.apiIP} {
			l.Sweep()
		}
	}
}
