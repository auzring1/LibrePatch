package auth

import (
	"slices"
	"strings"

	"github.com/google/uuid"
)

// Permission names checked by API handlers.
const (
	PermDevicesRead      = "devices:read"
	PermDevicesWrite     = "devices:write"
	PermDevicesWake      = "devices:wake"    // send a Wake-on-LAN packet for a sleeping device through another one (D125)
	PermDevicesInspect   = "devices:inspect" // read-only views: running programs, services, event log (administrators only, D125)
	PermEnrollmentRead   = "enrollment:read"
	PermEnrollmentWrite  = "enrollment:write"
	PermAuditRead        = "audit:read"
	PermGroupsRead       = "groups:read"
	PermGroupsWrite      = "groups:write"
	PermInventoryExport  = "inventory:export"
	PermCatalogRead      = "catalog:read"
	PermCatalogWrite     = "catalog:write"
	PermCatalogOverride  = "catalog:override"
	PermDeploymentsRead  = "deployments:read"
	PermDeploymentsWrite = "deployments:write"
	PermSettingsWrite    = "settings:write"
	PermUpdatesRead      = "updates:read"
	PermUpdatesWrite     = "updates:write"  // approve, decline, hide, install, scan, restart
	PermUpdatesPolicy    = "updates:policy" // rules, rings, source settings, releasing holds
	PermReleasesRead     = "releases:read"  // agent releases and rollout progress
	PermReleasesWrite    = "releases:write" // upload releases, choose the target, pause
	PermSitesRead        = "sites:read"
	PermSitesWrite       = "sites:write"
	PermUsersRead        = "users:read"
	PermUsersWrite       = "users:write" // users, role bindings, MFA resets, every API token
	PermPoliciesRead     = "policies:read"
	PermPoliciesWrite    = "policies:write" // auto-update policies and baselines
	PermReportsRead      = "reports:read"
	PermBrandingWrite    = "branding:write" // organization name, product name, colors, login texts and images (administrators only)

	// Settings sections (decision D95). Administrators hold all of them; operators the day-to-day ones.
	PermSettingsAppearance    = "settings:appearance"
	PermSettingsSecurity      = "settings:security"
	PermSettingsNotifications = "settings:notifications"
	PermSettingsUpdates       = "settings:updates"
	PermSettingsDevices       = "settings:devices"
	PermSettingsReports       = "settings:reports"
	PermSettingsData          = "settings:data"
	PermSettingsIntegrations  = "settings:integrations"
)

// Roles.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleReadOnly = "readonly"
)

// Scope types of a role binding.
const (
	ScopeOrg  = "org"
	ScopeSite = "site"
)

var rolePerms = map[string][]string{
	RoleAdmin: {PermDevicesRead, PermDevicesWrite, PermDevicesWake, PermDevicesInspect, PermEnrollmentRead, PermEnrollmentWrite, PermAuditRead,
		PermGroupsRead, PermGroupsWrite, PermInventoryExport,
		PermCatalogRead, PermCatalogWrite, PermCatalogOverride, PermDeploymentsRead, PermDeploymentsWrite, PermSettingsWrite,
		PermUpdatesRead, PermUpdatesWrite, PermUpdatesPolicy, PermReleasesRead, PermReleasesWrite,
		PermSitesRead, PermSitesWrite, PermUsersRead, PermUsersWrite, PermPoliciesRead, PermPoliciesWrite, PermReportsRead,
		PermBrandingWrite,
		PermSettingsAppearance, PermSettingsSecurity, PermSettingsNotifications, PermSettingsUpdates, PermSettingsDevices, PermSettingsReports, PermSettingsData, PermSettingsIntegrations},
	RoleOperator: {PermDevicesRead, PermDevicesWrite, PermDevicesWake, PermEnrollmentRead, PermGroupsRead, PermGroupsWrite, PermInventoryExport,
		PermCatalogRead, PermCatalogWrite, PermDeploymentsRead, PermDeploymentsWrite, PermUpdatesRead, PermUpdatesWrite, PermReleasesRead,
		PermSitesRead, PermPoliciesRead, PermReportsRead,
		PermSettingsNotifications, PermSettingsDevices, PermSettingsReports},
	RoleReadOnly: {PermDevicesRead, PermGroupsRead, PermCatalogRead, PermDeploymentsRead, PermUpdatesRead, PermReleasesRead,
		PermSitesRead, PermPoliciesRead, PermReportsRead},
}

// siteScopable lists the permissions a site-scoped binding can grant. They are the ones that act on
// a single device from its own page; everything else is organization-wide configuration or a
// fleet-wide view and needs an organization-scoped binding (docs/SECURITY.md §9d).
var siteScopable = map[string]bool{
	PermDevicesRead: true, PermDevicesWrite: true, PermDevicesWake: true, PermDevicesInspect: true, PermDeploymentsRead: true, PermDeploymentsWrite: true,
	PermUpdatesRead: true, PermUpdatesWrite: true, PermCatalogRead: true, PermSitesRead: true,
}

// TokenScopable reports whether a permission may be put in an API token. Identity administration
// stays interactive: tokens cannot manage users, roles or other tokens.
func TokenScopable(perm string) bool {
	return perm != PermUsersRead && perm != PermUsersWrite && perm != PermBrandingWrite && (perm == PermSettingsWrite || !strings.HasPrefix(perm, "settings:"))
}

// AllPermissions is every permission name, sorted.
func AllPermissions() []string {
	seen := map[string]bool{}
	for _, ps := range rolePerms {
		for _, p := range ps {
			seen[p] = true
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// ValidRole reports whether role is a known role name.
func ValidRole(role string) bool { _, ok := rolePerms[role]; return ok }

// Grant is one role binding of a user.
type Grant struct {
	Role      string
	ScopeType string
	ScopeID   uuid.UUID
}

// Access is what a caller may do: organization-wide permissions plus permissions limited to sites.
type Access struct {
	Org   map[string]bool
	Sites map[uuid.UUID]map[string]bool
}

// NewAccess builds the access of a user of org from their role bindings. Bindings that point at
// another organization are ignored.
func NewAccess(org uuid.UUID, grants []Grant) Access {
	a := Access{Org: map[string]bool{}, Sites: map[uuid.UUID]map[string]bool{}}
	for _, g := range grants {
		perms, ok := rolePerms[g.Role]
		if !ok {
			continue
		}
		switch g.ScopeType {
		case ScopeOrg:
			if g.ScopeID != org {
				continue
			}
			for _, p := range perms {
				a.Org[p] = true
			}
		case ScopeSite:
			m := a.Sites[g.ScopeID]
			if m == nil {
				m = map[string]bool{}
				a.Sites[g.ScopeID] = m
			}
			for _, p := range perms {
				if siteScopable[p] {
					m[p] = true
				}
			}
		}
	}
	return a
}

// OrgHas reports an organization-wide permission.
func (a Access) OrgHas(perm string) bool { return a.Org[perm] }

// HasAnywhere reports the permission in any scope (used to let a request in; the handler narrows it).
func (a Access) HasAnywhere(perm string) bool {
	if a.Org[perm] {
		return true
	}
	for _, m := range a.Sites {
		if m[perm] {
			return true
		}
	}
	return false
}

// SiteHas reports the permission for devices of the given site.
func (a Access) SiteHas(site uuid.UUID, perm string) bool {
	return a.Org[perm] || a.Sites[site][perm]
}

// SitesFor returns the sites where perm is held without an organization-wide grant. all is true
// when the permission is organization-wide (no filtering needed).
func (a Access) SitesFor(perm string) (all bool, ids []uuid.UUID) {
	if a.Org[perm] {
		return true, nil
	}
	for id, m := range a.Sites {
		if m[perm] {
			ids = append(ids, id)
		}
	}
	slices.SortFunc(ids, func(x, y uuid.UUID) int { return slices.Compare(x[:], y[:]) })
	return false, ids
}

// OrgPermissions lists the organization-wide permissions, sorted.
func (a Access) OrgPermissions() []string { return keys(a.Org) }

// SitePermissions lists, per site, the permissions held only there.
func (a Access) SitePermissions() map[string][]string {
	out := map[string][]string{}
	for id, m := range a.Sites {
		if ps := keys(m); len(ps) > 0 {
			out[id.String()] = ps
		}
	}
	return out
}

// ScopedPermissions is the union of site-limited permissions (what the console needs to decide
// which pages to offer to a site-limited user).
func (a Access) ScopedPermissions() []string {
	u := map[string]bool{}
	for _, m := range a.Sites {
		for p := range m {
			if !a.Org[p] {
				u[p] = true
			}
		}
	}
	return keys(u)
}

// Restrict narrows access to the given scopes (API tokens): nothing outside scopes survives.
func (a Access) Restrict(scopes []string) Access {
	keep := map[string]bool{}
	for _, s := range scopes {
		keep[s] = true
	}
	out := Access{Org: map[string]bool{}, Sites: map[uuid.UUID]map[string]bool{}}
	for p := range a.Org {
		if keep[p] {
			out.Org[p] = true
		}
	}
	for id, m := range a.Sites {
		nm := map[string]bool{}
		for p := range m {
			if keep[p] {
				nm[p] = true
			}
		}
		if len(nm) > 0 {
			out.Sites[id] = nm
		}
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for p, ok := range m {
		if ok {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// PermissionsFor returns the sorted union of permissions for org-scoped roles.
func PermissionsFor(orgRoles []string) []string {
	var out []string
	for _, r := range orgRoles {
		out = append(out, rolePerms[r]...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
