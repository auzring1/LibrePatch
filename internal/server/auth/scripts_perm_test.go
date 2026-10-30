package auth

import (
	"testing"

	"github.com/google/uuid"
)

// Running code as SYSTEM on endpoints is for administrators only, for the whole organization, and never through an API token (D127).
func TestScriptPermissionsAreAdministratorOnlyOrgWideAndNeverInATokenScope(t *testing.T) {
	org := uuid.New()
	site := uuid.New()
	perms := []string{PermScriptsRead, PermScriptsWrite, PermScriptsRun, PermScriptsApprove}
	admin := NewAccess(org, []Grant{{Role: RoleAdmin, ScopeType: ScopeOrg, ScopeID: org}})
	for _, p := range perms {
		if !admin.OrgHas(p) {
			t.Errorf("an administrator lacks %s", p)
		}
		if TokenScopable(p) {
			t.Errorf("%s can be put in an API token", p)
		}
		for _, role := range []string{RoleOperator, RoleReadOnly} {
			if NewAccess(org, []Grant{{Role: role, ScopeType: ScopeOrg, ScopeID: org}}).OrgHas(p) {
				t.Errorf("%s has %s", role, p)
			}
		}
		// A site-scoped administrator does not get them: they are not device-page permissions.
		if NewAccess(org, []Grant{{Role: RoleAdmin, ScopeType: ScopeSite, ScopeID: site}}).OrgHas(p) {
			t.Errorf("a site-scoped administrator has %s organization-wide", p)
		}
	}
}

// Removing a person's profile deletes their files on a computer: administrators only, never through an API token (D157). A
// site-scoped administrator may do it for the devices of their own site, like the other device-page actions.
func TestRemovingAProfileIsForAdministratorsOnlyAndNeverATokenScope(t *testing.T) {
	org, site := uuid.New(), uuid.New()
	if !NewAccess(org, []Grant{{Role: RoleAdmin, ScopeType: ScopeOrg, ScopeID: org}}).OrgHas(PermDevicesProfiles) {
		t.Error("an administrator lacks devices:profiles")
	}
	for _, role := range []string{RoleOperator, RoleReadOnly} {
		if NewAccess(org, []Grant{{Role: role, ScopeType: ScopeOrg, ScopeID: org}}).OrgHas(PermDevicesProfiles) {
			t.Errorf("%s may remove profiles", role)
		}
	}
	if TokenScopable(PermDevicesProfiles) {
		t.Error("devices:profiles can be put in an API token")
	}
	if !siteScopable[PermDevicesProfiles] || !NewAccess(org, []Grant{{Role: RoleAdmin, ScopeType: ScopeSite, ScopeID: site}}).SiteHas(site, PermDevicesProfiles) {
		t.Error("a site administrator can remove profiles on their own site's devices")
	}
}
