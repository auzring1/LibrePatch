package auth

import (
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPasswordHashVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") || NeedsRehash(h) {
		t.Fatalf("unexpected hash format %q", h)
	}
	if !VerifyPassword("correct horse battery", h) {
		t.Fatal("valid password rejected")
	}
	if VerifyPassword("wrong", h) || VerifyPassword("correct horse battery", "") || VerifyPassword("x", "$bcrypt$x") {
		t.Fatal("invalid password accepted")
	}
	// Hostile parameters are refused rather than computed.
	if VerifyPassword("x", "$argon2id$v=19$m=99999999,t=3,p=2$AAAA$AAAA") {
		t.Fatal("hostile params accepted")
	}
}

func TestPasswordPolicy(t *testing.T) {
	bad := []string{"short", "aaaaaaaaaaaaaaaa", "qwertyuiopasdfghjkl", "alice@example.com", strings.Repeat("x", 300)}
	for _, pw := range bad {
		if ValidatePassword(pw, "alice@example.com") == nil {
			t.Errorf("weak password %q accepted", pw)
		}
	}
	if err := ValidatePassword("Granite-Lantern-Pickle-42", "alice@example.com"); err != nil {
		t.Fatalf("good password rejected: %v", err)
	}
	if len(commonPasswords()) < 1000 {
		t.Fatal("breach list not loaded")
	}
}

func TestTOTPRFC6238Vector(t *testing.T) {
	// RFC 6238 Appendix B, SHA1 secret "12345678901234567890", T=59 -> 94287082 (8 digits); 6-digit = 287082.
	secret := []byte("12345678901234567890")
	if got := TOTPCode(secret, 59/30); got != "287082" {
		t.Fatalf("got %s", got)
	}
	now := time.Unix(1111111109, 0) // vector -> 07081804 -> 081804
	if got := TOTPCode(secret, TOTPStep(now)); got != "081804" {
		t.Fatalf("got %s", got)
	}
	step, ok := VerifyTOTP(secret, "081804", now.Add(25*time.Second))
	if !ok || step != TOTPStep(now) {
		t.Fatal("skew window not honoured")
	}
	if _, ok := VerifyTOTP(secret, "081804", now.Add(5*time.Minute)); ok {
		t.Fatal("stale code accepted")
	}
	if _, ok := VerifyTOTP(secret, "abc", now); ok {
		t.Fatal("malformed code accepted")
	}
	if !strings.HasPrefix(TOTPURI(brand.Name, "a@b.c", secret), "otpauth://totp/"+brand.Name+":a@b.c?") {
		t.Fatal(TOTPURI(brand.Name, "a@b.c", secret))
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := NewRecoveryCodes(RecoveryCodeCount)
	if err != nil || len(codes) != 10 {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 14 || !LooksLikeRecoveryCode(c) || seen[c] {
			t.Fatalf("bad code %q", c)
		}
		seen[c] = true
		if string(HashRecoveryCode(strings.ToUpper(c))) != string(HashRecoveryCode(" "+c+" ")) {
			t.Fatal("normalization mismatch")
		}
	}
	if LooksLikeRecoveryCode("123456") {
		t.Fatal("TOTP code classified as recovery code")
	}
}

func TestRBAC(t *testing.T) {
	for _, x := range PermissionsFor([]string{RoleReadOnly}) {
		switch x {
		case PermDevicesRead, PermGroupsRead, PermCatalogRead, PermDeploymentsRead, PermUpdatesRead, PermReleasesRead, PermSitesRead, PermPoliciesRead, PermReportsRead:
		default:
			t.Fatalf("read-only role has %s", x)
		}
	}
	for _, x := range PermissionsFor([]string{RoleOperator}) {
		switch x {
		case PermCatalogOverride, PermSettingsWrite, PermUpdatesPolicy, PermReleasesWrite, PermSitesWrite, PermUsersRead, PermUsersWrite, PermPoliciesWrite, PermBrandingWrite:
			t.Fatalf("operator has %s: overrides, settings, update policy, releases, sites, users, automation policies and branding are admin-only", x)
		}
	}
	if !slices.Contains(PermissionsFor([]string{RoleAdmin}), PermBrandingWrite) {
		t.Fatal("administrators manage branding")
	}
	if TokenScopable(PermBrandingWrite) {
		t.Fatal("branding cannot be delegated to an API token")
	}
	if got := len(PermissionsFor([]string{RoleAdmin})); got != len(AllPermissions()) {
		t.Fatalf("the admin role must hold every permission: %d of %d", got, len(AllPermissions()))
	}
}

func TestSiteScopedAccess(t *testing.T) {
	org, a, b := uuid.New(), uuid.New(), uuid.New()
	acc := NewAccess(org, []Grant{
		{Role: RoleOperator, ScopeType: ScopeSite, ScopeID: a},
		{Role: RoleReadOnly, ScopeType: ScopeSite, ScopeID: b},
		{Role: RoleAdmin, ScopeType: ScopeOrg, ScopeID: uuid.New()}, // another organization: ignored
	})
	if len(acc.Org) != 0 {
		t.Fatal("a site binding or a foreign-organization binding must grant nothing organization-wide")
	}
	if !acc.SiteHas(a, PermDevicesWrite) || acc.SiteHas(b, PermDevicesWrite) || acc.SiteHas(uuid.New(), PermDevicesRead) {
		t.Fatal("site grants must stay in their site")
	}
	if acc.SiteHas(a, PermGroupsWrite) || acc.SiteHas(a, PermUsersWrite) || acc.HasAnywhere(PermAuditRead) || acc.HasAnywhere(PermCatalogWrite) {
		t.Fatal("organization-level permissions must not be grantable per site")
	}
	if all, ids := acc.SitesFor(PermDevicesWrite); all || len(ids) != 1 || ids[0] != a {
		t.Fatalf("SitesFor: %v %v", all, ids)
	}
	if all, ids := acc.SitesFor(PermDevicesRead); all || len(ids) != 2 {
		t.Fatalf("SitesFor read: %v %v", all, ids)
	}
	full := NewAccess(org, []Grant{{Role: RoleAdmin, ScopeType: ScopeOrg, ScopeID: org}})
	if !full.SiteHas(a, PermDevicesWrite) || !full.OrgHas(PermUsersWrite) {
		t.Fatal("an org admin holds everything everywhere")
	}
	r := full.Restrict([]string{PermDevicesRead})
	if !r.OrgHas(PermDevicesRead) || r.OrgHas(PermDevicesWrite) || r.OrgHas(PermUsersWrite) {
		t.Fatal("a token's scopes must narrow its owner's access")
	}
	if TokenScopable(PermUsersWrite) || TokenScopable(PermUsersRead) || !TokenScopable(PermDevicesRead) {
		t.Fatal("identity administration must not be token-scopable")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(1, time.Minute, 3)
	for i := 0; i < 3; i++ {
		if !l.Allow("ip") {
			t.Fatal("burst not allowed")
		}
	}
	if l.Allow("ip") {
		t.Fatal("over-limit request allowed")
	}
	if !l.Allow("other") {
		t.Fatal("keys must be independent")
	}
}

// Flooding the limiter with made-up keys must not reset the bucket of a key that is being attacked.
func TestLimiterKeepsBusyKeysWhenFull(t *testing.T) {
	l := NewLimiter(1, time.Hour, 2)
	l.maxKeys = 50
	victim := "victim@example.test"
	for i := 0; i < 2; i++ {
		if !l.Allow(victim) {
			t.Fatal("the burst must be allowed")
		}
	}
	if l.Allow(victim) {
		t.Fatal("the burst is spent")
	}
	for i := 0; i < 500; i++ {
		l.Allow(fmt.Sprintf("noise-%d", i))
		if i%5 == 0 && l.Allow(victim) { // the attack on the account goes on while the table is being flooded
			t.Fatal("filling the table with other keys reset the victim's bucket")
		}
	}
	if l.Allow(victim) {
		t.Fatal("filling the table with other keys reset the victim's bucket")
	}
	if n := len(l.entries); n > l.maxKeys {
		t.Fatalf("table grew to %d entries, limit %d", n, l.maxKeys)
	}
}
