package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/server/policies"
)

// An all-apps policy that adds apps to the catalog by itself is a catalog change: policies:write alone is not enough (D132).
func TestAllAppsPolicyThatImportsNeedsCatalogWrite(t *testing.T) {
	s := &server{}
	call := func(perms map[string]bool, in policies.Input) (bool, int) {
		r := httptest.NewRequest("POST", "/api/v1/policies", nil)
		r = r.WithContext(context.WithValue(r.Context(), ctxPrincipal, &Principal{Access: auth.Access{Org: perms}}))
		w := httptest.NewRecorder()
		ok := s.mayImport(w, r, &in)
		return ok, w.Code
	}
	imports := policies.Input{Kind: policies.KindAll, Filter: &policies.AutoFilter{IncludeUnlisted: true}}
	plain := policies.Input{Kind: policies.KindAll, Filter: &policies.AutoFilter{VerifiedOnly: true}}
	one := policies.Input{Kind: "keep_updated"}

	writer := map[string]bool{auth.PermPoliciesWrite: true}
	both := map[string]bool{auth.PermPoliciesWrite: true, auth.PermCatalogWrite: true}
	if ok, code := call(writer, imports); ok || code != http.StatusForbidden {
		t.Fatalf("policies:write alone must not add apps to the catalog: %v %d", ok, code)
	}
	if ok, _ := call(both, imports); !ok {
		t.Fatal("policies:write with catalog:write may")
	}
	for _, in := range []policies.Input{plain, one, {Kind: policies.KindAll}} {
		if ok, _ := call(writer, in); !ok {
			t.Fatalf("a policy that does not import needs no catalog permission: %+v", in)
		}
	}
}
