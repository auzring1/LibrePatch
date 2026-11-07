package e2e

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	sconfig "github.com/auzring1/librepatch/internal/server/config"
)

// manifestSource serves the 7-Zip test manifests as if they came from the winget repository.
type manifestSource struct{ t *testing.T }

func (manifestSource) Versions(context.Context, string) ([]string, error) {
	return []string{"24.09"}, nil
}
func (m manifestSource) Manifests(context.Context, string, string) ([][]byte, error) {
	var out [][]byte
	for _, f := range []string{"7zip.version.yaml", "7zip.installer.yaml", "7zip.locale.yaml"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "internal", "server", "catalog", "testdata", f))
		if err != nil {
			m.t.Fatal(err)
		}
		out = append(out, b)
	}
	return out, nil
}

// An administrator marks a winget package verified after testing it; the mark is audited, shown in the package, and only
// people with the override permission can set it.
func TestAdministratorMarksAPackageVerified(t *testing.T) {
	h := newHarnessCfg(t, 90*24*time.Hour, func(c *sconfig.Config) { c.WingetSource = "github" })
	h.setupAndLogin()
	h.app.Catalog.Source = manifestSource{t}

	st, imp := h.do("POST", "/api/v1/catalog/import", map[string]any{"identifier": "7zip.7zip"}, nil)
	if st != 201 {
		t.Fatalf("import: %d %v", st, imp)
	}
	id := imp["package_id"].(string)
	pkg := func() (map[string]any, map[string]any) {
		st, d := h.do("GET", "/api/v1/catalog/packages/"+id, nil, nil)
		if st != 200 {
			t.Fatalf("package: %d %v", st, d)
		}
		ver, _ := d["verification"].(map[string]any)
		return d["package"].(map[string]any), ver
	}
	if p, ver := pkg(); p["verified"] != false || p["verified_source"] != "" || ver != nil {
		t.Fatalf("a fresh import is unverified: %v %v", p, ver)
	}

	// Without the permission nothing changes.
	op := h.orgUser("operator@example.com", "operator")
	if st, b := op.do("PUT", "/api/v1/catalog/packages/"+id+"/verification", map[string]any{"verified": true}, nil); st != 403 {
		t.Fatalf("an operator may not verify packages: %d %v", st, b)
	}

	if st, b := h.do("PUT", "/api/v1/catalog/packages/"+id+"/verification", map[string]any{"verified": true}, nil); st != 204 {
		t.Fatalf("verify: %d %v", st, b)
	}
	p, ver := pkg()
	if p["verified"] != true || p["verified_source"] != "organization" || ver == nil || ver["version"] != "24.09" || ver["by"] == "" || ver["at"] == nil {
		t.Fatalf("after marking: %v %v", p, ver)
	}
	if h.auditCount("catalog.verify") != 1 {
		t.Fatal("the mark must be audited")
	}
	d := h.auditDetails("catalog.verify")
	if d["identifier"] != "7zip.7zip" || d["after"].(map[string]any)["verified"] != true || d["before"].(map[string]any)["verified"] != false {
		t.Fatalf("audit details: %v", d)
	}
	// The list shows it too.
	st, list := h.do("GET", "/api/v1/catalog/packages", nil, nil)
	items, _ := list["items"].([]any)
	if st != 200 || len(items) != 1 || items[0].(map[string]any)["verified_source"] != "organization" {
		t.Fatalf("list: %d %v", st, list)
	}

	if st, b := h.do("PUT", "/api/v1/catalog/packages/"+id+"/verification", map[string]any{"verified": false}, nil); st != 204 {
		t.Fatalf("unverify: %d %v", st, b)
	}
	if p, ver := pkg(); p["verified"] != false || ver != nil {
		t.Fatalf("after removing the mark: %v %v", p, ver)
	}
	if h.auditCount("catalog.unverify") != 1 {
		t.Fatal("removing the mark must be audited")
	}
	if st, _ := h.do("PUT", "/api/v1/catalog/packages/00000000-0000-0000-0000-000000000001/verification", map[string]any{"verified": true}, nil); st != 404 {
		t.Fatalf("unknown package: %d", st)
	}
}
