package sbom

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testEpoch = 1700000000

func TestGoBinarySBOMOfTestBinary(t *testing.T) {
	// The running test binary carries build info with the modules this package's tests link.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := FromGoBinary(exe, GoOptions{Version: "v9.9.9", Name: "sbom-test", Epoch: testEpoch})
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(doc); err != nil {
		t.Fatalf("generated SBOM does not validate: %v\n%s", err, doc)
	}
	var b BOM
	if err := json.Unmarshal(doc, &b); err != nil {
		t.Fatal(err)
	}
	if b.Metadata.Timestamp != "2023-11-14T22:13:20Z" {
		t.Errorf("timestamp %q does not come from the supplied epoch", b.Metadata.Timestamp)
	}
	if got := b.Metadata.Component; got.Name != "sbom-test" || got.Version != "v9.9.9" || got.Type != "application" {
		t.Errorf("subject component = %+v", got)
	}
	var std bool
	for _, c := range b.Components {
		if c.Name == "stdlib" && strings.HasPrefix(c.PURL, "pkg:golang/stdlib@") {
			std = true
		}
	}
	if !std {
		t.Error("no stdlib component")
	}
	// Same input, same bytes (the SBOM takes part in the reproducibility check).
	doc2, err := FromGoBinary(exe, GoOptions{Version: "v9.9.9", Name: "sbom-test", Epoch: testEpoch})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(doc, doc2) {
		t.Error("the SBOM is not deterministic")
	}
}

func TestGoBinaryNeedsVersion(t *testing.T) {
	exe, _ := os.Executable()
	if _, err := FromGoBinary(exe, GoOptions{}); err == nil {
		t.Fatal("expected an error without a version")
	}
	if _, err := FromGoBinary(filepath.Join(t.TempDir(), "missing"), GoOptions{Version: "v1"}); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestGoSumHash(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	h, ok := goSumHash("h1:" + base64.StdEncoding.EncodeToString(raw))
	if !ok || h != "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" {
		t.Fatalf("goSumHash = %q %v", h, ok)
	}
	for _, bad := range []string{"", "h1:", "h1:!!!", "h1:AAAA", "sha256:abc", "h2:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="} {
		if _, ok := goSumHash(bad); ok {
			t.Errorf("goSumHash(%q) accepted", bad)
		}
	}
}

func TestPurlEscaping(t *testing.T) {
	if got := purlEscape("v1.2.3+incompatible"); got != "v1.2.3%2Bincompatible" {
		t.Errorf("purlEscape = %q", got)
	}
	if got := purlPath("github.com/go-chi/chi/v5"); got != "github.com/go-chi/chi/v5" {
		t.Errorf("purlPath = %q", got)
	}
	if got := npmPurlName("@mantine/core"); got != "%40mantine/core" {
		t.Errorf("npmPurlName = %q", got)
	}
}

const sampleLock = `{
  "name": "demo-web", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": {"name": "demo-web", "version": "1.0.0", "license": "UNLICENSED",
         "dependencies": {"@scope/ui": "1.0.0", "left": "2.0.0"},
         "devDependencies": {"tool": "3.0.0"}},
    "node_modules/@scope/ui": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/@scope/ui/-/ui-1.0.0.tgz",
         "integrity": "sha512-Aup7aUOfpbAUg2ROOJN6Iw5f9DMBlzu0mIkm/malLQFN/YQgO48wCj0Kxa3sEHJvPVFg7siR+qRInwXd2qhQKw==",
         "license": "MIT", "dependencies": {"left": "^2.0.0", "shared": "^1.0.0"}},
    "node_modules/left": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/left/-/left-2.0.0.tgz",
         "integrity": "sha1-qvmK1m3Tl5HtSRkDGHXYw4XhVLM=", "license": "(MIT OR Apache-2.0)"},
    "node_modules/shared": {"version": "1.0.0", "license": "ISC"},
    "node_modules/@scope/ui/node_modules/left": {"version": "1.5.0", "license": "Weird-License"},
    "node_modules/tool": {"version": "3.0.0", "dev": true, "license": "GPL-3.0-only", "dependencies": {"shared": "^1"}},
    "node_modules/only-dev": {"version": "1.0.0", "dev": true, "license": "MIT"},
    "node_modules/fsevents": {"version": "2.0.0", "devOptional": true, "license": "MIT"}
  }
}`

func TestNPMProductionClosure(t *testing.T) {
	doc, err := fromNPMLock([]byte(sampleLock), NPMOptions{Version: "v1.2.3", Epoch: testEpoch})
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(doc); err != nil {
		t.Fatalf("%v\n%s", err, doc)
	}
	var b BOM
	if err := json.Unmarshal(doc, &b); err != nil {
		t.Fatal(err)
	}
	got := map[string]Component{}
	for _, c := range b.Components {
		got[c.PURL] = c
	}
	for _, want := range []string{
		"pkg:npm/%40scope/ui@1.0.0", "pkg:npm/left@2.0.0", "pkg:npm/shared@1.0.0", "pkg:npm/left@1.5.0",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s; have %v", want, keys(got))
		}
	}
	for _, bad := range []string{"pkg:npm/tool@3.0.0", "pkg:npm/only-dev@1.0.0", "pkg:npm/fsevents@2.0.0"} {
		if _, ok := got[bad]; ok {
			t.Errorf("dev-only package %s leaked into the production SBOM", bad)
		}
	}
	ui := got["pkg:npm/%40scope/ui@1.0.0"]
	if ui.Group != "@scope" || ui.Name != "ui" {
		t.Errorf("scoped name not split: group %q name %q", ui.Group, ui.Name)
	}
	if len(ui.Hashes) != 1 || ui.Hashes[0].Alg != "SHA-512" || len(ui.Hashes[0].Content) != 128 {
		t.Errorf("integrity not converted: %+v", ui.Hashes)
	}
	if l := got["pkg:npm/left@2.0.0"]; len(l.Hashes) != 1 || l.Hashes[0].Alg != "SHA-1" || len(l.Licenses) != 1 || l.Licenses[0].Expression != "(MIT OR Apache-2.0)" {
		t.Errorf("left@2.0.0 = %+v", l)
	}
	if l := got["pkg:npm/left@1.5.0"]; len(l.Licenses) != 1 || l.Licenses[0].License == nil || l.Licenses[0].License.Name != "Weird-License" {
		t.Errorf("non-SPDX license should be a name: %+v", l.Licenses)
	}
	// Node resolution: @scope/ui requires left, and gets its nested 1.5.0, not the top-level 2.0.0.
	deps := map[string][]string{}
	for _, d := range b.Dependencies {
		deps[d.Ref] = d.DependsOn
	}
	if !contains(deps["pkg:npm/%40scope/ui@1.0.0"], "pkg:npm/left@1.5.0") || contains(deps["pkg:npm/%40scope/ui@1.0.0"], "pkg:npm/left@2.0.0") {
		t.Errorf("nested resolution wrong: %v", deps["pkg:npm/%40scope/ui@1.0.0"])
	}
	rootDeps := deps[b.Metadata.Component.BOMRef]
	if !contains(rootDeps, "pkg:npm/left@2.0.0") || contains(rootDeps, "pkg:npm/tool@3.0.0") {
		t.Errorf("root deps = %v", rootDeps)
	}
	again, err := fromNPMLock([]byte(sampleLock), NPMOptions{Version: "v1.2.3", Epoch: testEpoch})
	if err != nil || !bytes.Equal(doc, again) {
		t.Error("the npm SBOM is not deterministic")
	}
}

func TestNPMRejectsOldLockfile(t *testing.T) {
	if _, err := fromNPMLock([]byte(`{"lockfileVersion":1,"dependencies":{}}`), NPMOptions{Version: "v1"}); err == nil {
		t.Fatal("lockfile v1 accepted")
	}
	if _, err := fromNPMLock([]byte(`not json`), NPMOptions{Version: "v1"}); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := fromNPMLock([]byte(sampleLock), NPMOptions{}); err == nil {
		t.Fatal("missing version accepted")
	}
}

// TestRealWebLockfile builds the SBOM of the repository's own package-lock.json and validates it.
func TestRealWebLockfile(t *testing.T) {
	lock := filepath.Join("..", "..", "web", "package-lock.json")
	if _, err := os.Stat(lock); err != nil {
		t.Skip("web/package-lock.json not present")
	}
	doc, err := FromNPMLock(lock, NPMOptions{Version: "v0.0.0-test", Epoch: testEpoch})
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(doc); err != nil {
		t.Fatal(err)
	}
	var b BOM
	_ = json.Unmarshal(doc, &b)
	if len(b.Components) < 10 {
		t.Fatalf("only %d production components in the real lockfile", len(b.Components))
	}
	for _, c := range b.Components {
		if c.Name == "vite" || c.Name == "vitest" || c.Name == "typescript" {
			t.Errorf("dev tool %s in the production SBOM", c.Name)
		}
		if len(c.Hashes) == 0 {
			t.Errorf("%s has no integrity hash", c.PURL)
		}
	}
	// Every production license must be one the allow-list (scripts/check-licenses.sh) accepts.
	for _, c := range b.Components {
		for _, l := range c.Licenses {
			s := l.Expression
			if l.License != nil {
				s = l.License.ID + l.License.Name
			}
			if !permissive(s) && !fontException(c.PURL, s) {
				t.Errorf("%s has a license outside the allow-list: %s", c.PURL, s)
			}
		}
	}
}

// fontException: the console bundles the Inter typeface unmodified under the SIL Open Font License 1.1 (decision D93).
// The OFL allows bundling and redistributing a font with software; it is accepted for fonts only, and only for this
// package, so it does not widen the allow-list for code.
func fontException(purl, license string) bool {
	return license == "OFL-1.1" && strings.HasPrefix(purl, "pkg:npm/%40fontsource-variable/inter@")
}

func permissive(expr string) bool {
	ok := map[string]bool{"MIT": true, "ISC": true, "Apache-2.0": true, "BSD-2-Clause": true, "BSD-3-Clause": true, "0BSD": true, "MPL-2.0": true}
	for _, part := range strings.Split(strings.NewReplacer("(", " ", ")", " ").Replace(expr), " OR ") {
		if ok[strings.TrimSpace(part)] {
			return true
		}
	}
	return false
}

func TestCheckRejectsMalformed(t *testing.T) {
	good, err := fromNPMLock([]byte(sampleLock), NPMOptions{Version: "v1", Epoch: testEpoch})
	if err != nil {
		t.Fatal(err)
	}
	mut := func(f func(m map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(good, &m); err != nil {
			t.Fatal(err)
		}
		f(m)
		out, _ := json.Marshal(m)
		return out
	}
	first := func(m map[string]any) map[string]any { return m["components"].([]any)[0].(map[string]any) }
	cases := map[string][]byte{
		"not json":      []byte("{"),
		"wrong format":  mut(func(m map[string]any) { m["bomFormat"] = "SPDX" }),
		"wrong spec":    mut(func(m map[string]any) { m["specVersion"] = "1.4" }),
		"bad serial":    mut(func(m map[string]any) { m["serialNumber"] = "123" }),
		"bad timestamp": mut(func(m map[string]any) { m["metadata"].(map[string]any)["timestamp"] = "yesterday" }),
		"no subject":    mut(func(m map[string]any) { delete(m["metadata"].(map[string]any), "component") }),
		"no components": mut(func(m map[string]any) { m["components"] = []any{} }),
		"bad type":      mut(func(m map[string]any) { first(m)["type"] = "gizmo" }),
		"no name":       mut(func(m map[string]any) { first(m)["name"] = "" }),
		"bad purl":      mut(func(m map[string]any) { first(m)["purl"] = "npm/x@1" }),
		"short hash": mut(func(m map[string]any) {
			first(m)["hashes"] = []any{map[string]any{"alg": "SHA-256", "content": "abcd"}}
		}),
		"unknown hash alg": mut(func(m map[string]any) { first(m)["hashes"] = []any{map[string]any{"alg": "CRC32", "content": "abcd"}} }),
		"dangling depends": mut(func(m map[string]any) { m["dependencies"] = []any{map[string]any{"ref": "nope"}} }),
		"duplicate bom-ref": mut(func(m map[string]any) {
			c := m["components"].([]any)
			first(m)["bom-ref"] = c[1].(map[string]any)["bom-ref"]
		}),
		"empty license": mut(func(m map[string]any) { first(m)["licenses"] = []any{map[string]any{"license": map[string]any{}}} }),
	}
	for name, doc := range cases {
		if err := Check(doc); err == nil {
			t.Errorf("%s: Check accepted a malformed document", name)
		}
	}
	if err := Check(good); err != nil {
		t.Fatalf("control document rejected: %v", err)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func keys(m map[string]Component) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
