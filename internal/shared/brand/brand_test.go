package brand

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, f, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(f), "..", "..", ".."))
}

var skipDirs = map[string]bool{".git": true, "node_modules": true, ".claude": true, "gen": true, "dist": true,
	"loadtest-results": true, "dist-demo": true, "dist-release": true, "test-results": true, "playwright-report": true}

// walk calls fn for every text file of the repository that can reach a user.
func walk(t *testing.T, fn func(rel string, data []byte)) {
	t.Helper()
	root := repoRoot(t)
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			// Generated protobuf code sits under gen/ at the repository root only; the web console has its own gen-free tree.
			if skipDirs[d.Name()] && !(d.Name() == "dist" && !strings.HasPrefix(rel, "internal/")) {
				return filepath.SkipDir
			}
			if rel == "db/migrations" { // applied migrations are immutable
				return filepath.SkipDir
			}
			return nil
		}
		switch rel {
		case "go.sum", "web/package-lock.json":
			return nil
		}
		switch filepath.Ext(rel) {
		case ".syso", ".png", ".ico", ".woff", ".woff2", ".gz", ".zip", ".exe", ".age":
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil || !utf8Text(data) {
			return nil
		}
		fn(rel, data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func utf8Text(b []byte) bool {
	for _, c := range b[:min(len(b), 4096)] {
		if c == 0 {
			return false
		}
	}
	return true
}

// githubOrg is the GitHub organisation (the author's account), which appears in repository paths.
var githubOrg = regexp.MustCompile(`auzring1`)

// Assembled so this file does not contain the words it forbids.
var previousNames = []string{"reno" + "vatio", "auz" + "ring"}

// previousForms are the spellings of the name the product had before this one ("Current" is also an ordinary English
// word, so only the forms that can mean nothing but the product are forbidden). Lower case, matched case-insensitively.
var previousForms = []string{
	"curr" + "ent-agent", "curr" + "ent-server", "curr" + "ent-release", "curr" + "ent-sbom", "curr" + "ent-loadsim", "curr" + "ent-deploy",
	"curr" + "entagent", "curr" + "entstage", "curr" + "entsetup", "the curr" + "ent contributors",
	"curr" + "ent_app", "curr" + "ent_owner", "curr" + "ent_admin", "curr" + "ent.agent.v1", "urn:curr" + "ent:", "x-curr" + "ent-",
	"__host-cur_", "auzring1/curr" + "ent", "ghcr.io/auzring1/curr" + "ent",
}

// previousEnvPrefix matches the environment variable prefix of the previous name (not HKEY_CURRENT_USER and the like).
var previousEnvPrefix = regexp.MustCompile(`(^|[^A-Za-z0-9_])CURR` + `ENT_([A-TV-Z]|U[A-RT-Z])`)

// TestPreviousNameIsGone fails when a previous product name (in any spelling) or a form of the one before this appears anywhere in the repository,
// except as the GitHub organisation (the author's account) in a repository path. A document may name the old
// files it tells you to delete between <!-- old-names:begin --> and <!-- old-names:end -->, or on a line marked
// <!-- old-name -->.
func TestPreviousNameIsGone(t *testing.T) {
	var bad []string
	walk(t, func(rel string, data []byte) {
		if rel == "internal/shared/brand/brand_test.go" {
			return
		}
		inOldNames := false
		for i, line := range strings.Split(string(data), "\n") {
			if strings.HasSuffix(rel, ".md") {
				if strings.Contains(line, "<!-- old-names:begin -->") {
					inOldNames = true
				}
				if inOldNames {
					if strings.Contains(line, "<!-- old-names:end -->") {
						inOldNames = false
					}
					continue
				}
				if strings.Contains(line, "<!-- old-name -->") {
					continue
				}
			}
			// A line of any file type can be marked as naming an old file or setting on purpose.
			if strings.Contains(line, "<!-- old-name -->") || strings.Contains(line, "# old-name") {
				continue
			}
			l := strings.ToLower(githubOrg.ReplaceAllString(line, ""))
			hit := previousEnvPrefix.MatchString(line)
			for _, old := range previousNames {
				if strings.Contains(l, old) {
					hit = true
				}
			}
			for _, old := range previousForms {
				if strings.Contains(strings.ToLower(line), old) {
					hit = true
				}
			}
			if hit {
				bad = append(bad, rel+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
	})
	if len(bad) > 0 {
		t.Fatalf("a previous product name is still spelled in %d places (use the brand package, the generated web constants or the WiX defines):\n%s",
			len(bad), strings.Join(bad, "\n"))
	}
}

// TestNoCustomerNames fails when a customer's name is baked into code, seed data, defaults or docs. A deployment's
// organization name is configuration (Settings > Branding, or the first-run wizard), never source.
func TestNoCustomerNames(t *testing.T) {
	// Assembled so this file does not contain the words it forbids.
	banned := []string{"whit" + "man", "medical " + "clinics"}
	var bad []string
	walk(t, func(rel string, data []byte) {
		if rel == "internal/shared/brand/brand_test.go" {
			return
		}
		low := strings.ToLower(string(data))
		for _, b := range banned {
			if i := strings.Index(low, b); i >= 0 {
				bad = append(bad, rel+": contains "+strconv.Quote(b)+" near line "+strconv.Itoa(1+strings.Count(low[:i], "\n")))
			}
		}
	})
	if len(bad) > 0 {
		t.Fatalf("customer names must not appear in the repository:\n%s", strings.Join(bad, "\n"))
	}
}

// TestNameIsNotHardCoded fails when the product's derived names are typed into a Go string literal, a web
// source file or an MSI attribute: they must come from the single source of truth.
//
// The Go and web checks look for the forms that can only mean the product (the agent's name and the Windows service
// name); the MSI and the page template, which contain no ordinary prose, are checked for the bare name.
func TestNameIsNotHardCoded(t *testing.T) {
	forms := []string{AgentName, ServiceName, StageFolderName, SetupFolderName, KeyPrefix}
	hasForm := func(v string) bool {
		for _, f := range forms {
			if strings.Contains(v, f) {
				return true
			}
		}
		return false
	}
	var bad []string
	root := repoRoot(t)
	walk(t, func(rel string, data []byte) {
		switch {
		case strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go") && !strings.HasPrefix(rel, "internal/shared/brand/"):
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, filepath.Join(root, rel), data, 0)
			if err != nil {
				return
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, err := strconv.Unquote(lit.Value); err == nil && hasForm(v) {
						bad = append(bad, rel+":"+strconv.Itoa(fset.Position(lit.Pos()).Line)+": "+lit.Value)
					}
				}
				return true
			})
		case strings.HasPrefix(rel, "web/src/") && rel != "web/src/brand.generated.ts" && !strings.HasSuffix(rel, "schema.d.ts") &&
			(strings.HasSuffix(rel, ".ts") || strings.HasSuffix(rel, ".tsx")) && !strings.HasSuffix(rel, ".test.ts"):
			for i, line := range strings.Split(string(data), "\n") {
				if hasForm(line) {
					bad = append(bad, rel+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
				}
			}
		case strings.HasSuffix(rel, ".wxs") || strings.HasSuffix(rel, ".wxi"):
			noComments := regexp.MustCompile(`(?s)<!--.*?-->`).ReplaceAllString(string(data), "")
			// Whole word only.
			if regexp.MustCompile(`\b` + Name + `\b`).MatchString(noComments) {
				bad = append(bad, rel+": the product name is spelled in an attribute; use $(ProductName), $(AgentName) or $(Company)")
			}
		case rel == "web/index.html":
			if regexp.MustCompile(`\b` + Name + `\b`).MatchString(string(data)) {
				bad = append(bad, rel+": the server fills the title from the deployment's branding")
			}
		}
	})
	if len(bad) > 0 {
		t.Fatalf("the product's names must come from internal/shared/brand, not be typed:\n%s", strings.Join(bad, "\n"))
	}
}

// TestGeneratedWebConstantsMatch keeps the web console's generated module in step with the Go constants.
func TestGeneratedWebConstantsMatch(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "web", "src", "brand.generated.ts"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`PRODUCT_NAME = "` + Name + `"`, `AGENT_NAME = "` + AgentName + `"`, `COMPANY_NAME = "` + Company + `"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("web/src/brand.generated.ts lacks %s (run: go generate ./internal/shared/brand)", want)
		}
	}
}

// TestAgentVersionResource checks that the compiled Windows version resource says what Task Manager and the
// file properties should show.
func TestAgentVersionResource(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "cmd", "librepatch-agent", "rsrc_windows_amd64.syso"))
	if err != nil {
		t.Fatal(err)
	}
	utf16le := func(s string) []byte {
		var out []byte
		for _, u := range utf16.Encode([]rune(s)) {
			out = append(out, byte(u), byte(u>>8))
		}
		return out
	}
	for _, s := range []string{AgentName, Name, Company} {
		if !strings.Contains(string(b), string(utf16le(s))) {
			t.Errorf("the agent's version resource does not contain %q (regenerate: make winres)", s)
		}
	}
}
