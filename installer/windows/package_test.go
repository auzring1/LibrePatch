package windowsinstaller

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// These tests read the WiX sources as XML. They run on Linux and cannot prove that the MSI works on
// Windows; they pin the security-relevant structure (property names, hidden properties, no shell in any
// custom action, validation coverage) so that an edit cannot silently weaken it. The real build and an
// install/uninstall cycle are the CI job "msi" in .github/workflows/windows.yml.

type node struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Nodes   []node     `xml:",any"`
}

func (n node) attr(name string) string {
	for _, a := range n.Attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func (n node) walk(fn func(node)) {
	fn(n)
	for _, c := range n.Nodes {
		c.walk(fn)
	}
}

func (n node) find(local string) []node {
	var out []node
	n.walk(func(c node) {
		if c.XMLName.Local == local {
			out = append(out, c)
		}
	})
	return out
}

func load(t *testing.T, path string) node {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var n node
	if err := xml.Unmarshal(b, &n); err != nil {
		t.Fatalf("%s is not well-formed XML: %v", path, err)
	}
	return n
}

const wxsNS = "http://wixtoolset.org/schemas/v4/wxs"

func pkg(t *testing.T) node {
	t.Helper()
	root := load(t, "Package.wxs")
	if root.XMLName.Space != wxsNS || root.XMLName.Local != "Wix" {
		t.Fatalf("root element is %v, want {%s}Wix (WiX v4+ schema)", root.XMLName, wxsNS)
	}
	return root
}

func inc(t *testing.T) node {
	t.Helper()
	root := load(t, "Validation.wxi")
	if root.XMLName.Space != wxsNS || root.XMLName.Local != "Include" {
		t.Fatalf("Validation.wxi root is %v", root.XMLName)
	}
	return root
}

// launchConditions returns every launch condition (Package.wxs and the included Validation.wxi).
func launchConditions(t *testing.T) []node {
	t.Helper()
	return append(pkg(t).find("Launch"), inc(t).find("Launch")...)
}

func TestPublicInterfaceIsOnlyServerTokenAllowedjobs(t *testing.T) {
	want := map[string]bool{"SERVER": true, "TOKEN": true, "ALLOWEDJOBS": true, "ALLOWSCRIPTS": true}
	// Other upper-case property names are public on the msiexec command line too; these are the ones
	// that exist for a reason and take no part in the agent command line.
	other := map[string]bool{"AGENTSERVICEPATH": true, "WINBUILD": true, "DQ": true, "ARPNOMODIFY": true, "ARPCOMMENTS": true}
	got := map[string]node{}
	for _, p := range pkg(t).find("Property") {
		id := p.attr("Id")
		if id == strings.ToUpper(id) && !want[id] && !other[id] {
			t.Errorf("unexpected public (upper-case) property %q: the MSI interface is SERVER, TOKEN, ALLOWEDJOBS, ALLOWSCRIPTS", id)
		}
		got[id] = p
	}
	for id := range want {
		p, ok := got[id]
		if !ok {
			t.Fatalf("property %s is not declared", id)
		}
		if p.attr("Secure") != "yes" {
			t.Errorf("%s must be Secure=yes so that it is passed to the elevated install", id)
		}
	}
	// Private (mixed-case) property names used by the sequence must not be upper-case.
	for _, id := range []string{"SetupDir", "AgentArgsServer", "AgentArgsToken", "AgentArgsJobs", "AgentArgsScripts"} {
		if id == strings.ToUpper(id) {
			t.Errorf("%s would be public", id)
		}
	}
}

func TestTokenIsHiddenEverywhereItTravels(t *testing.T) {
	root := pkg(t)
	hidden := map[string]bool{}
	for _, p := range root.find("Property") {
		if p.attr("Hidden") == "yes" {
			hidden[p.attr("Id")] = true
		}
		if strings.EqualFold(p.attr("Id"), "MsiHiddenProperties") {
			t.Error("MsiHiddenProperties must not be authored directly: use Hidden=\"yes\" on the Property elements")
		}
	}
	for _, id := range []string{"TOKEN", "AgentArgsToken", "InstallAgent"} {
		if !hidden[id] {
			t.Errorf("%s must be Hidden=yes (MsiHiddenProperties): it carries the enrollment token", id)
		}
	}
	// Every SetProperty whose value mentions the token, or a property that carries it, must be hidden.
	carriers := regexp.MustCompile(`\[(TOKEN|AgentArgsToken|InstallAgent)\]`)
	for _, sp := range root.find("SetProperty") {
		if carriers.MatchString(sp.attr("Value")) && !hidden[sp.attr("Id")] {
			t.Errorf("SetProperty %s copies the token but is not hidden", sp.attr("Id"))
		}
	}
	// TOKEN may only be consumed by the token argument property and by launch conditions.
	for _, sp := range root.find("SetProperty") {
		if strings.Contains(sp.attr("Value"), "[TOKEN]") && sp.attr("Id") != "AgentArgsToken" {
			t.Errorf("SetProperty %s uses [TOKEN]; only AgentArgsToken may", sp.attr("Id"))
		}
	}
	// The deferred action must receive it as CustomActionData, i.e. through the property named like the action.
	var found bool
	for _, sp := range root.find("SetProperty") {
		if sp.attr("Id") == "InstallAgent" {
			found = true
			v := sp.attr("Value")
			if !strings.HasPrefix(v, `"[SetupDir]librepatch-agent.exe" install `) {
				t.Errorf("InstallAgent must begin with the quoted exe path (WixSilentExec requirement); got %q", v)
			}
			if !strings.Contains(v, "--if-not-installed") {
				t.Error("InstallAgent must pass --if-not-installed so that upgrades and repairs never re-enroll")
			}
			for _, part := range []string{"[AgentArgsServer]", "[AgentArgsToken]", "[AgentArgsJobs]"} {
				if !strings.Contains(v, part) {
					t.Errorf("InstallAgent value lacks %s", part)
				}
			}
		}
	}
	if !found {
		t.Error("no SetProperty provides CustomActionData for InstallAgent")
	}
}

func TestCustomActionsNeverUseShellsOrScripts(t *testing.T) {
	root := pkg(t)
	banned := []string{"cmd.exe", "cmd /", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "msiexec"}
	cas := root.find("CustomAction")
	if len(cas) == 0 {
		t.Fatal("no custom actions found")
	}
	for _, ca := range cas {
		id := ca.attr("Id")
		for _, a := range ca.Attrs {
			switch a.Name.Local {
			case "Id", "Execute", "Impersonate", "Return", "DllEntry", "BinaryRef":
			default:
				t.Errorf("custom action %s uses attribute %s: only the util extension's exec DLL entry points are allowed (no ExeCommand, scripts, FileRef, Property, Value, Directory)", id, a.Name.Local)
			}
		}
		if e := ca.attr("DllEntry"); e != "WixSilentExec64" {
			t.Errorf("custom action %s has DllEntry %q, want WixSilentExec64 (does not log the command line)", id, e)
		}
		if !strings.HasPrefix(ca.attr("BinaryRef"), "Wix4UtilCA_") {
			t.Errorf("custom action %s BinaryRef %q is not the util extension DLL", id, ca.attr("BinaryRef"))
		}
		if ex := ca.attr("Execute"); ex != "deferred" && ex != "rollback" {
			t.Errorf("custom action %s runs %q; it must be deferred or rollback (system context, no session access)", id, ex)
		}
		if ca.attr("Impersonate") != "no" {
			t.Errorf("custom action %s must have Impersonate=no (LocalSystem)", id)
		}
	}
	for _, sp := range root.find("SetProperty") {
		v := strings.ToLower(sp.attr("Value"))
		for _, b := range banned {
			if strings.Contains(v, b) {
				t.Errorf("SetProperty %s mentions %q", sp.attr("Id"), b)
			}
		}
	}
	root.walk(func(n node) {
		switch n.XMLName.Local {
		case "Binary", "ScriptFile", "Script", "ExeCommand":
			t.Errorf("unexpected element %s: no scripts or extra binaries", n.XMLName.Local)
		}
	})
}

func TestInstallUninstallSequencing(t *testing.T) {
	root := pkg(t)
	customs := map[string]node{}
	for _, c := range root.find("Custom") {
		customs[c.attr("Action")] = c
	}
	ia, ok := customs["InstallAgent"]
	if !ok {
		t.Fatal("InstallAgent is not scheduled")
	}
	if ia.attr("Condition") != "NOT Installed" {
		t.Errorf("InstallAgent condition = %q, want exactly 'NOT Installed' (not on repair/uninstall)", ia.attr("Condition"))
	}
	if ia.attr("After") != "RollbackInstallAgent" || customs["RollbackInstallAgent"].attr("After") != "InstallFiles" {
		t.Error("the rollback action must be scheduled after InstallFiles and immediately before InstallAgent")
	}
	rb := customs["RollbackInstallAgent"]
	if !strings.Contains(rb.attr("Condition"), "NOT AGENTSERVICEPATH") {
		t.Errorf("rollback must never touch a machine that already had the agent: condition %q", rb.attr("Condition"))
	}
	ua, ok := customs["UninstallAgent"]
	if !ok {
		t.Fatal("UninstallAgent is not scheduled")
	}
	for _, need := range []string{`REMOVE~="ALL"`, "NOT UPGRADINGPRODUCTCODE"} {
		if !strings.Contains(ua.attr("Condition"), need) {
			t.Errorf("UninstallAgent condition %q lacks %q: a major upgrade must not unenroll the device", ua.attr("Condition"), need)
		}
	}
	if ua.attr("Before") != "RemoveFiles" {
		t.Error("UninstallAgent must run before RemoveFiles (the staged exe is still there)")
	}
	// The hand-over of data must exist for all three actions, and every SetProperty must be ordered
	// before the first deferred action (InstallFiles) is scheduled.
	have := map[string]bool{}
	for _, sp := range root.find("SetProperty") {
		have[sp.attr("Id")] = true
		if sp.attr("Sequence") != "execute" {
			t.Errorf("SetProperty %s: Sequence must be execute (it must also run when the UI is suppressed)", sp.attr("Id"))
		}
	}
	for _, id := range []string{"InstallAgent", "RollbackInstallAgent", "UninstallAgent"} {
		if !have[id] {
			t.Errorf("no CustomActionData for %s", id)
		}
	}
	for _, sp := range root.find("SetProperty") {
		if (sp.attr("Id") == "UninstallAgent" || sp.attr("Id") == "RollbackInstallAgent") && !strings.HasSuffix(sp.attr("Value"), `librepatch-agent.exe" uninstall`) {
			t.Errorf("%s must run exactly `librepatch-agent.exe uninstall`, got %q", sp.attr("Id"), sp.attr("Value"))
		}
	}
}

func TestStagingDirectoryIsOutsideTheAgentTree(t *testing.T) {
	// `librepatch-agent uninstall` removes %ProgramFiles%\LibrePatch entirely and defers file removal to the
	// next reboot when it runs from below %ProgramFiles%\LibrePatch\Agent. The staged copy must therefore
	// live elsewhere.
	root := pkg(t)
	var dirs []node
	for _, d := range root.find("Directory") {
		if d.attr("Id") == "SetupDir" {
			dirs = append(dirs, d)
		}
	}
	if len(dirs) == 0 {
		t.Fatal("SetupDir is not declared")
	}
	for _, d := range dirs {
		name := strings.ToLower(d.attr("Name"))
		if name == "$(setupfolder)" { // resolved from the brand package by the build
			name = strings.ToLower(brand.SetupFolderName)
		}
		if name == strings.ToLower(brand.FolderName) || name == "agent" || strings.Contains(name, `\`) || strings.Contains(name, "/") {
			t.Errorf("SetupDir name %q would put the staged exe inside the tree that `uninstall` deletes", name)
		}
	}
	for _, sd := range root.find("StandardDirectory") {
		if sd.attr("Id") != "ProgramFiles64Folder" {
			t.Errorf("unexpected StandardDirectory %s: the MSI is per-machine, 64-bit", sd.attr("Id"))
		}
	}
	pk := root.find("Package")[0]
	if pk.attr("Scope") != "perMachine" {
		t.Error("Package must be Scope=perMachine")
	}
	if pk.attr("UpgradeCode") == "" || strings.Contains(pk.attr("UpgradeCode"), "$(") {
		t.Error("UpgradeCode must be a fixed GUID")
	}
	if len(root.find("MajorUpgrade")) != 1 {
		t.Error("exactly one MajorUpgrade is required")
	}
}

func TestToolchainIsPinnedAndConsistent(t *testing.T) {
	b, err := os.ReadFile("../../.config/dotnet-tools.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Tools map[string]struct {
			Version string `json:"version"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	wix := m.Tools["wix"].Version
	if !regexp.MustCompile(`^7\.\d+\.\d+$`).MatchString(wix) {
		t.Fatalf(".config/dotnet-tools.json must pin an exact WiX v7 version, got %q", wix)
	}
	for _, f := range []string{"build.ps1", "../../scripts/build-msi.sh", "../../.github/workflows/windows.yml"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(raw)
		if f != "../../.github/workflows/windows.yml" {
			if !strings.Contains(s, "WixToolset.Util.wixext/"+wix) {
				t.Errorf("%s does not pin WixToolset.Util.wixext/%s (same version as the wix tool)", f, wix)
			}
			if !strings.Contains(s, "acceptEula") {
				t.Errorf("%s does not pass the recorded EULA acceptance", f)
			}
		}
		for _, bad := range []string{"-SkipPublisherCheck", "--no-check-certificate", "InsecureSkipVerify", "-k "} {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains %q", f, bad)
			}
		}
	}
}

// ---- launch-condition validation -------------------------------------------------------------

func TestLaunchConditionsFitAndCoverTheDenyList(t *testing.T) {
	conds := launchConditions(t)
	if len(conds) < 10 {
		t.Fatalf("only %d launch conditions", len(conds))
	}
	for _, c := range conds {
		if n := len(c.attr("Condition")); n > 255 {
			t.Errorf("launch condition is %d characters (limit 255): %.60s...", n, c.attr("Condition"))
		}
		if c.attr("Message") == "" {
			t.Errorf("launch condition without a message: %.60s", c.attr("Condition"))
		}
		if _, err := parseCond(c.attr("Condition")); err != nil {
			t.Errorf("cannot parse %q: %v", c.attr("Condition"), err)
		}
	}
	allowed := map[string]string{
		"SERVER":      ".-_:",
		"TOKEN":       ".-_",
		"ALLOWEDJOBS": "_,",
	}
	shape := map[string]func(c string) string{ // a value that passes the shape checks except for the character c
		"SERVER":      func(c string) string { return "host" + c + "x:8443" },
		"TOKEN":       func(c string) string { return "LP1." + c + "x" },
		"ALLOWEDJOBS": func(c string) string { return "inventory" + c + "x" },
	}
	// "[" and "]" are not tested in conditions ("[" is special in MSI formatted text); the agent rejects them.
	for prop, ok := range allowed {
		for r := rune(0x20); r < 0x7f; r++ {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(ok, r) || r == '[' || r == ']' {
				continue
			}
			env := baseEnv()
			fillRequired(env, prop)
			env[prop] = shape[prop](string(r))
			var char bool
			for _, m := range failures(t, conds, env) {
				char = char || strings.Contains(m, "may only contain")
			}
			if !char {
				t.Errorf("%s containing %q is not rejected by the character check", prop, string(r))
			}
		}
		// and the allowed punctuation passes
		for _, r := range ok {
			env := baseEnv()
			fillRequired(env, prop)
			env[prop] = shape[prop](string(r))
			for _, m := range failures(t, conds, env) {
				t.Errorf("%s containing allowed %q is rejected: %s", prop, string(r), m)
			}
		}
	}
}

func baseEnv() map[string]string {
	return map[string]string{"VersionNT64": "1000", "VersionNT": "1000", "WINBUILD": "19045", "Privileged": "1", "DQ": `"`}
}

// fillRequired sets valid values for the required properties other than skip, so that a test isolates one property.
func fillRequired(env map[string]string, skip string) {
	if skip != "SERVER" {
		env["SERVER"] = "librepatch.example.com:8443"
	}
	if skip != "TOKEN" {
		env["TOKEN"] = "LP1.eyJ2IjoxfQ"
	}
}

func failures(t *testing.T, conds []node, env map[string]string) []string {
	t.Helper()
	var out []string
	for _, c := range conds {
		e, err := parseCond(c.attr("Condition"))
		if err != nil {
			t.Fatalf("parse %q: %v", c.attr("Condition"), err)
		}
		if !e.eval(env) {
			out = append(out, c.attr("Message"))
		}
	}
	return out
}

func TestLaunchConditionBehaviour(t *testing.T) {
	conds := launchConditions(t)
	type tc struct {
		name string
		env  map[string]string
		ok   bool
	}
	with := func(kv ...string) map[string]string {
		e := baseEnv()
		for i := 0; i < len(kv); i += 2 {
			e[kv[i]] = kv[i+1]
		}
		return e
	}
	good := []string{"SERVER", "librepatch.example.com:8443", "TOKEN", "LP1.eyJ0b2tlbiI6IngifQ-_x", "ALLOWEDJOBS", "inventory,wu_scan"}
	cases := []tc{
		{"fresh install with all properties", with(good...), true},
		{"fresh install without ALLOWEDJOBS", with("SERVER", "10.0.0.5:8443", "TOKEN", "LP1.abc"), true},
		{"IPv6 server", with("SERVER", "[::1]:8443", "TOKEN", "LP1.abc"), true},
		{"missing SERVER", with("TOKEN", "LP1.abc"), false},
		{"missing TOKEN", with("SERVER", "a.example:8443"), false},
		{"nothing at all on a fresh machine", with(), false},
		{"upgrade of an enrolled machine needs nothing", with("AGENTSERVICEPATH", `"C:\Program Files\LibrePatch\Agent\slot-a\librepatch-agent.exe" service`), true},
		{"uninstall needs nothing", with("Installed", "1"), true},
		{"SERVER without port", with("SERVER", "librepatch.example.com", "TOKEN", "LP1.abc"), false},
		{"TOKEN not an enrollment string", with("SERVER", "a:1", "TOKEN", "hello"), false},
		{"quote injection in SERVER", with("SERVER", `a:1"`, "TOKEN", "LP1.abc"), false},
		{"space in TOKEN", with("SERVER", "a:1", "TOKEN", "LP1.a b"), false},
		{"chained command in ALLOWEDJOBS", with("SERVER", "a:1", "TOKEN", "LP1.abc", "ALLOWEDJOBS", "inventory&calc"), false},
		{"extra argument in SERVER", with("SERVER", "a:1 --data-dir", "TOKEN", "LP1.abc"), false},
		{"Windows 10 1803", with("SERVER", "a:1", "TOKEN", "LP1.abc", "WINBUILD", "17134"), false},
		{"Windows 10 1809 / Server 2019", with("SERVER", "a:1", "TOKEN", "LP1.abc", "WINBUILD", "17763"), true},
		{"Windows 8.1", with("SERVER", "a:1", "TOKEN", "LP1.abc", "VersionNT", "603", "WINBUILD", "9600"), false},
		// Windows Installer itself reports 603 / 9600 on some Windows 10/11 machines; the registry build number decides.
		{"Windows 11 as reported by a shimmed installer", with("SERVER", "a:1", "TOKEN", "LP1.abc", "VersionNT", "603", "VersionNT64", "603", "WindowsBuild", "9600", "WINBUILD", "26100"), true},
		{"build number not readable", func() map[string]string {
			e := with("SERVER", "a:1", "TOKEN", "LP1.abc")
			delete(e, "WINBUILD")
			return e
		}(), false},
		{"32-bit Windows", func() map[string]string {
			e := with("SERVER", "a:1", "TOKEN", "LP1.abc")
			delete(e, "VersionNT64")
			return e
		}(), false},
		{"not elevated", func() map[string]string {
			e := with("SERVER", "a:1", "TOKEN", "LP1.abc")
			delete(e, "Privileged")
			return e
		}(), false},
	}
	for _, c := range cases {
		f := failures(t, conds, c.env)
		if c.ok && len(f) > 0 {
			t.Errorf("%s: rejected with %q", c.name, f)
		}
		if !c.ok && len(f) == 0 {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

// ---- a small evaluator for the subset of the MSI condition grammar that the sources use ---------

type expr interface {
	eval(env map[string]string) bool
}

type (
	orE   struct{ l, r expr }
	andE  struct{ l, r expr }
	notE  struct{ e expr }
	propE struct{ name string }
	cmpE  struct {
		op   string
		l, r operand
	}
	operand struct {
		lit   string
		prop  string
		isLit bool
	}
)

func (e orE) eval(m map[string]string) bool   { return e.l.eval(m) || e.r.eval(m) }
func (e andE) eval(m map[string]string) bool  { return e.l.eval(m) && e.r.eval(m) }
func (e notE) eval(m map[string]string) bool  { return !e.e.eval(m) }
func (e propE) eval(m map[string]string) bool { return m[e.name] != "" }
func (o operand) val(m map[string]string) string {
	if o.isLit {
		return o.lit
	}
	return m[o.prop]
}
func (e cmpE) eval(m map[string]string) bool {
	l, r := e.l.val(m), e.r.val(m)
	switch e.op {
	case "><":
		return r != "" && strings.Contains(l, r)
	case "<<":
		return r != "" && strings.HasPrefix(l, r)
	case ">>":
		return r != "" && strings.HasSuffix(l, r)
	case "=":
		return l == r
	case "~=":
		return strings.EqualFold(l, r)
	case "<>":
		return l != r
	}
	a, errA := strconv.Atoi(l)
	b, errB := strconv.Atoi(r)
	if errA != nil || errB != nil {
		return false // MSI compares a missing/non-numeric property as false
	}
	switch e.op {
	case ">=":
		return a >= b
	case "<=":
		return a <= b
	case ">":
		return a > b
	case "<":
		return a < b
	}
	return false
}

type parser struct {
	toks []string
	pos  int
}

var tokRe = regexp.MustCompile(`^\s*("[^"]*"|\(|\)|><|<<|>>|>=|<=|<>|~=|=|<|>|[A-Za-z_][A-Za-z0-9_.]*|[0-9]+)`)

func parseCond(s string) (expr, error) {
	p := &parser{}
	rest := s
	for strings.TrimSpace(rest) != "" {
		m := tokRe.FindStringSubmatch(rest)
		if m == nil {
			return nil, fmt.Errorf("unexpected input %q", rest)
		}
		p.toks = append(p.toks, m[1])
		rest = rest[len(m[0]):]
	}
	e, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("trailing token %q", p.toks[p.pos])
	}
	return e, nil
}

func (p *parser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *parser) or() (expr, error) {
	l, err := p.and()
	for err == nil && strings.EqualFold(p.peek(), "OR") {
		p.pos++
		var r expr
		if r, err = p.and(); err == nil {
			l = orE{l, r}
		}
	}
	return l, err
}

func (p *parser) and() (expr, error) {
	l, err := p.not()
	for err == nil && strings.EqualFold(p.peek(), "AND") {
		p.pos++
		var r expr
		if r, err = p.not(); err == nil {
			l = andE{l, r}
		}
	}
	return l, err
}

func (p *parser) not() (expr, error) {
	if strings.EqualFold(p.peek(), "NOT") {
		p.pos++
		e, err := p.not()
		return notE{e}, err
	}
	return p.cmp()
}

func (p *parser) cmp() (expr, error) {
	if p.peek() == "(" {
		p.pos++
		e, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("missing )")
		}
		p.pos++
		return e, nil
	}
	l, err := p.operand()
	if err != nil {
		return nil, err
	}
	switch op := p.peek(); op {
	case "><", "<<", ">>", ">=", "<=", "<>", "~=", "=", "<", ">":
		p.pos++
		r, err := p.operand()
		if err != nil {
			return nil, err
		}
		return cmpE{op, l, r}, nil
	}
	if l.isLit {
		return nil, fmt.Errorf("bare literal %q", l.lit)
	}
	return propE{l.prop}, nil
}

func (p *parser) operand() (operand, error) {
	t := p.peek()
	switch {
	case t == "":
		return operand{}, fmt.Errorf("unexpected end")
	case strings.HasPrefix(t, `"`):
		p.pos++
		return operand{lit: strings.Trim(t, `"`), isLit: true}, nil
	case unicode.IsDigit(rune(t[0])):
		p.pos++
		return operand{lit: t, isLit: true}, nil
	case unicode.IsLetter(rune(t[0])) || t[0] == '_':
		if u := strings.ToUpper(t); u == "AND" || u == "OR" || u == "NOT" {
			return operand{}, fmt.Errorf("unexpected %s", t)
		}
		p.pos++
		return operand{prop: t}, nil
	}
	return operand{}, fmt.Errorf("unexpected %q", t)
}

func TestWorkflowJobMSI(t *testing.T) {
	b, err := os.ReadFile("../../.github/workflows/windows.yml")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(b), "\r\n", "\n") // a Windows checkout may have converted the line endings
	i := strings.Index(s, "\n  msi:\n")
	if i < 0 {
		t.Fatal("job msi is missing from windows.yml")
	}
	job := s[i:]
	for _, want := range []string{"runs-on: windows-2025", "continue-on-error: true", "installer/windows/build.ps1", "/x ", "1603"} {
		if !strings.Contains(job, want) {
			t.Errorf("job msi lacks %q", want)
		}
	}
	pin := regexp.MustCompile(`uses: [\w./-]+@[0-9a-f]{40} # v`)
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "uses:") && !pin.MatchString(line) {
			t.Errorf("action not pinned by SHA: %s", strings.TrimSpace(line))
		}
	}
}

// ALLOWSCRIPTS=1 switches on running scripts (D127). Only its exact value "1" is looked at: it is never put into a command line.
func TestAllowScriptsIsOnlyComparedNeverPassedOn(t *testing.T) {
	root := pkg(t)
	for _, sp := range root.find("SetProperty") {
		if strings.Contains(sp.attr("Value"), "[ALLOWSCRIPTS]") {
			t.Errorf("%s passes ALLOWSCRIPTS on to a command line", sp.attr("Id"))
		}
	}
	found := false
	for _, sp := range root.find("SetProperty") {
		if sp.attr("Id") == "AgentArgsScripts" {
			found = true
			if sp.attr("Value") != " --allow-scripts" || !strings.Contains(sp.attr("Condition"), `ALLOWSCRIPTS="1"`) {
				t.Errorf("AgentArgsScripts must add a fixed flag only for ALLOWSCRIPTS=\"1\": %q if %q", sp.attr("Value"), sp.attr("Condition"))
			}
		}
	}
	if !found {
		t.Fatal("AgentArgsScripts is missing")
	}
}
