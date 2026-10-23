package vulns

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseCPE23(t *testing.T) {
	good := map[string]CPE{
		"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*":                     {"a", "google", "chrome", "*"},
		`cpe:2.3:a:notepad-plus-plus:notepad\+\+:8.1.1:*:*:*:*:*:*:*`: {"a", "notepad-plus-plus", "notepad++", "8.1.1"},
		"cpe:2.3:o:microsoft:windows_11_24h2:-:*:*:*:*:*:x64:*":       {"o", "microsoft", "windows_11_24h2", "-"},
		`cpe:2.3:a:vendor:pro\:duct:1.0:*:*:*:*:*:*:*`:                {"a", "vendor", "pro:duct", "1.0"},
		"CPE:2.3:a:x:y:1:*:*:*:*:*:*:*":                               {},
	}
	for in, want := range good {
		got, err := ParseCPE23(in)
		if want == (CPE{}) {
			if err == nil {
				t.Errorf("%q accepted", in)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%q: %+v %v, want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "cpe:2.2:a:x:y", "cpe:2.3:a:google", "cpe:2.3:a::chrome:1", "cpe:2.3:a:x:" + strings.Repeat("y", 700) + ":1:*:*:*:*:*:*:*"} {
		if _, err := ParseCPE23(bad); err == nil {
			t.Errorf("%.40q accepted", bad)
		}
	}
	if c, _ := ParseCPE23("cpe:2.3:a:g:c:*:*:*:*:*:*:*:*"); !c.Any() {
		t.Error("* means any version")
	}
}

func TestParseKEV(t *testing.T) {
	es, err := ParseKEV(fixture(t, "kev.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 2 {
		t.Fatalf("a malformed id and a duplicate are skipped: %+v", es)
	}
	a, b := es[0], es[1]
	if a.CVE != "CVE-2026-0001" || a.Ransomware || a.Added == nil || a.Added.Format("2006-01-02") != "2026-10-01" || a.Due == nil || a.Due.Format("2006-01-02") != "2026-10-22" || !strings.Contains(a.Name, "Type Confusion") {
		t.Fatalf("first: %+v", a)
	}
	if b.CVE != "CVE-2026-0002" || !b.Ransomware {
		t.Fatalf("an id in lower case is normalized and ransomware use is read: %+v", b)
	}
	for name, in := range map[string]string{"not json": "hello", "empty catalog": `{"vulnerabilities":[]}`, "only bad ids": `{"vulnerabilities":[{"cveID":"x"}]}`} {
		if _, err := ParseKEV([]byte(in)); err == nil {
			t.Errorf("%s accepted: an empty catalog would clear every exploited mark", name)
		}
	}
}

func TestParseNVD(t *testing.T) {
	tracked := Tracked{
		{"google", "chrome"}:               true,
		{"microsoft", "windows_11_24h2"}:   true,
		{"microsoft", "windows_10_22h2"}:   true,
		{"notepad-plus-plus", "notepad++"}: true,
	}
	p, err := ParseNVD(fixture(t, "nvd_page.json"), tracked)
	if err != nil {
		t.Fatal(err)
	}
	if p.TotalResults != 5 || p.StartIndex != 0 || len(p.CVEs) != 5 {
		t.Fatalf("page: %+v", p)
	}
	by := map[string]CVE{}
	for _, c := range p.CVEs {
		by[c.ID] = c
	}

	chrome := by["CVE-2026-0001"]
	if chrome.Severity != "high" || chrome.CVSS == nil || *chrome.CVSS != 8.8 || !strings.HasPrefix(chrome.Summary, "Type confusion in V8") || chrome.Published == nil || len(chrome.Ranges) != 1 {
		t.Fatalf("chrome: %+v", chrome)
	}
	r := chrome.Ranges[0]
	if r.Vendor != "google" || r.Product != "chrome" || r.StartKey != nil || r.EndText != "130.0.6723.58" || r.EndIncl || !bytes.Equal(r.EndKey, vercmp.Key("130.0.6723.58")) {
		t.Fatalf("chrome range: %+v", r)
	}

	win := by["CVE-2026-0002"]
	if len(win.Ranges) != 2 {
		t.Fatalf("a nested (AND) configuration keeps the vulnerable products and drops the platform: %+v", win.Ranges)
	}
	w11 := win.Ranges[0]
	if w11.Product != "windows_11_24h2" || !w11.StartIncl || !bytes.Equal(w11.StartKey, vercmp.Key("10.0.26100.0")) || !bytes.Equal(w11.EndKey, vercmp.Key("10.0.26100.2033")) {
		t.Fatalf("windows 11 range: %+v", w11)
	}

	np := by["CVE-2026-0003"]
	if np.Severity != "medium" || np.CVSS == nil || *np.CVSS != 5.0 {
		t.Fatalf("a CVSS 2 severity beside the data: %+v", np)
	}
	if len(np.Ranges) != 2 || np.Ranges[0].Product != "notepad++" || np.Ranges[0].StartText != "8.1.1" || np.Ranges[0].EndText != "8.1.1" || !np.Ranges[0].StartIncl || !np.Ranges[0].EndIncl {
		t.Fatalf("exact versions become one-version ranges, an untracked product is dropped: %+v", np.Ranges)
	}

	if !by["CVE-2026-0004"].Rejected {
		t.Fatal("a rejected CVE must be marked so what was stored can go")
	}
	un := by["CVE-2026-0005"]
	if un.Rejected || un.CVSS != nil || un.Severity != "" || len(un.Ranges) != 0 {
		t.Fatalf("an unanalyzed CVE has no score and no ranges: %+v", un)
	}

	// With no filter every vulnerable product is kept.
	all, _ := ParseNVD(fixture(t, "nvd_page.json"), nil)
	n := 0
	for _, c := range all.CVEs {
		if c.ID == "CVE-2026-0003" {
			n = len(c.Ranges)
		}
	}
	if n != 3 {
		t.Fatalf("no filter keeps all products: %d", n)
	}

	for name, in := range map[string]string{"not json": "x", "not an NVD answer": `{"hello":1}`} {
		if _, err := ParseNVD([]byte(in), nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// An empty page of a real response is fine.
	if p, err := ParseNVD([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":7,"vulnerabilities":[]}`), nil); err != nil || p.TotalResults != 7 || len(p.CVEs) != 0 {
		t.Fatalf("an empty page: %+v %v", p, err)
	}
}

// "-" in a CPE name means "not applicable": the product without a version. It is not a statement that every version is affected.
func TestACPEWithoutAVersionIsNotEveryVersion(t *testing.T) {
	if _, ok := rangeFor(nvdMatch{Vulnerable: true, Criteria: "cpe:2.3:a:mozilla:firefox:-:*:*:*:*:*:*:*"}, nil); ok {
		t.Fatal(`"-" must not become a range`)
	}
	if r, ok := rangeFor(nvdMatch{Vulnerable: true, Criteria: "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*"}, nil); !ok || r.StartKey != nil || r.EndKey != nil {
		t.Fatalf(`"*" with no bounds is every version: %+v %v`, r, ok)
	}
	if r, ok := rangeFor(nvdMatch{Vulnerable: true, Criteria: "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*", EndExcluding: "3.0.12"}, nil); !ok || r.EndText != "3.0.12" {
		t.Fatalf("a bound is kept: %+v %v", r, ok)
	}
}
