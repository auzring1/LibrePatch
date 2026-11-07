package wingetindex

import (
	"os"
	"testing"
)

// TestRealIndex reads a real source2.msix when LIBREPATCH_WINGET_INDEX_FILE points at one (a manual check, not part of
// CI: the file is downloaded from Microsoft).
func TestRealIndex(t *testing.T) {
	path := os.Getenv("LIBREPATCH_WINGET_INDEX_FILE")
	if path == "" {
		t.Skip("set LIBREPATCH_WINGET_INDEX_FILE to a downloaded source2.msix")
	}
	b, err := os.ReadFile(path) // #nosec G304 -- test input chosen by the developer
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseMSIX(b)
	if err != nil {
		t.Fatal(err)
	}
	pc, nn, np := 0, 0, 0
	byID := map[string]Package{}
	for _, p := range s.Packages {
		pc += len(p.ProductCodes)
		nn += len(p.NormNames)
		np += len(p.NormPublishers)
		byID[p.ID] = p
	}
	t.Logf("packages=%d productcodes=%d normnames=%d normpublishers=%d modified=%s", len(s.Packages), pc, nn, np, s.Modified)
	c := byID["Google.Chrome"]
	t.Logf("chrome: %+v", c)
	if c.LatestVersion == "" || len(c.ProductCodes) != 3 || len(c.NormNames) != 1 || c.NormNames[0] != "googlechrome" || c.NormPublishers[0] != "google" {
		t.Fatalf("unexpected Chrome entry: %+v", c)
	}
}

// TestRealIndexNormalizationAgrees checks the name normalization against the index itself: normalizing a package's own
// name should give one of the normalized names the index lists for it, for nearly every package.
func TestRealIndexNormalizationAgrees(t *testing.T) {
	path := os.Getenv("LIBREPATCH_WINGET_INDEX_FILE")
	if path == "" {
		t.Skip("set LIBREPATCH_WINGET_INDEX_FILE to a downloaded source2.msix")
	}
	b, err := os.ReadFile(path) // #nosec G304 -- test input chosen by the developer
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseMSIX(b)
	if err != nil {
		t.Fatal(err)
	}
	ok := 0
	for _, p := range s.Packages {
		n, a := NormalizeName(p.Name)
		for _, k := range p.NormNames {
			if k == n || k == n+"("+a+")" {
				ok++
				break
			}
		}
	}
	rate := float64(ok) / float64(len(s.Packages))
	t.Logf("%d of %d package names normalize to a listed name (%.2f%%)", ok, len(s.Packages), rate*100)
	if rate < 0.99 {
		t.Fatalf("agreement %.2f%% is below 99%%", rate*100)
	}
}
