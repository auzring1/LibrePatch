package wingetindex

import (
	"math/rand/v2"
	"os"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/mini-source2.msix")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseMSIXReadsPackagesAndKeys(t *testing.T) {
	s, err := ParseMSIX(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Packages) != 711 {
		t.Fatalf("packages = %d, want 711", len(s.Packages))
	}
	if s.Modified.Unix() != 1791572758 {
		t.Fatalf("modified = %v", s.Modified)
	}
	var chrome, filler *Package
	for i := range s.Packages {
		switch s.Packages[i].ID {
		case "Google.Chrome":
			chrome = &s.Packages[i]
		case "Vendor699.App699":
			filler = &s.Packages[i]
		}
	}
	if chrome == nil || chrome.LatestVersion != "155.0.8059.40" || len(chrome.ProductCodes) != 2 || chrome.ProductCodes[0] != "{74badaf7-9d73-386e-b2e4-2d4b3416a469}" ||
		len(chrome.NormNames) != 1 || chrome.NormNames[0] != "googlechrome" || chrome.NormPublishers[0] != "google" {
		t.Fatalf("chrome = %+v", chrome)
	}
	// The filler rows come from deep inside the b-trees (interior pages): every one must have its five product codes.
	if filler == nil || len(filler.ProductCodes) != 5 || filler.NormNames[0] != "fillerapp699" {
		t.Fatalf("filler = %+v", filler)
	}
	for _, p := range s.Packages {
		if len(p.ID) > 8 && p.ID[:6] == "Vendor" && len(p.ProductCodes) != 5 {
			t.Fatalf("%s has %d product codes", p.ID, len(p.ProductCodes))
		}
	}
}

func TestParseMSIXRefusesWhatIsNotAnIndex(t *testing.T) {
	for name, b := range map[string][]byte{"empty": nil, "garbage": []byte("this is not a zip file at all"), "text": make([]byte, 5000)} {
		if _, err := ParseMSIX(b); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := ParseDB([]byte("SQLite format 3\x00 and then nothing sensible")); err == nil {
		t.Fatal("a truncated database was accepted")
	}
}

// The file comes from the network: damaged input must produce an error or a result, never a panic or a hang.
func TestParseDBSurvivesDamage(t *testing.T) {
	dbBytes := mustDB(t)
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 400; i++ {
		b := append([]byte(nil), dbBytes...)
		switch i % 3 {
		case 0: // flip a few bytes anywhere
			for j := 0; j < 1+i%7; j++ {
				b[rng.IntN(len(b))] ^= byte(1 + rng.IntN(255))
			}
		case 1: // truncate
			b = b[:rng.IntN(len(b))]
		default: // damage a page header region
			p := rng.IntN(len(b)/4096) * 4096
			for j := 0; j < 12 && p+j < len(b); j++ {
				b[p+j] = byte(rng.IntN(256))
			}
		}
		_, _ = ParseDB(b)
	}
}

func mustDB(t *testing.T) []byte {
	t.Helper()
	// The database inside the fixture package.
	s := fixture(t)
	d, err := extractDB(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
