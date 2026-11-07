package branding

import (
	"encoding/json"
	"math"
	"os"
	"testing"
)

type vectors struct {
	Ratios []struct {
		A, B  string
		Ratio float64
	}
	Accents []struct {
		Accent, Secondary string
		OK                bool
		Why               string
	}
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/contrast_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestContrastReferenceRatios(t *testing.T) {
	for _, c := range loadVectors(t).Ratios {
		got, err := Contrast(c.A, c.B)
		if err != nil {
			t.Fatal(err)
		}
		if math.Abs(math.Round(got*100)/100-c.Ratio) > 0.005 {
			t.Errorf("Contrast(%s,%s) = %.3f, want %.2f", c.A, c.B, got, c.Ratio)
		}
		back, _ := Contrast(c.B, c.A)
		if back != got {
			t.Errorf("contrast must be symmetric: %v vs %v", got, back)
		}
	}
	if _, err := Contrast("red", "#ffffff"); err == nil {
		t.Error("a color name is not a #rrggbb color")
	}
}

func TestAccentChecks(t *testing.T) {
	for _, c := range loadVectors(t).Accents {
		fails := Failing(Checks(c.Accent, c.Secondary))
		if (len(fails) == 0) != c.OK {
			t.Errorf("accent %q secondary %q: ok=%v, want %v (%s): %+v", c.Accent, c.Secondary, len(fails) == 0, c.OK, c.Why, fails)
		}
	}
}

func TestDefaultAccentPasses(t *testing.T) {
	if f := Failing(Checks(DefaultAccent, "")); len(f) != 0 {
		t.Fatalf("the built-in accent must pass its own rules: %+v", f)
	}
}

// TestBlockedColorsAreRejected: the server enforces the contrast rule, whatever the browser did.
func TestBlockedColorsAreRejected(t *testing.T) {
	_, err := Validate(Settings{AccentColor: "#ffd43b"})
	ve, ok := err.(*ValidationError)
	if !ok || ve.Fields["accent_color"] == "" {
		t.Fatalf("a yellow accent must be refused with a message on accent_color: %v", err)
	}
	_, err = Validate(Settings{AccentColor: "#1971c2", SecondaryColor: "#ffff99"})
	ve, ok = err.(*ValidationError)
	if !ok || ve.Fields["secondary_color"] == "" || ve.Fields["accent_color"] != "" {
		t.Fatalf("a pale secondary must be refused on secondary_color only: %v", err)
	}
	if _, err := Validate(Settings{AccentColor: "#C92A2A"}); err != nil {
		t.Fatalf("a deep red accent is fine: %v", err)
	}
}
