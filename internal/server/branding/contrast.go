package branding

import (
	"fmt"
	"math"
	"strconv"
)

// Colors the console is drawn on. The checks below are what the interface actually does with the accent
// color, so a color that fails here cannot be saved (WCAG 2.1 AA).
const (
	White       = "#ffffff" // light theme page background and the text color on accent buttons
	DarkSurface = "#1a1b1e" // dark theme page background
	// MinText is the contrast WCAG AA asks of normal-size text (success criterion 1.4.3).
	MinText = 4.5
	// MinUI is the contrast WCAG AA asks of user-interface components and graphics (success criterion 1.4.11).
	MinUI = 3.0
)

// Check is one foreground/background pair with its measured and required contrast ratio.
type Check struct {
	ID         string  `json:"id"`
	Label      string  `json:"label"`
	Foreground string  `json:"foreground"`
	Background string  `json:"background"`
	Ratio      float64 `json:"ratio"`
	Required   float64 `json:"required"`
	Pass       bool    `json:"pass"`
}

func parseHex(c string) (r, g, b uint8, err error) {
	if len(c) != 7 || c[0] != '#' {
		return 0, 0, 0, fmt.Errorf("%q is not a color like #1971c2", c)
	}
	v, err := strconv.ParseUint(c[1:], 16, 32)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("%q is not a color like #1971c2", c)
	}
	return uint8(v >> 16), uint8(v >> 8), uint8(v), nil // #nosec G115 -- masked by the shifts of a 24-bit value
}

func channel(c uint8) float64 {
	s := float64(c) / 255
	if s <= 0.04045 { // WCAG 2.1 uses 0.03928; the difference changes no result at 8 bits
		return s / 12.92
	}
	return math.Pow((s+0.055)/1.055, 2.4)
}

// luminance is the WCAG relative luminance of a #rrggbb color.
func luminance(c string) (float64, error) {
	r, g, b, err := parseHex(c)
	if err != nil {
		return 0, err
	}
	return 0.2126*channel(r) + 0.7152*channel(g) + 0.0722*channel(b), nil
}

// Contrast is the WCAG contrast ratio of two #rrggbb colors, from 1 to 21.
func Contrast(a, b string) (float64, error) {
	la, err := luminance(a)
	if err != nil {
		return 0, err
	}
	lb, err := luminance(b)
	if err != nil {
		return 0, err
	}
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05), nil
}

func check(id, label, fg, bg string, required float64) Check {
	ratio, _ := Contrast(fg, bg)
	ratio = math.Round(ratio*100) / 100
	return Check{ID: id, Label: label, Foreground: fg, Background: bg, Ratio: ratio, Required: required, Pass: ratio >= required}
}

// Checks lists the contrast pairs for an accent color and an optional secondary color (both #rrggbb; an empty
// accent means the default). The accent is used for button backgrounds with white text, for links on white,
// and for outlines on the dark theme; the secondary color marks the active menu entry and similar graphics.
func Checks(accent, secondary string) []Check {
	if accent == "" {
		accent = DefaultAccent
	}
	out := []Check{
		check("accent_text_light", "Button text (white) on the accent color, and accent links on the white page", White, accent, MinText),
		check("accent_ui_dark", "Accent outlines and focus rings on the dark theme", accent, DarkSurface, MinUI),
	}
	if secondary != "" {
		out = append(out,
			check("secondary_ui_light", "Secondary color graphics on the white page", secondary, White, MinUI),
			check("secondary_ui_dark", "Secondary color graphics on the dark theme", secondary, DarkSurface, MinUI),
		)
	}
	return out
}

// Failing returns the checks that do not reach their required ratio.
func Failing(checks []Check) []Check {
	var bad []Check
	for _, c := range checks {
		if !c.Pass {
			bad = append(bad, c)
		}
	}
	return bad
}
