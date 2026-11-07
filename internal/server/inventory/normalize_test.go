package inventory

import "testing"

func TestNormalizeName(t *testing.T) {
	cases := []struct{ name, version, want string }{
		{"Google Chrome", "130.0.6723.92", "google chrome"},
		{"Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33135", "14.38.33135", "microsoft visual c++ 2015-2022 redistributable"},
		{"Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.38.33135", "14.38.33135", "microsoft visual c++ 2015-2022 redistributable"},
		{"7-Zip 23.01 (x64 edition)", "23.01", "7-zip"},
		{"7-Zip 24.08", "24.08", "7-zip"},
		{"Notepad++ (64-bit x64)", "8.7.1", "notepad++"},
		{"Microsoft Visual Studio Code (User)", "1.93.1", "microsoft visual studio code"},
		{"Microsoft Visual Studio Code", "1.93.1", "microsoft visual studio code"},
		{"Mozilla Firefox (x64 en-US)", "131.0", "mozilla firefox"},
		{"Python 3.12.4 (64-bit)", "3.12.4150.0", "python"},
		{"Zoom Workplace (64-bit)", "6.2.5", "zoom workplace"},
		{"Microsoft Office Professional Plus 2019 - en-us", "16.0.10416", "microsoft office professional plus 2019 - en-us"},
		{"Adobe Acrobat™ ® (64-bit)", "24.1", "adobe acrobat"},
		{"Git version 2.46.0", "2.46.0", "git version"},
		{"Slack", "4.40.128", "slack"},
		{"Microsoft.WindowsCalculator", "11.2.0.0", "microsoft.windowscalculator"},
		{"  Spaced   Out   App  ", "", "spaced out app"},
		{"1.2.3", "1.2.3", "1.2.3"}, // never reduce to empty
		{"", "", "unknown"},
		{"Chrome Beta x64", "1.0", "chrome beta"},
		{"VLC media player", "3.0.21", "vlc media player"},
		{"App v2.5 beta", "2.5", "app beta"},
	}
	for _, c := range cases {
		if got := NormalizeName(c.name, c.version); got != c.want {
			t.Errorf("NormalizeName(%q, %q) = %q, want %q", c.name, c.version, got, c.want)
		}
	}
	// Different versions and installers of one product collapse to one title.
	a := NormalizeName("7-Zip 23.01 (x64 edition)", "23.01")
	b := NormalizeName("7-Zip 24.08 (x64)", "24.08")
	if a != b {
		t.Errorf("same product, different titles: %q vs %q", a, b)
	}
	// Different products must stay distinct.
	if NormalizeName("Visual Studio Code", "1") == NormalizeName("Visual Studio 2022", "17.1") {
		t.Error("distinct products collapsed")
	}
}

func TestDisplayName(t *testing.T) {
	cases := []struct{ name, version, want string }{
		{"7-Zip 23.01 (x64 edition)", "23.01", "7-Zip"},
		{"Microsoft Visual Studio Code (User)", "1.93.1", "Microsoft Visual Studio Code"},
		{"Google Chrome", "130.0.1", "Google Chrome"},
		{"Notepad++ (64-bit x64)", "8.7", "Notepad++"},
		{"GIT Version 2.46.0", "2.46.0", "GIT Version"},
	}
	for _, c := range cases {
		if got := DisplayName(c.name, c.version); got != c.want {
			t.Errorf("DisplayName(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestNormalizePublisher(t *testing.T) {
	cases := map[string]string{
		"Google LLC":              "google",
		"Google Inc.":             "google",
		"Microsoft Corporation":   "microsoft",
		"The Document Foundation": "document foundation",
		"Igor Pavlov":             "igor pavlov",
		"Notepad++ Team":          "notepad++ team",
		"Mozilla Foundation":      "mozilla foundation",
		"JetBrains s.r.o.":        "jetbrains s r o",
		"":                        "",
		"  ACME  Software GmbH  ": "acme software",
	}
	for in, want := range cases {
		if got := NormalizePublisher(in); got != want {
			t.Errorf("NormalizePublisher(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"Google Chrome", "x64", "(64-bit)", "1.2.3", "", "\xff\xfe", "A (x64) (x86) (User)"} {
		f.Add(s, "1.2")
	}
	f.Fuzz(func(t *testing.T, name, version string) {
		n := NormalizeName(name, version)
		if n == "" || len(n) > MaxNormalizedLen {
			t.Fatalf("bad output %q for %q", n, name)
		}
		if again := NormalizeName(name, version); again != n { // determinism
			t.Fatal("non-deterministic")
		}
		if p := NormalizePublisher(name); len(p) > MaxNormalizedLen {
			t.Fatalf("publisher too long: %d", len(p))
		}
	})
}
