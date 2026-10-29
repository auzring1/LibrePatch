package installer

import (
	"strings"
	"testing"
)

func TestAppxNames(t *testing.T) {
	if n, ok := AppxNameFromFamily("Microsoft.WindowsTerminal_contosopub001"); !ok || n != "Microsoft.WindowsTerminal" {
		t.Fatalf("family: %q %v", n, ok)
	}
	if n, ok := AppxNameFromFullName("Microsoft.WindowsTerminal_1.25.2733.0_x64__contosopub001"); !ok || n != "Microsoft.WindowsTerminal" {
		t.Fatalf("full name: %q %v", n, ok)
	}
	for _, bad := range []string{"", "Microsoft.WindowsTerminal", "A B_contosopub001", "x;rm_contosopub001", "a_b", "$(calc)_contosopub001"} {
		if _, ok := AppxNameFromFamily(bad); ok {
			t.Errorf("family %q accepted", bad)
		}
	}
	for _, bad := range []string{"", "Name_1.0_x64_contosopub001", "Na me_1.0_x64__contosopub001", "Name_1.0_x64__contosopub001'; calc"} {
		if _, ok := AppxNameFromFullName(bad); ok {
			t.Errorf("full name %q accepted", bad)
		}
	}
	key := AppxDetectionKey("Microsoft.WindowsTerminal")
	if key != "Microsoft.WindowsTerminal_" {
		t.Fatal(key)
	}
	if n, ok := AppxNameFromDetectionKey(key); !ok || n != "Microsoft.WindowsTerminal" {
		t.Fatalf("key: %q %v", n, ok)
	}
	if _, ok := AppxNameFromDetectionKey("Microsoft.WindowsTerminal"); ok {
		t.Fatal("a key without the underscore is not an appx key")
	}
}

func TestIsMSIXFileName(t *testing.T) {
	for _, n := range []string{"a.msix", "A.MSIXBUNDLE", "Terminal_1.25.msixbundle", "x.appx", "x.appxbundle"} {
		if !IsMSIXFileName(n) {
			t.Errorf("%s should be a package", n)
		}
	}
	for _, n := range []string{"a.exe", "msix", "a.msi", "a.msix.exe", ""} {
		if IsMSIXFileName(n) {
			t.Errorf("%s should not be a package", n)
		}
	}
}

// The scripts take their input from parameters only: no value from a job may ever be pasted into the script text.
func TestMSIXScriptsAreFixedText(t *testing.T) {
	for name, s := range map[string]string{"install": MSIXInstallScript, "remove": MSIXRemoveScript} {
		if strings.Contains(s, "%") {
			t.Errorf("%s script has a placeholder", name)
		}
		if !strings.HasPrefix(s, "param(") || !strings.Contains(s, "$ErrorActionPreference = 'Stop'") {
			t.Errorf("%s script must start with its parameters and stop on errors", name)
		}
		if strings.Count(s, "{") != strings.Count(s, "}") || strings.Count(s, "(") != strings.Count(s, ")") {
			t.Errorf("%s script has unbalanced brackets", name)
		}
	}
	for _, want := range []string{"Add-AppxProvisionedPackage", "-SkipLicense", "Get-AppxPackage -AllUsers", "ConvertTo-Ver", "exit 0", "exit 1"} {
		if !strings.Contains(MSIXInstallScript, want) {
			t.Errorf("install script lacks %q", want)
		}
	}
	for _, want := range []string{"Remove-AppxPackage", "-AllUsers", "Remove-AppxProvisionedPackage"} {
		if !strings.Contains(MSIXRemoveScript, want) {
			t.Errorf("remove script lacks %q", want)
		}
	}
}
