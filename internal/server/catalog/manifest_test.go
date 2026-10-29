package catalog

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/auzring1/librepatch/internal/shared/installer"
)

func fixture(t *testing.T, names ...string) [][]byte {
	t.Helper()
	var out [][]byte
	for _, n := range names {
		b, err := os.ReadFile("testdata/" + n)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

func find(p *Parsed, arch, typ string) *Installer {
	for i := range p.Installers {
		if p.Installers[i].Arch == arch && p.Installers[i].Type == typ {
			return &p.Installers[i]
		}
	}
	return nil
}

func TestParseRealSevenZip(t *testing.T) {
	p, err := ParseFiles(fixture(t, "7zip.version.yaml", "7zip.installer.yaml", "7zip.locale.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Identifier != "7zip.7zip" || p.Version != "24.09" || p.Name != "7-Zip" || p.Publisher != "Igor Pavlov" || len(p.ManifestSHA256) != 32 {
		t.Fatalf("%+v", p)
	}
	exe := find(p, "x64", "exe")
	if exe == nil || exe.Unsupported != "" || len(exe.Silent) != 1 || exe.Silent[0] != "/S" || exe.Scope != "machine" {
		t.Fatalf("x64 exe: %+v", exe)
	}
	// 7-Zip's EXE registers an Uninstall key named "7-Zip": registry detection at >= the package version.
	if len(exe.Detection) != 1 || exe.Detection[0].Kind != "registry" || exe.Detection[0].Key != "7-Zip" || exe.Detection[0].Version != "24.09" || exe.Detection[0].Cmp != "ge" {
		t.Fatalf("exe detection: %+v", exe.Detection)
	}
	msi := find(p, "x64", "msi") // InstallerType "wix" maps to msi
	if msi == nil || msi.ProductCode != "{23170F69-40C1-2702-2409-000001000000}" || msi.UpgradeCode == "" {
		t.Fatalf("msi: %+v", msi)
	}
	if len(msi.Detection) != 1 || msi.Detection[0].Kind != "msi" {
		t.Fatalf("msi detection: %+v", msi.Detection)
	}
	if len(msi.Silent) != 0 {
		t.Fatal("MSI installers get the agent's own silent switches, not the manifest's")
	}
	// 32-bit ARM is not deployable.
	for _, in := range p.Installers {
		if strings.Contains(in.URL, "-arm.exe") && in.Unsupported == "" {
			t.Fatal("arm installer must be unsupported")
		}
	}
	if !strings.HasSuffix(exe.FileName, ".exe") || strings.ContainsAny(exe.FileName, `/\`) {
		t.Fatalf("file name %q", exe.FileName)
	}
}

func TestParseRealVSCodeInheritsRootFields(t *testing.T) {
	p, err := ParseFiles(fixture(t, "vscode.version.yaml", "vscode.installer.yaml", "vscode.locale.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Installers) != 4 {
		t.Fatalf("%d installers", len(p.Installers))
	}
	for _, in := range p.Installers {
		if in.Type != "inno" || len(in.Custom) != 1 || in.Custom[0] != "/mergetasks=!runcode" {
			t.Fatalf("root InstallerType/Switches not inherited: %+v", in)
		}
	}
	user := 0
	for _, in := range p.Installers {
		if in.Scope == "user" {
			user++
		}
	}
	if user != 2 {
		t.Fatalf("user-scope installers: %d", user)
	}
}

const singleton = `
PackageIdentifier: Acme.Tool
PackageVersion: 2.0.1
PackageName: Acme Tool
Publisher: Acme Inc.
License: MIT
ShortDescription: A tool
ManifestType: singleton
ManifestVersion: 1.6.0
InstallerType: nullsoft
Installers:
- Architecture: x64
  InstallerUrl: https://dl.acme.example/tool-2.0.1.exe
  InstallerSha256: ` + "AB" + `CDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789
  AppsAndFeaturesEntries:
  - DisplayVersion: 2.0.1.0
    ProductCode: AcmeTool
`

func TestParseSingleton(t *testing.T) {
	p, err := ParseFiles([][]byte{[]byte(singleton)})
	if err != nil {
		t.Fatal(err)
	}
	in := p.Installers[0]
	if in.Type != "nsis" || in.Scope != "any" || in.Arch != "x64" || len(in.Detection) != 1 || in.Detection[0].Version != "2.0.1.0" {
		t.Fatalf("%+v", in)
	}
	// NSIS needs no manifest switches: the agent supplies /S.
	if in.Unsupported != "" {
		t.Fatalf("unsupported: %s", in.Unsupported)
	}
}

func TestExeWithoutSilentSwitchIsUnsupported(t *testing.T) {
	m := strings.Replace(singleton, "InstallerType: nullsoft", "InstallerType: exe", 1)
	p, err := ParseFiles([][]byte{[]byte(m)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Installers[0].Unsupported, "silent") {
		t.Fatalf("%q", p.Installers[0].Unsupported)
	}
}

func TestMSIXNeedsAPackageFamilyAndIsInstalledMachineWide(t *testing.T) {
	m := strings.Replace(singleton, "InstallerType: nullsoft", "InstallerType: msix", 1)
	p, _ := ParseFiles([][]byte{[]byte(m)})
	if !strings.Contains(p.Installers[0].Unsupported, "PackageFamilyName") {
		t.Fatalf("a package without a family name cannot be found by the agent: %q", p.Installers[0].Unsupported)
	}
	if len(p.Installers[0].Detection) != 0 {
		t.Fatalf("detection without a name: %+v", p.Installers[0].Detection)
	}

	m = strings.Replace(singleton, "InstallerType: nullsoft", "InstallerType: msix\nScope: user\nPackageFamilyName: Contoso.Terminal_8wekyb3d8bbwe", 1)
	p, err := ParseFiles([][]byte{[]byte(m)})
	if err != nil {
		t.Fatal(err)
	}
	in := p.Installers[0]
	if in.Unsupported != "" || in.Scope != "machine" || in.Type != "msix" {
		t.Fatalf("an MSIX package is deployable and installed for the whole computer: %+v", in)
	}
	if !installer.IsMSIXFileName(in.FileName) {
		t.Fatalf("the staged file needs a package extension: %q", in.FileName)
	}
	if len(in.Detection) != 1 || in.Detection[0].Kind != "appx" || in.Detection[0].Key != "Contoso.Terminal_" || in.Detection[0].Cmp != "ge" || in.Detection[0].Version != p.Version {
		t.Fatalf("detection: %+v", in.Detection)
	}
}

func TestHostileSwitchesAreFlagged(t *testing.T) {
	h := strings.Replace(singleton, "InstallerType: nullsoft", "InstallerType: exe\nInstallerSwitches:\n  Silent: /S & calc.exe", 1)
	p, err := ParseFiles([][]byte{[]byte(h)})
	if err != nil {
		t.Fatal(err)
	}
	if p.Installers[0].Unsupported == "" {
		t.Fatal("manifest switches with shell metacharacters must be refused")
	}
}

func TestManifestRejections(t *testing.T) {
	cases := map[string]string{
		"http url":   strings.Replace(singleton, "https://dl.acme", "http://dl.acme", 1),
		"no sha":     strings.Replace(singleton, "InstallerSha256: ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789", "InstallerSha256: ", 1),
		"short sha":  strings.Replace(singleton, "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789", "ABCDEF", 1),
		"bad id":     strings.Replace(singleton, "Acme.Tool", "../evil", 1),
		"no dot id":  strings.Replace(singleton, "Acme.Tool", "Nodot", 1),
		"userinfo":   strings.Replace(singleton, "https://dl.acme", "https://u:p@dl.acme", 1),
		"no version": strings.Replace(singleton, "PackageVersion: 2.0.1", "PackageVersion: ''", 1),
		"yaml":       "a: [unclosed",
	}
	for name, m := range cases {
		if _, err := ParseFiles([][]byte{[]byte(m)}); !errors.Is(err, ErrManifest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseFiles(nil); err == nil {
		t.Error("empty set accepted")
	}
	if _, err := ParseFiles([][]byte{make([]byte, MaxManifestBytes+1)}); err == nil {
		t.Error("oversized manifest accepted")
	}
}

func FuzzParseManifest(f *testing.F) {
	f.Add([]byte(singleton))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParseFiles([][]byte{b})
		if err != nil {
			return
		}
		for _, in := range p.Installers {
			if !strings.HasPrefix(in.URL, "https://") || len(in.SHA256) != 32 || strings.ContainsAny(in.FileName, `/\`) {
				t.Fatalf("unsafe installer accepted: %+v", in)
			}
		}
	})
}

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	return fixture(t, name)[0]
}
