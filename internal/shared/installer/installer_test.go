package installer

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestValidateArg(t *testing.T) {
	ok := []string{"/S", "/VERYSILENT", "/quiet", "--silent", "-q", "/D=C:\\Tools\\App", "/log=install.log", "INSTALLDIR=C:\\Program Files\\App",
		"ADDLOCAL=ALL", "REBOOT=ReallySuppress", "/norestart", "--install-dir=C:/x"}
	for _, a := range ok {
		if err := ValidateArg(a); err != nil {
			t.Errorf("%q rejected: %v", a, err)
		}
	}
	bad := []string{"", "calc.exe", "/S & calc", "/S|calc", "/S;calc", "a b", `/x"`, "/S\n/D", "$(whoami)", "`id`", "/i", "/x", "/uninstall", "-i", "-x", "--x", "-uninstall", "--package", "-a", "-j:foo",
		"TRANSFORMS=evil.mst", "PATCH=x.msp", "lowercase=1", "/D=%TEMP%", "/é", strings.Repeat("A", MaxArgLen+1), "/S>out", "/S^x"}
	for _, a := range bad {
		if err := ValidateArg(a); !errors.Is(err, ErrArg) {
			t.Errorf("%q accepted (err=%v)", a, err)
		}
	}
	if err := ValidateArgs(make([]string, MaxArgs+1)); err == nil {
		t.Error("too many args accepted")
	}
}

func TestCommandBuilders(t *testing.T) {
	cases := []struct {
		name string
		s    Spec
		exe  string
		args []string
	}{
		{"msi machine", Spec{Type: MSI, Scope: Machine, Path: `C:\s\a.msi`, LogPath: `C:\l.log`},
			"msiexec.exe", []string{"/i", `C:\s\a.msi`, "/qn", "/norestart", "ALLUSERS=1", "/l*v", `C:\l.log`}},
		{"msi user", Spec{Type: MSI, Scope: User, Path: `C:\s\a.msi`, Extra: []string{"ADDLOCAL=ALL"}},
			"msiexec.exe", []string{"/i", `C:\s\a.msi`, "/qn", "/norestart", "ALLUSERS=2", "MSIINSTALLPERUSER=1", "ADDLOCAL=ALL"}},
		{"inno user", Spec{Type: Inno, Scope: User, Path: `C:\s\a.exe`},
			`C:\s\a.exe`, []string{"/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-", "/CURRENTUSER"}},
		{"inno machine", Spec{Type: Inno, Scope: Machine, Path: `C:\s\a.exe`, LogPath: `C:\l`},
			`C:\s\a.exe`, []string{"/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-", "/ALLUSERS", `/LOG=C:\l`}},
		{"nsis", Spec{Type: NSIS, Path: `C:\s\a.exe`}, `C:\s\a.exe`, []string{"/S"}},
		{"burn", Spec{Type: Burn, Path: `C:\s\a.exe`}, `C:\s\a.exe`, []string{"/quiet", "/norestart"}},
		{"exe", Spec{Type: EXE, Path: `C:\s\a.exe`, Extra: []string{"/silent"}}, `C:\s\a.exe`, []string{"/silent"}},
	}
	for _, c := range cases {
		exe, args, err := Command(c.s)
		if err != nil || exe != c.exe || !reflect.DeepEqual(args, c.args) {
			t.Errorf("%s: %q %q %v", c.name, exe, args, err)
		}
	}
	if _, _, err := Command(Spec{Type: EXE, Path: "x"}); err == nil {
		t.Error("EXE without silent switches must be refused")
	}
	if _, _, err := Command(Spec{Type: Zip, Path: "x"}); err == nil {
		t.Error("zip is not process based")
	}
	if _, _, err := Command(Spec{Type: MSI, Path: "x", Extra: []string{"/x"}}); err == nil {
		t.Error("forbidden switch accepted")
	}
}

func TestResolve(t *testing.T) {
	if Resolve(MSI, 0, nil, nil) != Success || Resolve(MSI, 3010, nil, nil) != RebootRequired ||
		Resolve(MSI, 1641, nil, nil) != RebootRequired || Resolve(MSI, 1618, nil, nil) != Retryable ||
		Resolve(MSI, 1603, nil, nil) != Failed || Resolve(EXE, 1618, nil, nil) != Failed {
		t.Fatal("type defaults")
	}
	if Resolve(EXE, 5, []int{5}, nil) != Success {
		t.Fatal("success code list")
	}
	if Resolve(EXE, 0, nil, map[int]Outcome{0: Failed}) != Failed {
		t.Fatal("code map must win")
	}
}

func TestCommandLineRoundTrip(t *testing.T) {
	cases := [][]string{{`C:\Program Files\App\unins000.exe`, "/SILENT"}, {"a", `b c`, `d"e`, `f\`, `g\\"h`, ""}, {`C:\x y\z.exe`, `/D=C:\a b\`}}
	for _, c := range cases {
		line := ComposeCommandLine(c[0], c[1:])
		got, err := SplitCommandLine(line)
		if err != nil || !reflect.DeepEqual(got, c) {
			t.Errorf("%q -> %q (%v)", c, got, err)
		}
	}
	got, _ := SplitCommandLine(`"C:\Program Files\App\unins000.exe" /SILENT /LOG="C:\a b\x.log"`)
	if len(got) != 3 || got[0] != `C:\Program Files\App\unins000.exe` || got[2] != `/LOG=C:\a b\x.log` {
		t.Errorf("registry-style line: %q", got)
	}
	if _, err := SplitCommandLine(`"unterminated`); err == nil {
		t.Error("unbalanced quote accepted")
	}
}

func FuzzCommandLine(f *testing.F) {
	f.Add(`"C:\a b\c.exe" /x "d e" f\\"g`)
	f.Fuzz(func(t *testing.T, s string) {
		args, err := SplitCommandLine(s)
		if err != nil || len(args) == 0 {
			return
		}
		again, err := SplitCommandLine(ComposeCommandLine(args[0], args[1:]))
		if err != nil || !reflect.DeepEqual(again, args) {
			t.Fatalf("round trip %q -> %q -> %q (%v)", s, args, again, err)
		}
	})
}

func makeZip(t *testing.T, files map[string]string, mutate func(*zip.FileHeader)) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		if mutate != nil {
			mutate(h)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	_ = zw.Close()
	p := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExtractZip(t *testing.T) {
	dst := t.TempDir()
	if err := ExtractZip(makeZip(t, map[string]string{"app/setup.exe": "MZ", "readme.txt": "hi"}, nil), dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "app", "setup.exe")); string(b) != "MZ" {
		t.Fatal("content not extracted")
	}
	for _, name := range []string{"../evil.txt", "a/../../evil.txt", "/abs.txt", `..\evil.txt`, `C:\evil.txt`, "a:stream", "CON", "COM4", "lpt9.txt", "trail.", "sp ace /x", "dir/NUL.txt", "x//y"} {
		if err := ExtractZip(makeZip(t, map[string]string{name: "x"}, nil), t.TempDir()); !errors.Is(err, ErrZip) {
			t.Errorf("%q accepted: %v", name, err)
		}
	}
	link := makeZip(t, map[string]string{"l": "target"}, func(h *zip.FileHeader) { h.SetMode(os.ModeSymlink | 0o777) })
	if err := ExtractZip(link, t.TempDir()); !errors.Is(err, ErrZip) {
		t.Errorf("symlink accepted: %v", err)
	}
	dup := filepath.Join(t.TempDir(), "d.zip")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range []string{"A.txt", "a.TXT"} {
		w, _ := zw.Create(n)
		_, _ = w.Write([]byte("x"))
	}
	_ = zw.Close()
	_ = os.WriteFile(dup, buf.Bytes(), 0o600)
	if err := ExtractZip(dup, t.TempDir()); !errors.Is(err, ErrZip) {
		t.Errorf("case-colliding names accepted: %v", err)
	}
}

func TestExpandEnv(t *testing.T) {
	env := map[string]string{"PROGRAMFILES": `C:\Program Files`, "LOCALAPPDATA": `C:\Users\a\AppData\Local`, "USERNAME": "a"}
	get := func(k string) string { return env[k] }
	if p, err := ExpandEnv(`%ProgramFiles%\App\a.exe`, false, get); err != nil || p != `C:\Program Files\App\a.exe` {
		t.Fatalf("%q %v", p, err)
	}
	if _, err := ExpandEnv(`%LOCALAPPDATA%\x`, false, get); err == nil {
		t.Error("user variable allowed for machine scope")
	}
	if _, err := ExpandEnv(`%LOCALAPPDATA%\x`, true, get); err != nil {
		t.Error("user variable refused for user scope")
	}
	for _, p := range []string{`%USERNAME%\x`, `%TEMP%\x`, `%ProgramFiles\x`} {
		if _, err := ExpandEnv(p, true, get); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
}

// Anything ValidateArg accepts must be a single token with no shell or
// line-control characters, whatever the input.
func FuzzValidateArg(f *testing.F) {
	for _, s := range []string{"/S", "/D=C:\\x", "INSTALLDIR=C:\\Program Files\\a", "a&b", "x\r\ny", "`calc`", "$(id)"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if ValidateArg(s) != nil {
			return
		}
		if strings.ContainsAny(s, "&|<>^%`$;\r\n\x00\"") {
			t.Fatalf("accepted dangerous argument %q", s)
		}
	})
}

// A hostile archive must never be extracted outside dst or crash the extractor.
func FuzzExtractZip(f *testing.F) {
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		dir := t.TempDir()
		src := filepath.Join(dir, "in.zip")
		if err := os.WriteFile(src, b, 0o600); err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dir, "out")
		if err := os.Mkdir(dst, 0o700); err != nil {
			t.Fatal(err)
		}
		_ = ExtractZip(src, dst)
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.Name() != "in.zip" && e.Name() != "out" {
				t.Fatalf("extraction wrote outside the destination: %s", e.Name())
			}
		}
	})
}
