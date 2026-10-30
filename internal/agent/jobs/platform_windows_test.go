//go:build windows

package jobs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/auzring1/librepatch/internal/shared/installer"
)

// These tests exercise the real Windows implementation. They need an elevated
// session (the Windows CI runner is one) and are skipped otherwise.

func elevated(t *testing.T) {
	t.Helper()
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		t.Skip("needs an elevated session")
	}
	_ = f.Close()
}

func TestWinVerifySignature(t *testing.T) {
	p := NewPlatform(t.TempDir())
	// The test binary is not Authenticode-signed.
	self, _ := os.Executable()
	sig, err := p.VerifySignature(self)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Valid {
		t.Errorf("unsigned test binary reported valid: %+v", sig)
	}
	// PowerShell 7 ships on the runner with a Microsoft signature.
	ps := filepath.Join(os.Getenv("ProgramFiles"), "PowerShell", "7", "pwsh.exe")
	if _, err := os.Stat(ps); err != nil {
		t.Skip("pwsh.exe not installed; cannot test a valid signature")
	}
	sig, err = p.VerifySignature(ps)
	if err != nil {
		t.Fatal(err)
	}
	if !sig.Valid || !strings.Contains(sig.Subject, "Microsoft") || len(sig.Thumbprint) != 32 {
		t.Errorf("pwsh.exe signature: %+v", sig)
	}
}

func TestWinRunExitCodeAndTimeout(t *testing.T) {
	p := NewPlatform(t.TempDir())
	cmd := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	res, err := p.Run(context.Background(), RunSpec{Exe: cmd, Args: []string{"/c", "exit", "3"}, Dir: t.TempDir(), Timeout: time.Minute})
	if err != nil || res.ExitCode != 3 || res.TimedOut {
		t.Fatalf("exit code run: %+v err=%v", res, err)
	}
	// A hung child tree must be killed with the job object, not left behind.
	start := time.Now()
	res, err = p.Run(context.Background(), RunSpec{Exe: cmd, Args: []string{"/c", "ping -n 60 127.0.0.1 >nul"}, Dir: t.TempDir(), Timeout: 2 * time.Second})
	if err != nil || !res.TimedOut {
		t.Fatalf("timeout run: %+v err=%v", res, err)
	}
	if time.Since(start) > 20*time.Second {
		t.Errorf("timeout took %s", time.Since(start))
	}
}

func TestWinStagingDirAndLock(t *testing.T) {
	elevated(t)
	p := NewPlatform(t.TempDir())
	dir, err := p.StagingDir(installer.Machine, "", "job-test-1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.RemoveAll(dir) }()
	f := filepath.Join(dir, "x.bin")
	if err := os.WriteFile(f, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	lk, err := p.OpenLocked(f)
	if err != nil {
		t.Fatal(err)
	}
	// While locked, writers and deleters are refused.
	if err := os.WriteFile(f, []byte("tampered"), 0o600); err == nil {
		t.Error("a locked file could be rewritten")
	}
	if err := os.Remove(f); err == nil {
		t.Error("a locked file could be deleted")
	}
	_ = lk.Close()
	if err := p.RemoveAll(dir); err != nil {
		t.Errorf("remove staging dir: %v", err)
	}
}

func TestWinTrustedExecutable(t *testing.T) {
	p := NewPlatform(t.TempDir())
	if err := p.TrustedExecutable(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")); err != nil {
		t.Errorf("System32 binary refused: %v", err)
	}
	// A file in a user-writable directory must not be run as SYSTEM.
	tmp := filepath.Join(t.TempDir(), "evil.exe")
	if err := os.WriteFile(tmp, []byte("MZ"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := p.TrustedExecutable(tmp); err == nil {
		t.Error("user-writable executable accepted")
	}
}

func TestWinUninstallRootsAndEnv(t *testing.T) {
	p := NewPlatform(t.TempDir())
	roots, err := p.UninstallRoots(installer.Machine, "")
	if err != nil || len(roots) == 0 {
		t.Fatalf("roots: %v %v", roots, err)
	}
	for _, r := range roots {
		if _, err := r.SubKeyNames(); err != nil {
			t.Errorf("list Uninstall keys: %v", err)
		}
		r.Close()
	}
	if pf := p.Env(installer.Machine, "", "ProgramFiles"); !strings.EqualFold(pf, os.Getenv("ProgramFiles")) {
		t.Errorf("ProgramFiles = %q", pf)
	}
	if _, exists, err := p.FileVersion(filepath.Join(os.Getenv("SystemRoot"), "System32", "kernel32.dll")); err != nil || !exists {
		t.Errorf("FileVersion(kernel32): %v %v", exists, err)
	}
}

func TestWinPathGoneIsOnlyTrueWhenCertain(t *testing.T) {
	p := NewPlatform(t.TempDir()).(*winPlatform)
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32", "kernel32.dll")
	if p.PathGone(sys) {
		t.Error("an existing file is not gone")
	}
	if !p.PathGone(filepath.Join(os.Getenv("SystemRoot"), "System32", "librepatch-no-such-file.exe")) {
		t.Error("a missing file on the system drive is gone")
	}
	for _, unsure := range []string{`\\no-such-host\share\x.exe`, `relative\x.exe`, `x.exe`, ``, `C:`, `\\?\C:\no-such-file.exe`} {
		if p.PathGone(unsure) {
			t.Errorf("%q is not certain, so it must not count as gone", unsure)
		}
	}
}

// The key is created under HKLM, so this needs an elevated session (the Windows CI runner is one).
func TestWinDeleteUninstallEntryRemovesOnlyThatKey(t *testing.T) {
	elevated(t)
	p := NewPlatform(t.TempDir())
	const name = "LibrePatchTestStaleEntry"
	path := uninstallPathNative + `\` + name
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	_ = k.SetStringValue("DisplayName", "Stale test entry")
	sub, _, err := registry.CreateKey(k, "Nested", registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	_ = sub.Close()
	_ = k.Close()
	// A neighbour that must survive.
	other, _, err := registry.CreateKey(registry.LOCAL_MACHINE, uninstallPathNative+`\`+name+"Neighbour", registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	_ = other.Close()
	defer func() { _ = registry.DeleteKey(registry.LOCAL_MACHINE, uninstallPathNative+`\`+name+"Neighbour") }()

	for _, bad := range []string{"", `..\Uninstall`, `a\b`, "a/b"} {
		if err := p.DeleteUninstallEntry(installer.Machine, "", bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	if err := p.DeleteUninstallEntry(installer.Machine, "", name); err != nil {
		t.Fatal(err)
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ); err == nil {
		_ = k.Close()
		t.Error("the key (with its subkey) should be gone")
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallPathNative+`\`+name+"Neighbour", registry.READ); err != nil {
		t.Errorf("the neighbouring key was removed: %v", err)
	} else {
		_ = k.Close()
	}
	if err := p.DeleteUninstallEntry(installer.Machine, "", name); err != nil {
		t.Errorf("a key that is already gone is not an error: %v", err)
	}
	// A user who is not signed in: the registry cannot be changed.
	if err := p.DeleteUninstallEntry(installer.User, "S-1-5-21-1-2-3-9999", name); err != ErrNoSession {
		t.Errorf("an unloaded hive gives ErrNoSession, got %v", err)
	}
}
