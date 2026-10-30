//go:build windows

package jobs

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
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

// Creates a throw-away local account with a real profile, removes the profile with the platform's DeleteProfile and checks
// that the profile entry and the folder are gone while the account stays. Needs an elevated session (the CI runner is one).
func TestWinDeleteProfileRemovesTheProfileAndKeepsTheAccount(t *testing.T) {
	elevated(t)
	const user = "lpprofiletest"
	if out, err := exec.Command("net", "user", user, "Lp-T3st-Pass-9x!", "/add").CombinedOutput(); err != nil {
		t.Skipf("cannot create a test account: %v %s", err, out)
	}
	defer func() { _ = exec.Command("net", "user", user, "/delete").Run() }()
	sid, _, _, err := windows.LookupSID("", user)
	if err != nil {
		t.Fatal(err)
	}
	sidStr := sid.String()
	createProfile := windows.NewLazySystemDLL("userenv.dll").NewProc("CreateProfile")
	sp, _ := windows.UTF16PtrFromString(sidStr)
	np, _ := windows.UTF16PtrFromString(user)
	buf := make([]uint16, 260)
	if hr, _, _ := createProfile.Call(uintptr(unsafe.Pointer(sp)), uintptr(unsafe.Pointer(np)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))); hr != 0 {
		t.Skipf("cannot create a profile (HRESULT %#x)", hr)
	}
	folder := windows.UTF16ToString(buf)

	p := NewPlatform(t.TempDir())
	info, err := p.ProfileInfo(sidStr)
	if err != nil || !info.Exists || info.Loaded || !strings.EqualFold(info.Path, folder) {
		t.Fatalf("before: %+v %v (folder %q)", info, err, folder)
	}
	if d, n := p.AccountName(sidStr); !strings.EqualFold(n, user) || d == "" {
		t.Errorf("AccountName = %q %q", d, n)
	}
	if err := p.DeleteProfile(sidStr); err != nil {
		t.Fatal(err)
	}
	after, err := p.ProfileInfo(sidStr)
	if err != nil || after.Exists {
		t.Errorf("the profile entry should be gone: %+v %v", after, err)
	}
	if _, err := os.Stat(folder); !os.IsNotExist(err) {
		t.Errorf("the profile folder should be gone: %v", err)
	}
	if _, _, _, err := windows.LookupSID("", user); err != nil {
		t.Errorf("the account itself must stay: %v", err)
	}
	// Removing it again is a quiet no-op on our side: the entry is simply not there.
	if again, err := p.ProfileInfo(sidStr); err != nil || again.Exists {
		t.Errorf("%+v %v", again, err)
	}
}
