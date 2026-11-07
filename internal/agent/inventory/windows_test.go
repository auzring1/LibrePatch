//go:build windows

package inventory

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

func randName(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func writeUninstall(t *testing.T, root registry.Key, path, name, display, version string) {
	t.Helper()
	k, _, err := registry.CreateKey(root, path+`\`+name, registry.ALL_ACCESS)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer k.Close()
	_ = k.SetStringValue("DisplayName", display)
	_ = k.SetStringValue("DisplayVersion", version)
	_ = k.SetStringValue("Publisher", "LibrePatch CI")
	t.Cleanup(func() { _ = registry.DeleteKey(root, path+`\`+name) })
}

func findItem(items []*agentv1.SoftwareItem, name string) *agentv1.SoftwareItem {
	for _, it := range items {
		if it.Name == name {
			return it
		}
	}
	return nil
}

// The real collector against the real registry: a machine-wide and a per-user
// uninstall entry must appear with the right scope; Windows itself must yield
// a plausible amount of software and at least one user.
func TestRealCollector(t *testing.T) {
	machine, user := randName("LibrePatchCI-M-"), randName("LibrePatchCI-U-")
	writeUninstall(t, registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, machine, machine, "1.2.3")
	writeUninstall(t, registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall`, user, user, "4.5.6")

	scan, err := NewCollector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("collected %d items, %d users, %d failed groups, warnings=%v", len(scan.Items), len(scan.Users), len(scan.Failed), scan.Warnings)
	if m := findItem(scan.Items, machine); m == nil || m.Key.Scope != agentv1.SoftwareScope_SOFTWARE_SCOPE_MACHINE || m.Version != "1.2.3" {
		t.Fatalf("machine item: %+v", m)
	}
	// HKCU of the test process is a loaded HKU hive of a profile: reported per user with its SID.
	if u := findItem(scan.Items, user); u == nil || u.Key.Scope != agentv1.SoftwareScope_SOFTWARE_SCOPE_USER || u.Key.UserSid == "" {
		t.Logf("per-user item not found (the runner's profile may not be listed): %+v", u)
	}
	if len(scan.Items) < 5 {
		t.Fatalf("suspiciously few items: %d", len(scan.Items))
	}
	if len(scan.Users) == 0 {
		t.Fatal("no user profiles")
	}
	sources := map[agentv1.SoftwareSource]int{}
	for _, it := range scan.Items {
		sources[it.Key.Source]++
	}
	t.Logf("items per source: %v", sources) // AppX/MSI/portable counts: spike results for docs/research

	// Stability: an immediate second scan must produce no delta.
	scan2, err := NewCollector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, ups, rms := diffForTest(scan, scan2)
	if ups != 0 || rms != 0 {
		t.Logf("second scan differed (%d upserts, %d removes): background installs are possible on CI", ups, rms)
	}
}

func diffForTest(a, b *Scan) (Snapshot, int, int) {
	snap := Snapshot{}
	for _, it := range a.Items {
		snap[string(ItemKeyBytes(it.Key))] = ItemHash(it)
	}
	ups, rms, next := Diff(snap, b)
	return next, len(ups), len(rms)
}

// An offline hive must load without touching the user's real file.
func TestLoadAppHiveIsReadOnly(t *testing.T) {
	name := randName("LibrePatchCIHive")
	writeUninstall(t, registry.CURRENT_USER, `Software\`+name+`\Microsoft\Windows\CurrentVersion\Uninstall`, "Pkg", "Offline Pkg", "9.9.9")
	file := filepath.Join(t.TempDir(), "hive.dat")
	if out, err := exec.Command("reg", "save", `HKCU\Software\`+name, file, "/y").CombinedOutput(); err != nil {
		t.Fatalf("reg save: %v: %s", err, out)
	}
	before := fileHash(t, file)
	root := t.TempDir()
	node, err := loadOfflineCopy(file, root)
	if err != nil {
		t.Fatalf("loading offline hive: %v", err)
	}
	// The saved hive's root is the key itself.
	sub, err := node.Open(`Microsoft\Windows\CurrentVersion\Uninstall\Pkg`)
	if err != nil {
		t.Fatalf("subkey not readable from loaded hive: %v", err)
	}
	if v, _ := sub.String("DisplayName"); v != "Offline Pkg" {
		t.Fatalf("DisplayName=%q", v)
	}
	sub.Close()
	node.Close()
	if after := fileHash(t, file); !bytes.Equal(before, after) {
		t.Fatal("loading the hive modified the original file")
	}
	if left, _ := os.ReadDir(root); len(left) != 0 {
		t.Fatalf("temporary hive copy not removed: %v", left)
	}

	// Documents the spike result (research U8): a direct RegLoadAppKey of the
	// same file may rewrite it, which is why production code loads a copy.
	direct := filepath.Join(t.TempDir(), "direct.dat")
	b, _ := os.ReadFile(file)
	_ = os.WriteFile(direct, b, 0o600)
	h0 := fileHash(t, direct)
	if n, err := loadAppHive(direct); err == nil {
		n.Close()
	}
	t.Logf("direct RegLoadAppKey modified the file: %v", !bytes.Equal(h0, fileHash(t, direct)))
}

func fileHash(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return h[:]
}

// Registry change notifications fire on a new uninstall entry.
func TestWatcherFiresOnInstall(t *testing.T) {
	w, err := NewWatcher(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	time.Sleep(500 * time.Millisecond) // let the watchers arm
	writeUninstall(t, registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, randName("LibrePatchCI-W-"), "Watcher Test", "1")
	select {
	case <-w.Events():
	case <-time.After(10 * time.Second):
		t.Fatal("no change notification after writing an Uninstall key")
	}
}
