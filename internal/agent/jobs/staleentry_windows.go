//go:build windows

package jobs

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/auzring1/librepatch/internal/agent/inventory"
	"github.com/auzring1/librepatch/internal/shared/installer"
)

const (
	uninstallPathNative = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	uninstallPathWOW    = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
	maxKeyDepth         = 8
)

// PathGone is true only when path is on a local fixed drive and Windows says it does not exist.
func (p *winPlatform) PathGone(path string) bool {
	if len(path) < 3 || path[1] != ':' || (path[2] != '\\' && path[2] != '/') || !isAbsWin(path) {
		return false // a network path, a device path or a relative path: not certain
	}
	root, err := windows.UTF16PtrFromString(path[:3])
	if err != nil || windows.GetDriveType(root) != windows.DRIVE_FIXED {
		return false // removable, network or missing drive: the file may be on it
	}
	_, err = os.Stat(path)
	return errors.Is(err, os.ErrNotExist)
}

// DeleteUninstallEntry removes one Uninstall subkey. The key name is checked first: it must be a single name, so a crafted
// value cannot reach anything outside the Uninstall key.
func (p *winPlatform) DeleteUninstallEntry(scope installer.Scope, sid, key string) error {
	if key == "" || len(key) > 512 || strings.ContainsAny(key, `\/`) || strings.ContainsRune(key, 0) {
		return errors.New("not a single Uninstall key name")
	}
	if scope == installer.Machine {
		for _, rel := range []string{uninstallPathNative, uninstallPathWOW} {
			if err := deleteSubKey(registry.LOCAL_MACHINE, rel, key); err != nil {
				return err
			}
		}
		return nil
	}
	if !inventory.IsUserSID(sid) {
		return errors.New("not a user SID")
	}
	if h, err := registry.OpenKey(registry.USERS, sid, registry.QUERY_VALUE); err != nil {
		return ErrNoSession // the user's hive is not loaded: nobody is signed in, and an offline copy would not persist a change
	} else {
		_ = h.Close()
	}
	for _, rel := range []string{`Software\Microsoft\Windows\CurrentVersion\Uninstall`, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`} {
		if err := deleteSubKey(registry.USERS, sid+`\`+rel, key); err != nil {
			return err
		}
	}
	return nil
}

// deleteSubKey deletes root\parent\name with everything below it, when it exists.
func deleteSubKey(root registry.Key, parent, name string) error {
	p, err := registry.OpenKey(root, parent, registry.READ|registry.WRITE|registry.WOW64_64KEY)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil
		}
		return fmt.Errorf("open %s: %w", parent, err)
	}
	defer p.Close()
	return deleteTree(p, name, 0)
}

func deleteTree(parent registry.Key, name string, depth int) error {
	if depth > maxKeyDepth {
		return errors.New("the key is nested too deeply")
	}
	k, err := registry.OpenKey(parent, name, registry.READ|registry.WRITE|registry.WOW64_64KEY)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil
		}
		return fmt.Errorf("open %s: %w", name, err)
	}
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		_ = k.Close()
		return err
	}
	for _, s := range subs {
		if err := deleteTree(k, s, depth+1); err != nil {
			_ = k.Close()
			return err
		}
	}
	_ = k.Close()
	if err := registry.DeleteKey(parent, name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("delete %s: %w", name, err)
	}
	return nil
}
