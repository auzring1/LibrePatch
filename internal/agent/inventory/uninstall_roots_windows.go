//go:build windows

package inventory

import (
	"errors"
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows/registry"
)

const (
	uninstallRel     = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	uninstallRel32   = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
	userUninstallKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
	userUninstallWOW = `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
)

// hiveRef closes a loaded hive when its last Uninstall root is closed.
type hiveRef struct {
	mu   sync.Mutex
	hive RegNode
	n    int
}

type refNode struct {
	RegNode
	ref *hiveRef
}

func (r refNode) Close() {
	r.RegNode.Close()
	r.ref.mu.Lock()
	r.ref.n--
	last := r.ref.n == 0
	r.ref.mu.Unlock()
	if last {
		r.ref.hive.Close()
	}
}

// UninstallRoots opens the Uninstall keys for machine scope (HKLM, 64-bit and
// WOW6432Node views) or for one user (loaded hive, or a private copy of the
// offline hive). The caller closes every returned node.
func UninstallRoots(machine bool, sid string) ([]RegNode, error) {
	var roots []RegNode
	if machine {
		for _, p := range []string{uninstallRel, uninstallRel32} {
			if k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ); err == nil {
				roots = append(roots, winNode{k: k})
			}
		}
		if len(roots) == 0 {
			return nil, errors.New("HKLM Uninstall key not readable")
		}
		return roots, nil
	}
	prof, err := ProfileFor(sid)
	if err != nil {
		return nil, err
	}
	hive, err := winPlatform{}.UserHive(prof)
	if err != nil {
		return nil, err
	}
	ref := &hiveRef{hive: hive}
	for _, p := range []string{userUninstallKey, userUninstallWOW} {
		if n, err := hive.Open(p); err == nil {
			ref.n++
			roots = append(roots, refNode{RegNode: n, ref: ref})
		}
	}
	if len(roots) == 0 {
		hive.Close()
		return nil, nil
	}
	return roots, nil
}

// ProfileFor finds a user's profile directory and whether its hive is loaded.
func ProfileFor(sid string) (Profile, error) {
	if !IsUserSID(sid) {
		return Profile{}, errors.New("not a user SID")
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+sid, registry.READ)
	if err != nil {
		return Profile{}, err
	}
	defer k.Close()
	path, _, err := k.GetStringValue("ProfileImagePath")
	if err != nil {
		return Profile{}, err
	}
	loaded := false
	if h, err := registry.OpenKey(registry.USERS, sid, registry.READ); err == nil {
		_ = h.Close()
		loaded = true
	}
	return Profile{SID: sid, Path: filepath.Clean(path), Loaded: loaded}, nil
}
