//go:build !windows

package inventory

import "errors"

// UninstallRoots exists only on Windows.
func UninstallRoots(bool, string) ([]RegNode, error) {
	return nil, errors.New("not supported on this platform")
}

// ProfileFor exists only on Windows.
func ProfileFor(string) (Profile, error) {
	return Profile{}, errors.New("not supported on this platform")
}
