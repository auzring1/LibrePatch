//go:build !windows

package jobs

import "errors"

// HelperMain runs the user-context helper; it exists only on Windows.
func HelperMain([]string) error {
	return errors.New("the user-context helper is only available on Windows")
}
