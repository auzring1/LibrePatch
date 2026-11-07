//go:build !windows

package install

// serviceRegistered is always false off Windows (there is no service to register).
func serviceRegistered() bool { return false }
