//go:build !windows

package peercache

// OpenFirewall is Windows-only; elsewhere there is nothing to open.
func OpenFirewall(port uint16) error { return nil }

// CloseFirewall is Windows-only.
func CloseFirewall() {}
