//go:build !windows

package install

// DataDir is the default state directory on non-Windows development builds.
func DataDir() string { return "/var/lib/librepatch-agent" }
