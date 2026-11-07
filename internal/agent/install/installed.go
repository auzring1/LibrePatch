package install

import (
	"os"
	"path/filepath"
)

// IsInstalled reports whether this machine already has an installed and configured
// agent: the Windows service is registered and the protected config.json exists.
// `librepatch-agent install --if-not-installed` uses it so that the MSI can be run again
// (major upgrade, repair, GPO re-application) on an enrolled machine without
// re-enrolling and without needing a new token.
func IsInstalled() bool { return installedIn(DataDir(), serviceRegistered) }

// installedIn is IsInstalled with its inputs explicit, for tests.
func installedIn(dataDir string, serviceExists func() bool) bool {
	if !serviceExists() {
		return false
	}
	st, err := os.Stat(filepath.Join(dataDir, "config.json"))
	return err == nil && st.Mode().IsRegular()
}
