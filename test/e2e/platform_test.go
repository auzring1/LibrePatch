package e2e

import (
	"runtime"
	"testing"
)

func runtimeOS() string   { return runtime.GOOS }
func runtimeArch() string { return runtime.GOARCH }

// skipOnWindows is for tests whose "installer" is a shell script. Only the Linux dev platform runs those;
// the real Windows platform cannot start a .sh file (it has its own coverage in internal/agent/jobs and
// the deploy job in .github/workflows/windows.yml).
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("uses shell-script installers that only the Linux dev platform can run")
	}
}
