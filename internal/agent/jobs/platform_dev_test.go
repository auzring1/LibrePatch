//go:build !windows

package jobs

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/auzring1/librepatch/internal/shared/installer"
)

// The development platform runs a test script with the system's /bin/sh. It must never change that program's mode:
// as a normal user the change is refused (and the script would not run), and as root it would damage the system.
func TestDevRunLeavesTheInterpreterAlone(t *testing.T) {
	sh, err := os.Stat("/bin/sh")
	if err != nil {
		t.Skip("no /bin/sh")
	}
	p := NewPlatform(t.TempDir())
	dir, err := p.StagingDir(installer.Machine, "", "job1")
	if err != nil {
		t.Fatal(err)
	}
	script := dir + "/script.sh"
	if err := os.WriteFile(script, []byte("echo hello-from-script\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rr, err := p.Run(context.Background(), RunSpec{Exe: "/bin/sh", Args: []string{script}, Dir: dir, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("the script did not start: %v", err)
	}
	if rr.ExitCode != 0 || !strings.Contains(rr.LogTail, "hello-from-script") {
		t.Fatalf("exit %d, output %q", rr.ExitCode, rr.LogTail)
	}
	after, err := os.Stat("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode() != sh.Mode() {
		t.Fatalf("/bin/sh changed from %v to %v", sh.Mode(), after.Mode())
	}
}
