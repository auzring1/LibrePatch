package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/auzring1/librepatch/internal/agent/install"
)

var msiProductRe = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

// cmdSelfUninstall is started by the service when an administrator revoked the device with "uninstall the agent". It waits a few
// seconds (so the service can report the job as done), then removes the agent: the MSI when it came from the MSI, otherwise what
// `uninstall` does. Internal: nothing here is for people to run.
func cmdSelfUninstall(args []string) error {
	fs := flag.NewFlagSet("self-uninstall", flag.ContinueOnError)
	wait := fs.Int("wait", 15, "seconds to wait first")
	msi := fs.String("msi", "", "product code of the installed MSI")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *wait < 0 || *wait > 300 {
		return fmt.Errorf("--wait must be 0 to 300 seconds")
	}
	time.Sleep(time.Duration(*wait) * time.Second)
	if *msi != "" {
		if !msiProductRe.MatchString(*msi) {
			return fmt.Errorf("--msi is not a product code")
		}
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		// #nosec G204 -- the product code was just checked against the GUID pattern; the program is msiexec in System32
		return exec.Command(filepath.Join(root, "System32", "msiexec.exe"), "/x", *msi, "/qn", "/norestart").Run()
	}
	return install.Uninstall(io.Discard)
}
