//go:build windows

package peercache

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/windows"

	"github.com/auzring1/librepatch/internal/shared/brand"
)

var ruleName = brand.Name + " peer cache"

func netsh(args ...string) error {
	root, _ := windows.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(root, "System32", "netsh.exe"), args...) // #nosec G204 -- fixed binary, fixed arguments, a validated port
	return cmd.Run()
}

// OpenFirewall lets this program receive connections on the port from the domain and private networks (never public ones).
// It replaces an earlier rule of the same name.
func OpenFirewall(port uint16) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	CloseFirewall()
	if err := netsh("advfirewall", "firewall", "add", "rule", "name="+ruleName, "dir=in", "action=allow", "protocol=TCP",
		"localport="+strconv.Itoa(int(port)), "program="+exe, "profile=domain,private", "enable=yes"); err != nil {
		return fmt.Errorf("firewall rule: %w", err)
	}
	return nil
}

// CloseFirewall removes the rule.
func CloseFirewall() {
	_ = netsh("advfirewall", "firewall", "delete", "rule", "name="+ruleName)
}
