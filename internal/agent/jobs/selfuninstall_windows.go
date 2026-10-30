//go:build windows

package jobs

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procMsiEnumRelatedProducts = windows.NewLazySystemDLL("msi.dll").NewProc("MsiEnumRelatedProductsW")

// installedMSIProduct returns the product code of the agent's MSI when it is installed ("" when the agent was installed by its own
// `install` command). Windows Installer is asked by upgrade code; nothing comes from outside.
func installedMSIProduct() string {
	up, err := windows.UTF16PtrFromString(AgentUpgradeCode)
	if err != nil {
		return ""
	}
	buf := make([]uint16, 39)
	r, _, _ := procMsiEnumRelatedProducts.Call(uintptr(unsafe.Pointer(up)), 0, 0, uintptr(unsafe.Pointer(&buf[0])))
	if r != 0 { // ERROR_SUCCESS is 0; anything else means no related product
		return ""
	}
	return windows.UTF16ToString(buf)
}

// StartSelfUninstall starts `librepatch-agent self-uninstall` as a detached process of its own (it must outlive the service,
// which the removal stops). When the agent came from the MSI the MSI is uninstalled, so the entry in Apps goes with it.
func (p *winPlatform) StartSelfUninstall(wait time.Duration) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	args := []string{"self-uninstall", "--wait", strconv.Itoa(int(wait / time.Second))}
	how := "agent uninstall"
	if code := installedMSIProduct(); code != "" {
		args = append(args, "--msi", code)
		how = "MSI package"
	}
	cmd := exec.Command(exe, args...) // #nosec G204 -- our own executable, fixed arguments
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP, HideWindow: true}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	_ = cmd.Process.Release()
	return how, nil
}
