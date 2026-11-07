//go:build windows

package rebootstate

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

func keyExists(path string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	_ = k.Close()
	return true
}

func regValue(path, name string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer func() { _ = k.Close() }()
	s, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

// Check reads the restart markers of this PC.
func Check() State {
	var s State
	if keyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`) {
		s.Reasons = append(s.Reasons, ReasonServicing)
	}
	if keyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`) {
		s.Reasons = append(s.Reasons, ReasonWindowsUpdate)
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringsValue("PendingFileRenameOperations"); err == nil {
			ParsePendingFileRenames(v).Classify(&s)
		}
		_ = k.Close()
	}
	active := regValue(`SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName`, "ComputerName")
	pending := regValue(`SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`, "ComputerName")
	if active != "" && pending != "" && !strings.EqualFold(active, pending) {
		s.Reasons = append(s.Reasons, ReasonComputerName)
	}
	return s
}
