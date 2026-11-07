//go:build windows

package install

import "golang.org/x/sys/windows/svc/mgr"

// serviceRegistered reports whether the LibrePatchAgent service exists (running or not).
func serviceRegistered() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return false
	}
	_ = s.Close()
	return true
}
