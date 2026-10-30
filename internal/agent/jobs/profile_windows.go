//go:build windows

package jobs

import (
	"errors"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/auzring1/librepatch/internal/agent/inventory"
)

var (
	userenv            = windows.NewLazySystemDLL("userenv.dll")
	procDeleteProfileW = userenv.NewProc("DeleteProfileW")
)

// ProfileInfo reads the profile list entry for sid and whether the user's hive is loaded.
func (p *winPlatform) ProfileInfo(sid string) (ProfileInfo, error) {
	prof, err := inventory.ProfileFor(sid)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return ProfileInfo{}, nil
		}
		return ProfileInfo{}, err
	}
	return ProfileInfo{Exists: true, Path: prof.Path, Loaded: prof.Loaded}, nil
}

// AccountName resolves the SID to DOMAIN and name.
func (p *winPlatform) AccountName(sid string) (string, string) {
	s, err := windows.StringToSid(sid)
	if err != nil {
		return "", ""
	}
	name, domain, _, err := s.LookupAccount("")
	if err != nil {
		return "", ""
	}
	return domain, name
}

// AutoLogon returns the account the computer signs in to by itself (Winlogon's AutoAdminLogon), if any.
func (p *winPlatform) AutoLogon() (string, string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", ""
	}
	defer k.Close()
	if v, _, err := k.GetStringValue("AutoAdminLogon"); err != nil || strings.TrimSpace(v) != "1" {
		return "", ""
	}
	user, _, _ := k.GetStringValue("DefaultUserName")
	domain, _, _ := k.GetStringValue("DefaultDomainName")
	return strings.TrimSpace(domain), strings.TrimSpace(user)
}

// DeleteProfile calls userenv!DeleteProfileW, the function behind Settings and "User Profiles". Passing only the SID lets
// Windows use the folder it has recorded; no path is taken from anywhere else.
func (p *winPlatform) DeleteProfile(sid string) error {
	sp, err := windows.UTF16PtrFromString(sid)
	if err != nil {
		return err
	}
	r, _, callErr := procDeleteProfileW.Call(uintptr(unsafe.Pointer(sp)), 0, 0)
	if r != 0 {
		return nil
	}
	if errno, ok := callErr.(syscall.Errno); ok {
		switch errno {
		case windows.ERROR_SHARING_VIOLATION, windows.ERROR_BUSY:
			return ErrProfileInUse
		}
		return errno
	}
	return callErr
}
