//go:build windows

package inventory

import (
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// NewCollector returns the Windows collector.
func NewCollector() Collector { return &Scanner{P: &winPlatform{}} }

// RunBackground runs fn on a locked OS thread in background mode, which lowers
// its CPU, I/O and memory priority so scans never slow the user's machine.
func RunBackground(fn func()) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	const beginBackground, endBackground = 0x00010000, 0x00020000 // THREAD_MODE_BACKGROUND_BEGIN/END
	h := windows.CurrentThread()
	began := setThreadPriority(h, beginBackground) == nil
	defer func() {
		if began {
			_ = setThreadPriority(h, endBackground)
		}
	}()
	fn()
}

var (
	kernel32DLL         = windows.NewLazySystemDLL("kernel32.dll")
	procSetThreadPrio   = kernel32DLL.NewProc("SetThreadPriority")
	advapi32DLL         = windows.NewLazySystemDLL("advapi32.dll")
	procRegLoadAppKeyW  = advapi32DLL.NewProc("RegLoadAppKeyW")
	msiDLL              = windows.NewLazySystemDLL("msi.dll")
	procMsiEnumProducts = msiDLL.NewProc("MsiEnumProductsExW")
	procMsiGetProduct   = msiDLL.NewProc("MsiGetProductInfoExW")
	netapi32DLL         = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserLocalGrp = netapi32DLL.NewProc("NetUserGetLocalGroups")
	procNetApiBufFree   = netapi32DLL.NewProc("NetApiBufferFree")
)

func setThreadPriority(h windows.Handle, prio uint32) error {
	r, _, e := procSetThreadPrio.Call(uintptr(h), uintptr(prio))
	if r == 0 {
		return e
	}
	return nil
}

// winNode adapts a registry.Key to RegNode.
type winNode struct {
	k      registry.Key
	expand bool // expand REG_EXPAND_SZ using the service's environment (HKLM only)
}

func mapRegErr(err error) error {
	if errors.Is(err, registry.ErrNotExist) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return ErrRegNotExist
	}
	return err
}

func (n winNode) SubKeyNames() ([]string, error) { return n.k.ReadSubKeyNames(-1) }

func (n winNode) Open(path string) (RegNode, error) {
	k, err := registry.OpenKey(n.k, path, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return nil, mapRegErr(err)
	}
	return winNode{k: k, expand: n.expand}, nil
}

func (n winNode) String(name string) (string, bool) {
	s, typ, err := n.k.GetStringValue(name)
	if err != nil {
		return "", false
	}
	if typ == registry.EXPAND_SZ && n.expand {
		if e, err := registry.ExpandString(s); err == nil {
			s = e
		}
	}
	return s, true
}

func (n winNode) DWord(name string) (uint32, bool) {
	v, typ, err := n.k.GetIntegerValue(name)
	if err != nil || (typ != registry.DWORD && typ != registry.QWORD) {
		return 0, false
	}
	return uint32(v), true // #nosec G115 -- DWORD values
}

func (n winNode) Close() { _ = n.k.Close() }

type winPlatform struct{}

func (winPlatform) HKLM() (RegNode, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, "", registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return nil, err
	}
	return winNode{k: k, expand: true}, nil
}

func (winPlatform) ProgramFiles() string { return os.Getenv("ProgramFiles") }

func (winPlatform) ReadDir(path string) ([]DirEntry, error) {
	es, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrRegNotExist
	}
	if err != nil {
		return nil, err
	}
	out := make([]DirEntry, 0, len(es))
	for _, e := range es {
		out = append(out, DirEntry{Name: e.Name(), IsDir: e.IsDir()})
	}
	return out, nil
}

// Profiles lists user profiles with account names and logged-on state.
func (p winPlatform) Profiles() ([]Profile, error) {
	hklm, err := p.HKLM()
	if err != nil {
		return nil, err
	}
	defer hklm.Close()
	loaded := func(sid string) bool {
		k, err := registry.OpenKey(registry.USERS, sid, registry.QUERY_VALUE)
		if err != nil {
			return false
		}
		_ = k.Close()
		return true
	}
	host, _ := os.Hostname()
	adminGroup := builtinAdministrators()
	lookup := func(sid string) (string, string, bool) {
		s, err := windows.StringToSid(sid)
		if err != nil {
			return "", "", false
		}
		user, domain, _, err := s.LookupAccount("")
		if err != nil {
			return "", "", false
		}
		isAdmin := false
		// Group membership of domain accounts may need a domain controller and
		// can block; evaluate local accounts and logged-on users only.
		if adminGroup != "" && (strings.EqualFold(domain, host) || loaded(sid)) {
			isAdmin = inLocalGroup(domain, user, adminGroup)
		}
		return user, domain, isAdmin
	}
	return ParseProfileList(hklm, loaded, lookup)
}

func builtinAdministrators() string {
	sid, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return ""
	}
	name, _, _, err := sid.LookupAccount("")
	if err != nil {
		return ""
	}
	return name
}

// inLocalGroup reports whether DOMAIN\user is (directly or indirectly) in the named local group.
func inLocalGroup(domain, user, group string) bool {
	account := user
	if domain != "" {
		account = domain + `\` + user
	}
	a, err := windows.UTF16PtrFromString(account)
	if err != nil {
		return false
	}
	var buf *byte
	var entries, total uint32
	const lgIncludeIndirect, maxPreferred = 0x1, 0xFFFFFFFF
	r, _, _ := procNetUserLocalGrp.Call(0, uintptr(unsafe.Pointer(a)), 0, lgIncludeIndirect,
		uintptr(unsafe.Pointer(&buf)), maxPreferred, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&total)))
	if r != 0 || buf == nil {
		return false
	}
	defer procNetApiBufFree.Call(uintptr(unsafe.Pointer(buf)))
	// LOCALGROUP_USERS_INFO_0 is an array of { LPWSTR name }.
	names := unsafe.Slice((**uint16)(unsafe.Pointer(buf)), entries)
	for _, n := range names {
		if strings.EqualFold(windows.UTF16PtrToString(n), group) {
			return true
		}
	}
	return false
}

// UserHive returns HKU\SID for logged-on users. For offline profiles it loads
// a private copy of NTUSER.DAT: the Windows CI spike (docs/research U8) showed
// that RegLoadAppKey, even with a read-only mask, can rewrite the hive file
// (log replay / header updates), and a user's real hive must never be touched.
func (winPlatform) UserHive(p Profile) (RegNode, error) {
	if p.Loaded {
		k, err := registry.OpenKey(registry.USERS, p.SID, registry.READ)
		if err != nil {
			return nil, err
		}
		return winNode{k: k}, nil
	}
	file := strings.TrimRight(p.Path, `\/`) + `\NTUSER.DAT`
	return loadOfflineCopy(file, hiveTempRoot())
}

// hiveTempRoot is a directory under the agent's protected data directory
// (SYSTEM and Administrators only, inherited), so copies of user hives are
// never readable by other users.
func hiveTempRoot() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, brand.FolderName, "tmp")
}

// tempHive is a loaded private copy; Close unloads it and deletes the copy.
type tempHive struct {
	winNode
	dir string
}

func (t tempHive) Close() {
	t.winNode.Close()
	_ = os.RemoveAll(t.dir)
}

// loadOfflineCopy copies the hive file (and its transaction logs, so a dirty
// hive is consistent) into a fresh directory under root and loads the copy.
func loadOfflineCopy(file, root string) (RegNode, error) {
	if _, err := os.Stat(file); err != nil {
		// A user whose profile folder was deleted (the account is gone, the registry entry stayed) is not a problem to
		// report on every scan; a hive that is merely missing from an existing folder still is.
		if _, derr := os.Stat(filepath.Dir(file)); errors.Is(derr, os.ErrNotExist) {
			return nil, ErrProfileGone
		}
		return nil, fmt.Errorf("profile hive: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(root, "hive-")
	if err != nil {
		return nil, err
	}
	dst := filepath.Join(dir, "NTUSER.DAT")
	if err := copyFile(file, dst); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("copy profile hive: %w", err)
	}
	for _, ext := range []string{".LOG1", ".LOG2"} {
		_ = copyFile(file+ext, dst+ext) // logs are optional
	}
	n, err := loadAppHive(dst)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return tempHive{winNode: n.(winNode), dir: dir}, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- profile path from the registry ProfileList
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- fresh private temp dir
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// loadAppHive loads a hive file as a private, read-only application hive.
func loadAppHive(file string) (RegNode, error) {
	f, err := windows.UTF16PtrFromString(file)
	if err != nil {
		return nil, err
	}
	var h syscall.Handle
	const keyRead, regProcessAppKey = 0x20019, 0x1
	r, _, _ := procRegLoadAppKeyW.Call(uintptr(unsafe.Pointer(f)), uintptr(unsafe.Pointer(&h)), keyRead, regProcessAppKey, 0)
	if r != 0 {
		return nil, fmt.Errorf("RegLoadAppKey %s: %w", file, syscall.Errno(r)) // #nosec G115 -- LSTATUS
	}
	return winNode{k: registry.Key(h)}, nil
}

// MSIProducts enumerates Windows Installer products in all contexts.
func (winPlatform) MSIProducts() ([]MSIProduct, error) {
	var out []MSIProduct
	const (
		contextAll     = 7
		errNoMoreItems = 259
		errMoreData    = 234
		contextMachine = 4
		allUsers       = "S-1-1-0"
		maxProducts    = 20000
	)
	all, _ := windows.UTF16PtrFromString(allUsers)
	for i := uint32(0); i < maxProducts; i++ {
		var code [39]uint16
		var ctx uint32
		sidBuf := make([]uint16, 256)
		sidLen := uint32(len(sidBuf)) // #nosec G115 -- fixed 256
		r, _, _ := procMsiEnumProducts.Call(0, uintptr(unsafe.Pointer(all)), contextAll, uintptr(i),
			uintptr(unsafe.Pointer(&code[0])), uintptr(unsafe.Pointer(&ctx)), uintptr(unsafe.Pointer(&sidBuf[0])), uintptr(unsafe.Pointer(&sidLen)))
		if r == errNoMoreItems {
			break
		}
		if r == errMoreData {
			sidBuf = make([]uint16, sidLen+1)
			sidLen = uint32(len(sidBuf)) // #nosec G115 -- sized by the API's own report
			r, _, _ = procMsiEnumProducts.Call(0, uintptr(unsafe.Pointer(all)), contextAll, uintptr(i),
				uintptr(unsafe.Pointer(&code[0])), uintptr(unsafe.Pointer(&ctx)), uintptr(unsafe.Pointer(&sidBuf[0])), uintptr(unsafe.Pointer(&sidLen)))
		}
		if r != 0 {
			return out, fmt.Errorf("MsiEnumProductsEx: error %d", r)
		}
		pc := windows.UTF16ToString(code[:])
		machine := ctx == contextMachine
		sid := ""
		if !machine {
			sid = windows.UTF16ToString(sidBuf)
		}
		prod := MSIProduct{Code: pc, Machine: machine, SID: sid}
		prod.Name = msiProp(pc, sid, ctx, "InstalledProductName")
		prod.Version = msiProp(pc, sid, ctx, "VersionString")
		prod.Publisher = msiProp(pc, sid, ctx, "Publisher")
		prod.InstallLocation = msiProp(pc, sid, ctx, "InstallLocation")
		prod.InstallDate = normalizeDateString(msiProp(pc, sid, ctx, "InstallDate"))
		out = append(out, prod)
	}
	return out, nil
}

func msiProp(code, sid string, ctx uint32, prop string) string {
	c, err := windows.UTF16PtrFromString(code)
	if err != nil {
		return ""
	}
	pr, _ := windows.UTF16PtrFromString(prop)
	var sidPtr *uint16
	if sid != "" {
		sidPtr, _ = windows.UTF16PtrFromString(sid)
	}
	const errMoreData = 234
	buf := make([]uint16, 512)
	n := uint32(len(buf)) // #nosec G115 -- fixed 512
	r, _, _ := procMsiGetProduct.Call(uintptr(unsafe.Pointer(c)), uintptr(unsafe.Pointer(sidPtr)), uintptr(ctx),
		uintptr(unsafe.Pointer(pr)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if r == errMoreData && n < 65536 {
		buf = make([]uint16, n+1)
		n = uint32(len(buf)) // #nosec G115 -- small buffer
		r, _, _ = procMsiGetProduct.Call(uintptr(unsafe.Pointer(c)), uintptr(unsafe.Pointer(sidPtr)), uintptr(ctx),
			uintptr(unsafe.Pointer(pr)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	}
	if r != 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}
