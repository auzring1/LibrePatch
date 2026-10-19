//go:build windows

package jobs

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/auzring1/librepatch/internal/agent/inventory"
	"github.com/auzring1/librepatch/internal/agent/selfupdate"
	"github.com/auzring1/librepatch/internal/agent/wu"
	"github.com/auzring1/librepatch/internal/shared/installer"
)

type winPlatform struct {
	dataDir string
}

// NewPlatform returns the Windows platform. Machine-scope staging lives under
// the protected data directory; user-scope staging uses a separate root that
// the target user can traverse (see StagingDir).
func NewPlatform(dataDir string) Platform { return &winPlatform{dataDir: dataDir} }

const (
	sddlMachine  = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	sddlRootTrav = "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x20;;;BU)" // Users may traverse, not list
)

func programData() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return pd
	}
	return `C:\ProgramData`
}

// ensureDir creates path with the given SDDL, or verifies an existing
// directory is owned by SYSTEM or Administrators (a user could have pre-created
// it under ProgramData to plant files).
func ensureDir(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(p, sa)
	if err == nil {
		return nil
	}
	if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	osd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := osd.Owner()
	if err != nil {
		return err
	}
	if !owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return fmt.Errorf("staging directory %s is owned by %s, not SYSTEM or Administrators", path, owner)
	}
	return nil
}

func (p *winPlatform) StagingDir(scope installer.Scope, sid, jobID string) (string, error) {
	if !validID(jobID) {
		return "", errors.New("bad job id")
	}
	if scope == installer.User {
		if !strings.HasPrefix(sid, "S-1-") || strings.ContainsAny(sid, `\/:*?"<>|`) {
			return "", errors.New("bad SID")
		}
		root := filepath.Join(programData(), brand.StageFolderName)
		if err := ensureDir(root, sddlRootTrav); err != nil {
			return "", err
		}
		userDir := filepath.Join(root, sid)
		// SYSTEM and Administrators write; the target user may read and execute (D13).
		if err := ensureDir(userDir, sddlMachine+"(A;OICI;0x1200a9;;;"+sid+")"); err != nil {
			return "", err
		}
		dir := filepath.Join(userDir, jobID)
		return dir, ensureDir(dir, sddlMachine+"(A;OICI;0x1200a9;;;"+sid+")")
	}
	root := filepath.Join(p.dataDir, "stage")
	if err := ensureDir(root, sddlMachine); err != nil {
		return "", err
	}
	dir := filepath.Join(root, jobID)
	return dir, ensureDir(dir, sddlMachine)
}

func validID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// RemoveAll retries briefly: antivirus and the installer's own children can
// hold files for a moment after the process tree ends.
func (p *winPlatform) RemoveAll(path string) error {
	var err error
	for i := 0; i < 5; i++ {
		if err = os.RemoveAll(path); err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return err
}

func (p *winPlatform) FreeSpaceMB(path string) (uint64, error) {
	pp, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(pp, &avail, &total, &free); err != nil {
		return 0, err
	}
	return avail >> 20, nil
}

func (p *winPlatform) OSBuild() uint32 { return windows.RtlGetVersion().BuildNumber }

func (p *winPlatform) Env(scope installer.Scope, sid, name string) string {
	if scope != installer.User {
		return os.Getenv(name)
	}
	prof, err := inventory.ProfileFor(sid)
	if err != nil {
		return ""
	}
	switch strings.ToUpper(name) {
	case "USERPROFILE":
		return prof.Path
	case "LOCALAPPDATA":
		return filepath.Join(prof.Path, "AppData", "Local")
	case "APPDATA":
		return filepath.Join(prof.Path, "AppData", "Roaming")
	}
	return os.Getenv(name) // machine-wide variables (Program Files, SystemRoot, ...)
}

func (p *winPlatform) FileVersion(path string) (string, bool, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	var zero windows.Handle
	size, err := windows.GetFileVersionInfoSize(path, &zero)
	if err != nil || size == 0 {
		return "", true, nil // present, no version resource
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return "", true, nil
	}
	var block unsafe.Pointer
	var blen uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\`, unsafe.Pointer(&block), &blen); err != nil || blen < uint32(unsafe.Sizeof(windows.VS_FIXEDFILEINFO{})) {
		return "", true, nil
	}
	fi := (*windows.VS_FIXEDFILEINFO)(block)
	return fmt.Sprintf("%d.%d.%d.%d", fi.FileVersionMS>>16, fi.FileVersionMS&0xffff, fi.FileVersionLS>>16, fi.FileVersionLS&0xffff), true, nil
}

func (p *winPlatform) UninstallRoots(scope installer.Scope, sid string) ([]inventory.RegNode, error) {
	return inventory.UninstallRoots(scope == installer.Machine, sid)
}

func (p *winPlatform) AppxPackages(string) ([]string, error) { return nil, ErrUnsupported }

type lockedFile struct{ f *os.File }

func (l lockedFile) Read(b []byte) (int, error) { return l.f.Read(b) }
func (l lockedFile) Close() error               { return l.f.Close() }

// OpenLocked opens read-only with FILE_SHARE_READ only: while the handle is
// open nobody can write, rename or delete the file.
func (p *winPlatform) OpenLocked(path string) (LockedFile, error) {
	pp, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(pp, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return lockedFile{f: os.NewFile(uintptr(h), path)}, nil
}

func (p *winPlatform) MsiExec() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "msiexec.exe")
}

// TrustedExecutable allows only administrator-controlled locations, so a
// registry value pointing at a user-writable path can never be run as SYSTEM.
func (p *winPlatform) TrustedExecutable(path string) error {
	if !isAbsWin(path) {
		return errors.New("not an absolute path")
	}
	clean := strings.ToLower(filepath.Clean(path))
	var roots []string
	for _, v := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles", "SystemRoot"} {
		if r := os.Getenv(v); r != "" {
			roots = append(roots, strings.ToLower(filepath.Clean(r)))
		}
	}
	roots = append(roots, strings.ToLower(filepath.Join(programData(), "Package Cache")))
	trusted := false
	for _, r := range roots {
		if strings.HasPrefix(clean, r+`\`) {
			trusted = true
			break
		}
	}
	if !trusted {
		return errors.New("located outside Program Files, Windows and the Package Cache")
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	return nil
}

// ---- Authenticode ----

var (
	wintrust       = windows.NewLazySystemDLL("wintrust.dll")
	procProvData   = wintrust.NewProc("WTHelperProvDataFromStateData")
	procProvSigner = wintrust.NewProc("WTHelperGetProvSignerFromChain")
	procProvCert   = wintrust.NewProc("WTHelperGetProvCertFromChain")
	errNoSignature = windows.Errno(0x800B0100) // TRUST_E_NOSIGNATURE
	errProviderUnk = windows.Errno(0x800B0001) // TRUST_E_PROVIDER_UNKNOWN
	errSubjectForm = windows.Errno(0x800B0003) // TRUST_E_SUBJECT_FORM_UNKNOWN
)

type cryptProviderCert struct {
	cbStruct uint32
	pCert    *windows.CertContext
}

// VerifySignature checks the embedded Authenticode signature with WinVerifyTrust
// (revocation checking is off so an offline machine can still install) and
// extracts the signer's subject and certificate thumbprint.
func (p *winPlatform) VerifySignature(path string) (Signature, error) {
	pp, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return Signature{}, err
	}
	fileInfo := &windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: pp}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fileInfo),
	}
	verr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	defer func() {
		data.StateAction = windows.WTD_STATEACTION_CLOSE
		_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	}()
	sig := Signature{}
	if verr != nil {
		var errno windows.Errno
		if errors.As(verr, &errno) && (errno == errNoSignature || errno == errProviderUnk || errno == errSubjectForm) {
			return sig, nil // unsigned
		}
		sig.Signed = true
		sig.Detail = fmt.Sprintf("WinVerifyTrust: %v", verr)
		fillSigner(&sig, data.StateData)
		return sig, nil
	}
	sig.Signed, sig.Valid = true, true
	fillSigner(&sig, data.StateData)
	return sig, nil
}

func fillSigner(sig *Signature, state windows.Handle) {
	if state == 0 || procProvData.Find() != nil {
		return
	}
	pd, _, _ := procProvData.Call(uintptr(state))
	if pd == 0 {
		return
	}
	sgnr, _, _ := procProvSigner.Call(pd, 0, 0, 0)
	if sgnr == 0 {
		return
	}
	pc, _, _ := procProvCert.Call(sgnr, 0)
	if pc == 0 {
		return
	}
	// pc is a pointer into WinTrust-owned memory that stays valid until the state is closed.
	pcp := *(*unsafe.Pointer)(unsafe.Pointer(&pc)) // #nosec G103 -- Win32 structure returned by WinTrust
	cert := (*cryptProviderCert)(pcp).pCert
	if cert == nil {
		return
	}
	n := windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, nil, 0)
	if n > 1 {
		buf := make([]uint16, n)
		windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &buf[0], n)
		sig.Subject = windows.UTF16ToString(buf)
	}
	enc := unsafe.Slice(cert.EncodedCert, cert.Length)
	h := sha256.Sum256(enc)
	sig.Thumbprint = h[:]
}

// ---- running processes ----

const jobObjectMsgActiveProcessZero = 4

// Run starts spec as the service identity inside a Job Object so the whole
// process tree is tracked: many installers re-spawn themselves and exit early.
func (p *winPlatform) Run(ctx context.Context, spec RunSpec) (RunResult, error) {
	return runInJob(ctx, spec, 0)
}

func (p *winPlatform) HasSession(sid string) bool {
	_, ok := sessionOf(sid)
	return ok
}

func (p *winPlatform) SessionEvents() <-chan struct{} { return sessionSig }

// sessionOf finds an active or disconnected interactive session of the user.
// WTSQueryUserToken needs the SYSTEM identity, so it fails (false) elsewhere.
func sessionOf(sid string) (uint32, bool) {
	var info *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &info, &count); err != nil {
		return 0, false
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	sessions := unsafe.Slice(info, count)
	var best uint32
	found := false
	for _, s := range sessions {
		if s.State != windows.WTSActive && s.State != windows.WTSDisconnected {
			continue
		}
		var tok windows.Token
		if err := windows.WTSQueryUserToken(s.SessionID, &tok); err != nil {
			continue
		}
		u, err := tok.GetTokenUser()
		_ = tok.Close()
		if err != nil || u.User.Sid.String() != sid {
			continue
		}
		// prefer an active session over a disconnected one
		if !found || s.State == windows.WTSActive {
			best, found = s.SessionID, true
		}
	}
	return best, found
}

// tailFile returns the last logTailMax bytes of a file (” if unreadable).
func tailFile(path string) string {
	f, err := os.Open(path) // #nosec G304 -- log inside the staging directory
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	off := int64(0)
	if fi.Size() > logTailMax {
		off = fi.Size() - logTailMax
	}
	b, _ := io.ReadAll(io.NewSectionReader(f, off, logTailMax))
	// Installer logs are often UTF-16LE; make them readable.
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		u := make([]uint16, 0, len(b)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
		}
		return windows.UTF16ToString(u)
	}
	return string(b)
}

// ---- Windows Update and restarts ----

// WindowsUpdate returns the WUA client.
func (p *winPlatform) SelfUpdater() selfupdate.Platform {
	return selfupdate.NewWindows(p.dataDir, func() {
		if RequestServiceRestart != nil {
			RequestServiceRestart()
		}
	})
}

func (p *winPlatform) WindowsUpdate() wu.Client { return wu.NewClient(p.dataDir) }

var procAbortShutdown = windows.NewLazySystemDLL("advapi32.dll").NewProc("AbortSystemShutdownW")

// enableShutdownPrivilege turns on SeShutdownPrivilege in the service's token (held but disabled by default).
func enableShutdownPrivilege() error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()
	var luid windows.LUID
	name, _ := windows.UTF16PtrFromString("SeShutdownPrivilege")
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	return windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
}

// Reboot starts a restart with a countdown that Windows shows to every signed-in user (with the
// message) and that an administrator can abort with "shutdown /a". Applications are not forced
// closed: users get the usual "save your work" prompts, and the restart still happens at the end.
func (p *winPlatform) Reboot(delay time.Duration, message string) error {
	if err := enableShutdownPrivilege(); err != nil {
		return fmt.Errorf("cannot enable the shutdown privilege: %w", err)
	}
	msg, err := windows.UTF16PtrFromString(message)
	if err != nil {
		return err
	}
	secs := uint32(delay / time.Second) // #nosec G115 -- bounded by the caller to 24 h
	// SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MINOR_UPGRADE | SHTDN_REASON_FLAG_PLANNED
	const reason = 0x00020000 | 0x00000003 | 0x80000000
	err = windows.InitiateSystemShutdownEx(nil, msg, secs, false, true, reason)
	if errors.Is(err, windows.ERROR_SHUTDOWN_IS_SCHEDULED) || errors.Is(err, windows.ERROR_SHUTDOWN_IN_PROGRESS) {
		return ErrRebootScheduled
	}
	return err
}

// AbortReboot cancels a pending countdown. "No shutdown in progress" is not an error.
func (p *winPlatform) AbortReboot() error {
	if err := enableShutdownPrivilege(); err != nil {
		return err
	}
	r, _, e := procAbortShutdown.Call(0)
	if r == 0 {
		if errno, ok := e.(windows.Errno); ok && errno == windows.Errno(1116) { // ERROR_NO_SHUTDOWN_IN_PROGRESS
			return nil
		}
		return e
	}
	return nil
}

// RebootRequired reports the usual pending-restart markers.
func (p *winPlatform) RebootRequired() bool { return wu.PendingReboot() }
