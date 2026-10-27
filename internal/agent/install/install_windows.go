//go:build windows

package install

import (
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
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/auzring1/librepatch/internal/agent/config"
	"github.com/auzring1/librepatch/internal/agent/core"
	"github.com/auzring1/librepatch/internal/agent/keystore"
	"github.com/auzring1/librepatch/internal/agent/store"
)

// Protected DACLs (no inheritance from parents):
//   - data dir:    SYSTEM and Administrators full control only
//   - program dir: SYSTEM/Administrators full, Users read+execute
//   - service:     SYSTEM/Administrators manage; interactive/service users may only query
const (
	sddlDataDir    = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	sddlProgramDir = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	sddlService    = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
)

// Options for Install.
type Options struct {
	Server      string
	Token       string
	AllowedJobs string
	// NoScripts switches off running scripts from the console on this computer (they are on by default, D150).
	NoScripts bool
	Wait      time.Duration
	Out       io.Writer
}

func requireAdmin() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("this command must be run from an elevated (Administrator) prompt")
	}
	return nil
}

// Install copies the agent to Program Files, writes the protected config,
// registers and starts the service, then reports the enrollment outcome.
func Install(o Options) error {
	if err := requireAdmin(); err != nil {
		return err
	}
	cfg, err := config.FromBundle(o.Token, o.Server)
	if err != nil {
		return fmt.Errorf("invalid --token: %w", err)
	}
	if cfg.AllowedJobs, err = config.ParseAllowedJobs(o.AllowedJobs); err != nil {
		return err
	}
	cfg.NoScripts = o.NoScripts
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer func() { _ = m.Disconnect() }()
	if s, err := m.OpenService(ServiceName); err == nil {
		_ = s.Close()
		return errors.New("the agent is already installed; run `librepatch-agent uninstall` first")
	}

	dataDir := DataDir()
	for _, d := range []struct{ path, sddl string }{
		{dataDir, sddlDataDir},
		{filepath.Join(dataDir, "logs"), ""},
		{programDir(), sddlProgramDir},
		{filepath.Dir(BinaryPath()), ""},
	} {
		if d.sddl != "" {
			if err := secureDir(d.path, d.sddl); err != nil {
				return fmt.Errorf("secure %s: %w", d.path, err)
			}
			continue
		}
		if err := os.MkdirAll(d.path, 0o700); err != nil {
			return err
		}
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Clean(self), filepath.Clean(BinaryPath())) {
		if err := copyFile(self, BinaryPath()); err != nil {
			return fmt.Errorf("copy agent binary: %w", err)
		}
	}
	if err := config.Save(filepath.Join(dataDir, "config.json"), cfg); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	_ = os.Remove(filepath.Join(dataDir, "status.json"))

	// mgr quotes the binary path, so there is no unquoted-path vulnerability.
	s, err := m.CreateService(ServiceName, BinaryPath(), mgr.Config{
		DisplayName:      brand.AgentName,
		Description:      brand.Name + " endpoint management agent (outbound-only; no listening ports).",
		StartType:        mgr.StartAutomatic,
		ServiceStartName: "LocalSystem",
		ErrorControl:     mgr.ErrorNormal,
	}, "service")
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer func() { _ = s.Close() }()
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Minute},
	}, 24*60*60); err != nil {
		fmt.Fprintln(o.Out, "warning: could not set service recovery actions:", err)
	} else if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		// Needed so that a deliberate non-zero exit (restart into an updated version) is restarted.
		fmt.Fprintln(o.Out, "warning: could not enable restart after a non-zero exit:", err)
	}
	if err := setServiceDACL(s.Handle); err != nil {
		fmt.Fprintln(o.Out, "warning: could not restrict service permissions:", err)
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	fmt.Fprintf(o.Out, "Installed %s and started the %s service.\nWaiting for enrollment with %s ...\n", BinaryPath(), ServiceName, cfg.Server)
	return waitForEnrollment(dataDir, o.Wait, o.Out)
}

func waitForEnrollment(dataDir string, wait time.Duration, out io.Writer) error {
	deadline := time.Now().Add(wait)
	last := ""
	for time.Now().Before(deadline) {
		st, err := core.ReadStatus(dataDir)
		if err == nil && st.State != last {
			last = st.State
			switch st.State {
			case "connected":
				fmt.Fprintf(out, "Enrolled and connected. Device ID: %s\n", st.DeviceID)
				return nil
			case "pending_approval":
				fmt.Fprintf(out, "Enrolled; waiting for an administrator to approve device %s in the console.\n", st.DeviceID)
				return nil
			case "error", "rejected":
				return fmt.Errorf("enrollment problem: %s (the service keeps retrying; see %s)", st.Message, filepath.Join(dataDir, "logs", "agent.log"))
			}
		}
		time.Sleep(time.Second)
	}
	fmt.Fprintf(out, "Still working on enrollment (last state: %q). Check %s.\n", last, filepath.Join(dataDir, "logs", "agent.log"))
	return nil
}

// Uninstall stops and removes the service, deletes the device key and files.
func Uninstall(out io.Writer) error {
	if err := requireAdmin(); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	if s, err := m.OpenService(ServiceName); err == nil {
		if st, err := s.Control(svc.Stop); err == nil {
			for i := 0; i < 30 && st.State != svc.Stopped; i++ {
				time.Sleep(time.Second)
				st, _ = s.Query()
			}
		}
		if err := s.Delete(); err != nil {
			_ = s.Close()
			return fmt.Errorf("delete service: %w", err)
		}
		_ = s.Close()
		fmt.Fprintln(out, "Service removed.")
	} else {
		fmt.Fprintln(out, "Service not installed; cleaning up files.")
	}
	dataDir := DataDir()
	// Delete every device key generation recorded in state.
	if st, err := store.Open(filepath.Join(dataDir, "state.db")); err == nil {
		if id, _ := st.Identity(); id != nil {
			ks := keystore.Default(dataDir)
			for g := 1; g <= id.KeyGen; g++ {
				_ = ks.Delete(fmt.Sprintf("%s%d", core.KeyPrefix, g))
			}
			fmt.Fprintf(out, "Device key(s) deleted. Remember to revoke device %s in the console if it is still listed.\n", id.DeviceID)
		}
		_ = st.Close()
	}
	if err := os.RemoveAll(dataDir); err != nil {
		fmt.Fprintln(out, "warning: could not remove", dataDir+":", err)
	}
	if err := removeProgramDir(out); err != nil {
		return err
	}
	fmt.Fprintln(out, "Uninstall complete.")
	return nil
}

func removeProgramDir(out io.Writer) error {
	dir := programDir()
	self, _ := os.Executable()
	if strings.HasPrefix(strings.ToLower(filepath.Clean(self)), strings.ToLower(dir)) {
		// Cannot delete a running executable: schedule removal at next reboot.
		_ = filepath.Walk(dir, func(p string, _ os.FileInfo, _ error) error {
			if pp, err := windows.UTF16PtrFromString(p); err == nil {
				_ = windows.MoveFileEx(pp, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
			}
			return nil
		})
		fmt.Fprintln(out, "Program files will be removed at the next reboot.")
		return nil
	}
	if err := os.RemoveAll(filepath.Dir(dir)); err != nil {
		return fmt.Errorf("remove %s: %w", dir, err)
	}
	return nil
}

// secureDir creates path with the protected DACL in one step, so there is no window in which it is
// writable by users. A directory that already exists must not be a reparse point and must be owned by
// SYSTEM or Administrators: a standard user may create a folder under %ProgramData% and would remain
// its owner (and so could rewrite its DACL later) even after we replace the DACL (SECURITY.md T-LPE-6).
// It is not deleted automatically; the administrator has to remove or fix it.
func secureDir(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	err = windows.CreateDirectory(p, sa)
	if err == nil {
		return nil
	}
	if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("%s exists and is not a plain directory (symbolic link, junction or file); remove it and run install again", path)
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
		return fmt.Errorf("%s already exists and is owned by %s, not SYSTEM or Administrators; inspect it, remove it and run install again", path, owner)
	}
	return applySDDL(path, sddl)
}

func applySDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func setServiceDACL(h windows.Handle) error {
	sd, err := windows.SecurityDescriptorFromString(sddlService)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(h, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- our own executable
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755) // #nosec G302 G304 -- agent binary copied into the ACL-protected Program Files directory
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
