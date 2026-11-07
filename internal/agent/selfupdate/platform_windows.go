//go:build windows

package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName = brand.ServiceName
	taskName    = brand.RollbackTask
	slotA       = "a"
	slotB       = "b"
)

// Windows drives the service control manager and Task Scheduler.
type Windows struct {
	DataDir string
	// RestartHook makes the running service exit (set by main to winsvc.RequestRestart).
	RestartHook func()
}

func programDir() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, brand.FolderName, "Agent")
}

func slotExe(slot string) string {
	return filepath.Join(programDir(), "slot-"+slot, brand.AgentExe)
}

// Default returns the platform for this operating system.
func Default(dataDir string, restart func()) Platform { return NewWindows(dataDir, restart) }

// NewWindows returns the real platform.
func NewWindows(dataDir string, restart func()) *Windows {
	return &Windows{DataDir: dataDir, RestartHook: restart}
}

func openService() (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, err
	}
	s, err := m.OpenService(serviceName)
	if err != nil {
		_ = m.Disconnect()
		return nil, nil, err
	}
	return m, s, nil
}

// exeFromImagePath extracts the binary from a service image path (`"C:\...\librepatch-agent.exe" service`).
func exeFromImagePath(p string) string {
	p = strings.TrimSpace(p)
	if strings.HasPrefix(p, `"`) {
		if i := strings.Index(p[1:], `"`); i >= 0 {
			return p[1 : 1+i]
		}
	}
	if i := strings.Index(strings.ToLower(p), ".exe"); i >= 0 {
		return p[:i+4]
	}
	return p
}

func slotOf(exe string) (string, error) {
	d := strings.ToLower(filepath.Base(filepath.Dir(exe)))
	switch d {
	case "slot-a":
		return slotA, nil
	case "slot-b":
		return slotB, nil
	}
	return "", fmt.Errorf("the service binary %q is not in a slot directory", exe)
}

// Current implements Platform.
func (w *Windows) Current() (string, string, error) {
	m, s, err := openService()
	if err != nil {
		return "", "", err
	}
	defer func() { _ = s.Close(); _ = m.Disconnect() }()
	c, err := s.Config()
	if err != nil {
		return "", "", err
	}
	exe := exeFromImagePath(c.BinaryPathName)
	slot, err := slotOf(exe)
	return slot, exe, err
}

// StageInactive implements Platform.
func (w *Windows) StageInactive(src string) (string, string, error) {
	cur, _, err := w.Current()
	if err != nil {
		return "", "", err
	}
	slot := slotB
	if cur == slotB {
		slot = slotA
	}
	dst := slotExe(slot)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { // #nosec G301 -- inherits the protected Program Files DACL
		return "", "", err
	}
	in, err := os.Open(src) // #nosec G304 -- verified, locked staged file
	if err != nil {
		return "", "", err
	}
	defer func() { _ = in.Close() }()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755) // #nosec G302 G304 -- agent binary in the administrator-controlled Program Files directory
	if err != nil {
		return "", "", err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return "", "", err
	}
	if err := out.Close(); err != nil {
		return "", "", err
	}
	_ = os.Remove(dst) // the inactive slot is not running; a stale copy may be read-only or in use by nothing
	return slot, dst, os.Rename(tmp, dst)
}

// Switch implements Platform.
func (w *Windows) Switch(slot string) error {
	if slot != slotA && slot != slotB {
		return errors.New("bad slot")
	}
	m, s, err := openService()
	if err != nil {
		return err
	}
	defer func() { _ = s.Close(); _ = m.Disconnect() }()
	c, err := s.Config()
	if err != nil {
		return err
	}
	c.BinaryPathName = `"` + slotExe(slot) + `" service`
	if err := s.UpdateConfig(c); err != nil {
		return fmt.Errorf("update service image path: %w", err)
	}
	// A non-zero exit of the service must count as a failure, or the restart action never fires.
	return s.SetRecoveryActionsOnNonCrashFailures(true)
}

// ScheduleRollback implements Platform. The task is defined with XML so that times are ISO 8601
// and independent of the machine's regional settings.
func (w *Windows) ScheduleRollback(at time.Time, exe string) error {
	xml := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>%s update safety net</Description></RegistrationInfo>
  <Triggers><TimeTrigger><StartBoundary>%s</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>%s</Command><Arguments>rollback-check</Arguments></Exec></Actions>
</Task>`, xmlEscape(brand.AgentName), at.Local().Format("2006-01-02T15:04:05"), xmlEscape(exe))
	f := filepath.Join(w.DataDir, "rollback-task.xml")
	if err := os.WriteFile(f, utf16le(xml), 0o600); err != nil {
		return err
	}
	defer func() { _ = os.Remove(f) }()
	out, err := runSchtasks("/Create", "/TN", taskName, "/XML", f, "/F")
	if err != nil {
		return fmt.Errorf("schtasks /Create: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// CancelRollback implements Platform.
func (w *Windows) CancelRollback() error {
	out, err := runSchtasks("/Delete", "/TN", taskName, "/F")
	if err != nil && !strings.Contains(strings.ToLower(string(out)), "cannot find") && !strings.Contains(string(out), "does not exist") {
		return fmt.Errorf("schtasks /Delete: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// schtasksTimeout bounds one call of schtasks.exe. CancelRollback runs on the connection path (a new version proves
// itself by completing its first handshake), so a hung task scheduler must not hold the agent there.
const schtasksTimeout = time.Minute

func runSchtasks(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), schtasksTimeout)
	defer cancel()
	return exec.CommandContext(ctx, schtasks(), args...).CombinedOutput() // #nosec G204 -- fixed arguments and a path this agent wrote
}

func schtasks() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "schtasks.exe")
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 0, 2+2*len(u))
	out = append(out, 0xFF, 0xFE)
	for _, c := range u {
		out = append(out, byte(c), byte(c>>8)) // #nosec G115 -- deliberate split of a UTF-16 unit into two bytes
	}
	return out
}

// Restart implements Platform.
func (w *Windows) Restart() error {
	if w.RestartHook == nil {
		return errors.New("selfupdate: no restart hook")
	}
	w.RestartHook()
	return nil
}

// Bounce implements Platform: stop and start the service from outside.
func (w *Windows) Bounce() error {
	m, s, err := openService()
	if err != nil {
		return err
	}
	defer func() { _ = s.Close(); _ = m.Disconnect() }()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return err
		}
		for i := 0; i < 60; i++ {
			if st, err := s.Query(); err == nil && st.State == svc.Stopped {
				break
			}
			time.Sleep(time.Second)
		}
	}
	return s.Start()
}
