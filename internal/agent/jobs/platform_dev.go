//go:build !windows

package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/inventory"
	"github.com/auzring1/librepatch/internal/agent/selfupdate"
	"github.com/auzring1/librepatch/internal/agent/wu"
	"github.com/auzring1/librepatch/internal/shared/installer"
)

// devPlatform is the Linux stand-in used only for integration tests and the
// browser test. It runs "installers" as plain executables and has no registry,
// so detection uses files. It is never shipped (the product agent is Windows-only).
type devPlatform struct {
	dir    string
	pf     string
	suOnce sync.Once
	su     *selfupdate.Dev
}

// NewPlatform returns the development platform rooted at dataDir. The fake
// "Program Files" is LIBREPATCH_DEV_PROGRAMFILES or <dataDir>/pf.
func NewPlatform(dataDir string) Platform {
	pf := os.Getenv("LIBREPATCH_DEV_PROGRAMFILES")
	if pf == "" {
		pf = filepath.Join(dataDir, "pf")
	}
	return &devPlatform{dir: dataDir, pf: pf}
}

func (p *devPlatform) StagingDir(_ installer.Scope, _, jobID string) (string, error) {
	d := filepath.Join(p.dir, "stage", jobID)
	return d, os.MkdirAll(d, 0o700)
}
func (p *devPlatform) RemoveAll(path string) error           { return os.RemoveAll(path) }
func (p *devPlatform) FreeSpaceMB(string) (uint64, error)    { return 1 << 20, nil }
func (p *devPlatform) OSBuild() uint32                       { return 99999 }
func (p *devPlatform) AppxPackages(string) ([]string, error) { return nil, nil }
func (p *devPlatform) SessionEvents() <-chan struct{}        { return sessionSig }
func (p *devPlatform) HasSession(string) bool                { return true }
func (p *devPlatform) TrustedExecutable(string) error        { return nil }
func (p *devPlatform) MsiExec() string                       { return "msiexec.exe" }

func (p *devPlatform) Env(_ installer.Scope, _ string, name string) string {
	if strings.EqualFold(name, "PROGRAMFILES") {
		return p.pf
	}
	return os.Getenv(name)
}

func (p *devPlatform) FileVersion(path string) (string, bool, error) {
	if _, err := os.Stat(path); err != nil {
		return "", false, nil
	}
	return "", true, nil
}

type emptyRoot struct{}

func (emptyRoot) SubKeyNames() ([]string, error)         { return nil, nil }
func (emptyRoot) Open(string) (inventory.RegNode, error) { return nil, inventory.ErrRegNotExist }
func (emptyRoot) String(string) (string, bool)           { return "", false }
func (emptyRoot) DWord(string) (uint32, bool)            { return 0, false }
func (emptyRoot) Close()                                 {}

func (p *devPlatform) UninstallRoots(installer.Scope, string) ([]inventory.RegNode, error) {
	return []inventory.RegNode{emptyRoot{}}, nil
}

func (p *devPlatform) OpenLocked(path string) (LockedFile, error) { return os.Open(path) } // #nosec G304 -- staged file
func (p *devPlatform) VerifySignature(string) (Signature, error)  { return Signature{}, nil }

func (p *devPlatform) Run(ctx context.Context, s RunSpec) (RunResult, error) {
	if s.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}
	// A staged installer must be executable. A program that is not under the data directory (the shell that runs a
	// test script) belongs to the system and is left alone: changing its mode needs root, and on a machine where
	// the test agent runs as root it would damage the system's own shell.
	if rel, err := filepath.Rel(p.dir, s.Exe); err == nil && !strings.HasPrefix(rel, "..") {
		// #nosec G302 -- dev platform only: the staged test installer must be executable
		if err := os.Chmod(s.Exe, 0o700); err != nil && !errors.Is(err, os.ErrNotExist) {
			return RunResult{}, err
		}
	}
	cmd := exec.CommandContext(ctx, s.Exe, s.Args...) // #nosec G204 -- dev platform runs the staged, hash-verified test installer
	cmd.Dir = s.Dir
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	err := cmd.Run()
	res := RunResult{LogTail: out.String()}
	var ee *exec.ExitError
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		res.TimedOut = true
		res.ExitCode = -1
		return res, nil
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
		return res, nil
	case err != nil:
		return res, err
	}
	return res, nil
}

// WindowsUpdate is the scripted development client (see wu.DevFile).
// SelfUpdater returns the development slot simulation (one instance per platform so tests can hook its restart).
func (p *devPlatform) SelfUpdater() selfupdate.Platform { return p.Dev() }

// Dev exposes the slot simulation to tests and the browser test.
func (p *devPlatform) Dev() *selfupdate.Dev {
	p.suOnce.Do(func() { p.su = selfupdate.NewDev(p.dir) })
	return p.su
}

func (p *devPlatform) WindowsUpdate() wu.Client { return wu.NewClient(p.dir) }

// Reboot records the request instead of restarting the developer's machine.
func (p *devPlatform) Reboot(delay time.Duration, message string) error {
	b, _ := json.Marshal(map[string]any{"at": time.Now().Unix(), "delay_s": int(delay.Seconds()), "message": message})
	_ = os.Remove(wu.DevRebootMarker(p.dir))
	return os.WriteFile(filepath.Join(p.dir, "reboot-requested.json"), b, 0o600)
}

func (p *devPlatform) AbortReboot() error {
	err := os.Remove(filepath.Join(p.dir, "reboot-requested.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (p *devPlatform) RebootRequired() bool {
	_, err := os.Stat(wu.DevRebootMarker(p.dir))
	return err == nil
}

func (p *devPlatform) RunAsUser(ctx context.Context, _ string, s RunSpec) (RunResult, error) {
	return p.Run(ctx, s)
}

// The development platform has no interactive users: it cannot see their programs or talk to them.
func (p *devPlatform) RunningProcesses([]string, string) ([]Proc, error) { return nil, ErrUnsupported }
func (p *devPlatform) UserSession(string) (uint32, bool)                 { return 0, false }
func (p *devPlatform) Ask(context.Context, uint32, string, string, time.Duration, bool) (Answer, error) {
	return 0, ErrUnsupported
}
func (p *devPlatform) CloseProcesses(_ context.Context, procs []Proc, _ time.Duration) ([]Proc, error) {
	return procs, ErrUnsupported
}

// The development platform reads scripted views from inspect-dev.json in the agent's data directory
// ({"processes": [...], "services": [...], "events": [...]}), the way wu-dev.json scripts Windows updates.
func (p *devPlatform) devInspect() (v struct {
	Processes []ProcessInfo `json:"processes"`
	Services  []ServiceInfo `json:"services"`
	Events    []EventInfo   `json:"events"`
}, err error) {
	b, err := os.ReadFile(filepath.Join(p.dir, "inspect-dev.json"))
	if err != nil {
		return v, ErrUnsupported
	}
	return v, json.Unmarshal(b, &v)
}

func (p *devPlatform) Processes() ([]ProcessInfo, error) {
	v, err := p.devInspect()
	return v.Processes, err
}

func (p *devPlatform) Services() ([]ServiceInfo, error) {
	v, err := p.devInspect()
	return v.Services, err
}

func (p *devPlatform) Events(_ context.Context, q EventQuery) ([]EventInfo, error) {
	v, err := p.devInspect()
	if len(v.Events) > q.Max {
		v.Events = v.Events[:q.Max]
	}
	return v.Events, err
}

// ScriptHost on the development platform runs a script with /bin/sh, so the console flow can be tried without Windows.
func (p *devPlatform) ScriptHost(kind agentv1.ScriptInterpreter) (ScriptHost, error) {
	if kind != agentv1.ScriptInterpreter_SCRIPT_INTERPRETER_POWERSHELL {
		return ScriptHost{}, ErrUnsupported
	}
	return ScriptHost{FileName: "script.sh", Exe: "/bin/sh", Args: []string{"%FILE%"}}, nil
}
