//go:build windows

package jobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var procGetProcessMemoryInfo = windows.NewLazySystemDLL("psapi.dll").NewProc("GetProcessMemoryInfo")

// processMemoryCounters is PROCESS_MEMORY_COUNTERS.
type processMemoryCounters struct {
	Cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

// Processes implements Platform: the running programs, from a process snapshot. Memory and path need a handle; a
// program that will not give one (protected processes) is listed without them.
func (p *winPlatform) Processes() ([]ProcessInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []ProcessInfo
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		pi := ProcessInfo{PID: pe.ProcessID, ParentPID: pe.ParentProcessID, Name: windows.UTF16ToString(pe.ExeFile[:]), Threads: pe.Threads}
		var ses uint32
		if windows.ProcessIdToSessionId(pe.ProcessID, &ses) == nil {
			pi.Session = ses
		}
		if pe.ProcessID != 0 {
			if h, herr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pe.ProcessID); herr == nil {
				var mc processMemoryCounters
				mc.Cb = uint32(unsafe.Sizeof(mc))
				if r, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&mc)), uintptr(mc.Cb)); r != 0 {
					pi.WorkingSetKB = uint64(mc.WorkingSetSize) / 1024
				}
				buf := make([]uint16, 1024)
				n := uint32(len(buf))
				if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
					pi.Path = windows.UTF16ToString(buf[:n])
				}
				_ = windows.CloseHandle(h)
			}
		}
		out = append(out, pi)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return out, err
	}
	return out, nil
}

var serviceStates = map[svc.State]string{svc.Stopped: "stopped", svc.StartPending: "starting", svc.StopPending: "stopping", svc.Running: "running",
	svc.ContinuePending: "continuing", svc.PausePending: "pausing", svc.Paused: "paused"}

// Services implements Platform. Read-only: a service is opened for querying only.
func (p *winPlatform) Services() ([]ServiceInfo, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return nil, err
	}
	var out []ServiceInfo
	for _, n := range names {
		h, err := windows.OpenService(m.Handle, windows.StringToUTF16Ptr(n), windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
		if err != nil {
			continue
		}
		s := &mgr.Service{Name: n, Handle: h}
		si := ServiceInfo{Name: n}
		if cfg, err := s.Config(); err == nil {
			si.Display, si.Account, si.Path = cfg.DisplayName, cfg.ServiceStartName, cfg.BinaryPathName
			switch {
			case cfg.StartType == mgr.StartAutomatic && cfg.DelayedAutoStart:
				si.Start = "automatic_delayed"
			case cfg.StartType == mgr.StartAutomatic:
				si.Start = "automatic"
			case cfg.StartType == mgr.StartManual:
				si.Start = "manual"
			case cfg.StartType == mgr.StartDisabled:
				si.Start = "disabled"
			default:
				si.Start = fmt.Sprintf("type %d", cfg.StartType)
			}
		}
		if st, err := s.Query(); err == nil {
			si.State = serviceStates[st.State]
		}
		_ = windows.CloseServiceHandle(h)
		out = append(out, si)
	}
	return out, nil
}

// Events implements Platform with the system's own wevtutil.exe (absolute path, fixed arguments built from
// validated values, no shell).
func (p *winPlatform) Events(ctx context.Context, q EventQuery) ([]EventInfo, error) {
	if !inspectLogs[q.Log] {
		return nil, fmt.Errorf("log %q is not offered", q.Log)
	}
	root, _ := windows.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	exe := filepath.Join(root, "System32", "wevtutil.exe")
	ms := q.Since.Milliseconds()
	query := fmt.Sprintf("*[System[(Level>=1 and Level<=%d) and TimeCreated[timediff(@SystemTime) <= %d]]]", q.MaxLevel, ms)
	cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, exe, "qe", q.Log, "/q:"+query, fmt.Sprintf("/c:%d", q.Max), "/rd:true", "/f:RenderedXml") // #nosec G204 -- fixed binary, validated values
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &limitedBuffer{b: &out, max: 16 << 20}, &errb
	cmd.SysProcAttr = hiddenWindow()
	if err := cmd.Run(); err != nil {
		if cctx.Err() != nil {
			return nil, cctx.Err()
		}
		return nil, fmt.Errorf("wevtutil: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	return ParseEventXML(&out, q.Max)
}

type limitedBuffer struct {
	b   *bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.b.Len()+len(p) > l.max {
		p = p[:max(l.max-l.b.Len(), 0)]
	}
	l.b.Write(p)
	return len(p), nil
}

func hiddenWindow() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}
