//go:build windows

package jobs

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/auzring1/librepatch/internal/shared/installer"
)

var procWTSSendMessage = windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSSendMessageW")

// snapshotProcs lists every running program with its session.
func snapshotProcs() ([]Proc, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []Proc
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		var ses uint32
		if windows.ProcessIdToSessionId(pe.ProcessID, &ses) != nil {
			continue
		}
		out = append(out, Proc{PID: pe.ProcessID, Name: windows.UTF16ToString(pe.ExeFile[:]), Session: ses})
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return out, err
	}
	return out, nil
}

// RunningProcesses implements Platform.
func (p *winPlatform) RunningProcesses(names []string, sid string) ([]Proc, error) {
	want := map[string]bool{}
	for _, n := range names {
		want[strings.ToLower(n)] = true
	}
	var only uint32
	if sid != "" {
		s, ok := sessionOf(sid)
		if !ok {
			return nil, nil
		}
		only = s
	}
	all, err := snapshotProcs()
	if err != nil {
		return nil, err
	}
	var out []Proc
	for _, x := range all {
		if want[strings.ToLower(x.Name)] && (sid == "" || x.Session == only) {
			out = append(out, x)
		}
	}
	return out, nil
}

// UserSession implements Platform: the user's own session, or the active signed-in one (never session 0).
func (p *winPlatform) UserSession(sid string) (uint32, bool) {
	if sid != "" {
		return sessionOf(sid)
	}
	var info *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &info, &count); err != nil {
		return 0, false
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	console := windows.WTSGetActiveConsoleSessionId()
	var best uint32
	found := false
	for _, s := range unsafe.Slice(info, count) {
		if s.State != windows.WTSActive || s.SessionID == 0 {
			continue
		}
		if !found || s.SessionID == console {
			best, found = s.SessionID, true
		}
	}
	return best, found
}

// Ask implements Platform with WTSSendMessage: a standard message box the service shows in the user's session.
// No helper program is started and nothing from the user is executed; the answer is one of three numbers.
func (p *winPlatform) Ask(ctx context.Context, session uint32, title, message string, timeout time.Duration, yesNo bool) (Answer, error) {
	const (
		mbOK, mbYesNo       = 0x0, 0x4
		mbIconInfo, mbIconQ = 0x40, 0x20
		mbSetForeground     = 0x10000
		mbTopmost           = 0x40000
		idYes, idNo         = 6, 7
		maxSeconds          = 3600
	)
	t, err := windows.UTF16FromString(title)
	if err != nil {
		return 0, err
	}
	m, err := windows.UTF16FromString(message)
	if err != nil {
		return 0, err
	}
	style := uintptr(mbOK | mbIconInfo | mbSetForeground | mbTopmost)
	wait := uintptr(0)
	if yesNo {
		style, wait = mbYesNo|mbIconQ|mbSetForeground|mbTopmost, 1
	}
	secs := uint32(timeout / time.Second) // #nosec G115 -- bounded by validation to one hour
	if secs > maxSeconds {
		secs = maxSeconds
	}
	type reply struct {
		resp uint32
		ok   bool
		err  error
	}
	done := make(chan reply, 1)
	go func() {
		var resp uint32
		r, _, e := procWTSSendMessage.Call(0, uintptr(session),
			uintptr(unsafe.Pointer(&t[0])), uintptr((len(t)-1)*2),
			uintptr(unsafe.Pointer(&m[0])), uintptr((len(m)-1)*2),
			style, uintptr(secs), uintptr(unsafe.Pointer(&resp)), wait)
		if r == 0 {
			done <- reply{err: e}
			return
		}
		done <- reply{resp: resp, ok: true}
	}()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case d := <-done:
		if d.err != nil {
			return 0, fmt.Errorf("WTSSendMessage: %w", d.err)
		}
		switch d.resp {
		case idYes:
			return AnswerYes, nil
		case idNo:
			return AnswerNo, nil
		}
		return AnswerTimeout, nil
	}
}

// CloseProcesses implements Platform. Each program first gets the normal request to close, made by the system's
// own taskkill.exe running as the signed-in user (so only that user's windows are reached and nothing is forced).
// What is still open after grace is ended.
func (p *winPlatform) CloseProcesses(ctx context.Context, procs []Proc, grace time.Duration) ([]Proc, error) {
	bySession := map[uint32][]Proc{}
	for _, x := range procs {
		if x.Session != 0 {
			bySession[x.Session] = append(bySession[x.Session], x)
		}
	}
	for session, list := range bySession {
		if err := politeClose(ctx, session, list); err != nil {
			return stillRunning(procs), err
		}
	}
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if len(stillRunning(procs)) == 0 {
			return nil, nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(500 * time.Millisecond):
		}
	}
	if ctx.Err() != nil {
		return stillRunning(procs), ctx.Err()
	}
	// The same pid and image name again right now; a pid that was reused by another program is left alone.
	for _, x := range stillRunning(procs) {
		h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, x.PID)
		if err != nil {
			continue
		}
		_ = windows.TerminateProcess(h, 1)
		_, _ = windows.WaitForSingleObject(h, 5000)
		_ = windows.CloseHandle(h)
	}
	return stillRunning(procs), nil
}

// stillRunning returns the listed programs that are still there under the same pid and name.
func stillRunning(procs []Proc) []Proc {
	all, err := snapshotProcs()
	if err != nil {
		return procs
	}
	now := map[uint32]string{}
	for _, x := range all {
		now[x.PID] = strings.ToLower(x.Name)
	}
	var out []Proc
	for _, x := range procs {
		if n, ok := now[x.PID]; ok && n == strings.ToLower(x.Name) {
			out = append(out, x)
		}
	}
	return out
}

// politeClose runs `taskkill /PID n ...` (no /F: it asks the windows to close) in the user's session with the user's token.
func politeClose(ctx context.Context, session uint32, procs []Proc) error {
	var tok windows.Token
	if err := windows.WTSQueryUserToken(session, &tok); err != nil {
		return fmt.Errorf("WTSQueryUserToken: %w", err)
	}
	defer tok.Close()
	root, _ := windows.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	exe := filepath.Join(root, "System32", "taskkill.exe")
	var args []string
	for _, x := range procs {
		args = append(args, "/PID", strconv.FormatUint(uint64(x.PID), 10))
	}
	cl, err := windows.UTF16PtrFromString(installer.ComposeCommandLine(exe, args))
	if err != nil {
		return err
	}
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, tok, false); err != nil {
		return err
	}
	defer windows.DestroyEnvironmentBlock(env)
	si := windows.StartupInfo{Desktop: desktop}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	flags := uint32(windows.CREATE_NO_WINDOW | windows.CREATE_UNICODE_ENVIRONMENT)
	if err := windows.CreateProcessAsUser(tok, nil, cl, nil, nil, false, flags, env, nil, &si, &pi); err != nil {
		return fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)
	if ev, _ := windows.WaitForSingleObject(pi.Process, 15000); ev == uint32(windows.WAIT_TIMEOUT) {
		_ = windows.TerminateProcess(pi.Process, 1)
	}
	return ctx.Err()
}
