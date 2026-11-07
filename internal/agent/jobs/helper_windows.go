//go:build windows

package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/auzring1/librepatch/internal/shared/installer"
)

// RunAsUser runs spec in the user's session through the helper process
// (docs/ARCHITECTURE.md §8): token from WTSQueryUserToken, two anonymous pipes
// whose child ends are passed through an explicit handle list, one task, one result.
func (p *winPlatform) RunAsUser(ctx context.Context, sid string, spec RunSpec) (RunResult, error) {
	if spec.Helper == nil {
		return RunResult{}, errors.New("no helper task was prepared")
	}
	session, ok := sessionOf(sid)
	if !ok {
		return RunResult{}, ErrNoSession
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(session, &tok); err != nil {
		return RunResult{}, fmt.Errorf("WTSQueryUserToken: %w", err)
	}
	defer tok.Close()

	self, err := os.Executable()
	if err != nil {
		return RunResult{}, err
	}
	// pipes: the service keeps taskW and resR; the helper gets taskR and resW.
	var taskR, taskW, resR, resW windows.Handle
	if err := windows.CreatePipe(&taskR, &taskW, nil, 0); err != nil {
		return RunResult{}, err
	}
	defer windows.CloseHandle(taskW)
	if err := windows.CreatePipe(&resR, &resW, nil, 0); err != nil {
		_ = windows.CloseHandle(taskR)
		return RunResult{}, err
	}
	defer windows.CloseHandle(resR)
	for _, h := range []windows.Handle{taskR, resW} {
		if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			_ = windows.CloseHandle(taskR)
			_ = windows.CloseHandle(resW)
			return RunResult{}, err
		}
	}

	cmdline := installer.ComposeCommandLine(self, []string{"helper", strconv.FormatUint(uint64(taskR), 10), strconv.FormatUint(uint64(resW), 10)})
	cl, _ := windows.UTF16PtrFromString(cmdline)
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		_ = windows.CloseHandle(taskR)
		_ = windows.CloseHandle(resW)
		return RunResult{}, err
	}
	defer attrs.Delete()
	handles := []windows.Handle{taskR, resW}
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		_ = windows.CloseHandle(taskR)
		_ = windows.CloseHandle(resW)
		return RunResult{}, err
	}
	si := &windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.StartupInfo.Cb = uint32(unsafe.Sizeof(*si))
	si.StartupInfo.Desktop = desktop

	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, tok, false); err != nil {
		_ = windows.CloseHandle(taskR)
		_ = windows.CloseHandle(resW)
		return RunResult{}, fmt.Errorf("CreateEnvironmentBlock: %w", err)
	}
	defer windows.DestroyEnvironmentBlock(env)

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		_ = windows.CloseHandle(taskR)
		_ = windows.CloseHandle(resW)
		return RunResult{}, err
	}
	defer windows.CloseHandle(job)
	var lim windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	lim.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&lim)), uint32(unsafe.Sizeof(lim))); err != nil {
		_ = windows.CloseHandle(taskR)
		_ = windows.CloseHandle(resW)
		return RunResult{}, err
	}

	const belowNormal = 0x00004000
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT | belowNormal)
	var pi windows.ProcessInformation
	err = windows.CreateProcessAsUser(tok, nil, cl, nil, nil, true, flags, env, nil, &si.StartupInfo, &pi)
	// the helper owns its ends now; closing ours makes EOF reach the right side
	_ = windows.CloseHandle(taskR)
	_ = windows.CloseHandle(resW)
	if err != nil {
		return RunResult{}, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)
	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		return RunResult{}, err
	}
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		return RunResult{}, err
	}

	task := *spec.Helper
	task.Exe, task.Args, task.Dir, task.LogPath = spec.Exe, spec.Args, spec.Dir, spec.LogPath
	task.TimeoutS = int64(spec.Timeout / time.Second)
	b, err := json.Marshal(task)
	if err != nil {
		_ = windows.TerminateJobObject(job, 1)
		return RunResult{}, err
	}
	tw := os.NewFile(uintptr(taskW), "task")
	if _, err := tw.Write(b); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		return RunResult{}, fmt.Errorf("send task: %w", err)
	}
	_ = tw.Close()
	taskW = 0

	resCh := make(chan []byte, 1)
	rf := os.NewFile(uintptr(resR), "result")
	go func() {
		out, _ := io.ReadAll(io.LimitReader(rf, maxResultBytes+1))
		resCh <- out
	}()
	wait := spec.Timeout + time.Minute
	ev, _ := windows.WaitForSingleObject(pi.Process, uint32(wait/time.Millisecond)) // #nosec G115 -- bounded by MaxTimeout
	timedOut := ev == uint32(windows.WAIT_TIMEOUT)
	if timedOut || ctx.Err() != nil {
		_ = windows.TerminateJobObject(job, 1)
	}
	var out []byte
	select {
	case out = <-resCh:
	case <-time.After(5 * time.Second):
	}
	if ctx.Err() != nil {
		return RunResult{}, ctx.Err()
	}
	if timedOut {
		return RunResult{ExitCode: -1, TimedOut: true}, nil
	}
	if len(out) == 0 || len(out) > maxResultBytes {
		return RunResult{}, errors.New("the helper returned no usable result")
	}
	var hr HelperResult
	if err := json.Unmarshal(out, &hr); err != nil {
		return RunResult{}, errors.New("the helper returned malformed data")
	}
	if hr.Error != "" {
		return RunResult{}, fmt.Errorf("the helper refused the task: %s", hr.Error)
	}
	return RunResult{ExitCode: hr.ExitCode, TimedOut: hr.TimedOut, LogTail: hr.LogTail}, nil
}

// HelperMain is the entry point of `librepatch-agent helper <task-handle> <result-handle>`.
func HelperMain(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: helper <task-handle> <result-handle>")
	}
	th, err1 := strconv.ParseUint(args[0], 10, 64)
	rh, err2 := strconv.ParseUint(args[1], 10, 64)
	if err1 != nil || err2 != nil {
		return errors.New("bad handles")
	}
	tf, rf := os.NewFile(uintptr(th), "task"), os.NewFile(uintptr(rh), "result")
	defer tf.Close()
	defer rf.Close()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := u.User.Sid.String()
	plat := &winPlatform{}
	env := HelperEnv{CurrentSID: sid, StageRoot: filepath.Join(programData(), brand.StageFolderName, sid),
		Run:        func(ctx context.Context, s RunSpec) (RunResult, error) { return runInJob(ctx, s, 0) },
		OpenLocked: plat.OpenLocked}
	ctx, cancel := context.WithTimeout(context.Background(), MaxTimeout+5*time.Minute)
	defer cancel()
	return ServeHelper(ctx, tf, rf, env)
}
