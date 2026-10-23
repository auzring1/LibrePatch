//go:build windows

package jobs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/auzring1/librepatch/internal/shared/installer"
)

type jobAssociate struct {
	CompletionKey  uintptr
	CompletionPort windows.Handle
}

// launcher starts the (suspended) process; token 0 means the current identity.
type launcher func(cmdline, dir *uint16, flags uint32, si *windows.StartupInfoEx, pi *windows.ProcessInformation) error

func defaultLauncher(cmdline, dir *uint16, flags uint32, si *windows.StartupInfoEx, pi *windows.ProcessInformation) error {
	return windows.CreateProcess(nil, cmdline, nil, nil, true, flags, nil, dir, &si.StartupInfo, pi)
}

// runInJob starts spec suspended, assigns it to a Job Object, resumes it and
// waits until every process in the job has exited (or the timeout/ctx ends,
// which kills the tree). stdout and stderr go to a file in spec.Dir whose tail
// is returned when the installer writes no log of its own.
func runInJob(ctx context.Context, spec RunSpec, token windows.Token) (RunResult, error) {
	l := launcher(defaultLauncher)
	return runInJobWith(ctx, spec, l)
}

func runInJobWith(ctx context.Context, spec RunSpec, launch launcher) (RunResult, error) {
	if !isAbsWin(spec.Exe) {
		return RunResult{}, fmt.Errorf("refusing to run a non-absolute path %q", spec.Exe)
	}
	cmdline, err := windows.UTF16PtrFromString(installer.ComposeCommandLine(spec.Exe, spec.Args))
	if err != nil {
		return RunResult{}, err
	}
	var dir *uint16
	if spec.Dir != "" {
		if dir, err = windows.UTF16PtrFromString(spec.Dir); err != nil {
			return RunResult{}, err
		}
	}

	// Output capture: a private inheritable file handle, restricted to this one child.
	outDir := spec.OutDir
	if outDir == "" {
		outDir = spec.Dir
	}
	outPath := filepath.Join(outDir, "output.log")
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	op, _ := windows.UTF16PtrFromString(outPath)
	outH, err := windows.CreateFile(op, windows.GENERIC_WRITE, windows.FILE_SHARE_READ, sa, windows.CREATE_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return RunResult{}, err
	}
	defer windows.CloseHandle(outH)
	np, _ := windows.UTF16PtrFromString("NUL")
	inH, err := windows.CreateFile(np, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, sa, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return RunResult{}, err
	}
	defer windows.CloseHandle(inH)

	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return RunResult{}, err
	}
	defer attrs.Delete()
	handles := []windows.Handle{inH, outH}
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return RunResult{}, err
	}
	si := &windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.StartupInfo.Cb = uint32(unsafe.Sizeof(*si))
	si.StartupInfo.Flags = windows.STARTF_USESTDHANDLES
	si.StartupInfo.StdInput, si.StartupInfo.StdOutput, si.StartupInfo.StdErr = inH, outH, outH

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return RunResult{}, err
	}
	defer windows.CloseHandle(job) // KILL_ON_JOB_CLOSE ends any survivors
	var lim windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	lim.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&lim)), uint32(unsafe.Sizeof(lim))); err != nil {
		return RunResult{}, err
	}
	port, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		return RunResult{}, err
	}
	defer windows.CloseHandle(port)
	assoc := jobAssociate{CompletionKey: uintptr(job), CompletionPort: port}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectAssociateCompletionPortInformation, uintptr(unsafe.Pointer(&assoc)), uint32(unsafe.Sizeof(assoc))); err != nil {
		return RunResult{}, err
	}

	const belowNormal = 0x00004000
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT | belowNormal | windows.CREATE_UNICODE_ENVIRONMENT)
	var pi windows.ProcessInformation
	if err := launch(cmdline, dir, flags, si, &pi); err != nil {
		return RunResult{}, err
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)
	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		return RunResult{}, fmt.Errorf("assign to job object: %w", err)
	}
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		return RunResult{}, err
	}

	res := RunResult{}
	var deadline time.Time
	if spec.Timeout > 0 {
		deadline = time.Now().Add(spec.Timeout)
	}
	for {
		var code uint32
		var key uintptr
		var ov *windows.Overlapped
		err := windows.GetQueuedCompletionStatus(port, &code, &key, &ov, 1000)
		if err == nil && code == jobObjectMsgActiveProcessZero {
			break
		}
		if err != nil && !errors.Is(err, windows.WAIT_TIMEOUT) {
			_ = windows.TerminateJobObject(job, 1)
			return res, err
		}
		if ctx.Err() != nil {
			_ = windows.TerminateJobObject(job, 1)
			return res, ctx.Err()
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			_ = windows.TerminateJobObject(job, 1)
			res.TimedOut = true
			break
		}
	}
	var exit uint32
	if err := windows.GetExitCodeProcess(pi.Process, &exit); err == nil {
		res.ExitCode = int(int32(exit)) // #nosec G115 -- exit codes are signed NTSTATUS/HRESULT values
	}
	if res.TimedOut {
		res.ExitCode = -1
	}
	if spec.LogPath != "" {
		res.LogTail = tailFile(spec.LogPath)
	}
	if res.LogTail == "" {
		res.LogTail = tailFile(outPath)
	}
	_ = os.Remove(outPath)
	return res, nil
}
