// Package jobs is the agent's job engine: it accepts verified job envelopes,
// persists them, schedules them (not_before, maintenance window, user logon),
// and runs them through the install pipeline (docs/ARCHITECTURE.md §5, §7).
//
// All operating-system access goes through Platform so the engine is tested on
// Linux with fakes; platform_windows.go holds the real implementation.
package jobs

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/auzring1/librepatch/internal/agent/inventory"
	"github.com/auzring1/librepatch/internal/agent/selfupdate"
	"github.com/auzring1/librepatch/internal/agent/wu"
	"github.com/auzring1/librepatch/internal/shared/installer"
)

// ErrNoSession means the target user has no interactive session right now.
var ErrNoSession = errors.New("jobs: user has no active session")

// ErrUnsupported means this platform cannot do the requested operation.
var ErrUnsupported = errors.New("jobs: not supported on this platform")

// ErrRebootScheduled means Windows already has a restart countdown running (a second click on Restart, or an
// administrator's own "shutdown"). It is not a failure: the restart the caller wants is on its way.
var ErrRebootScheduled = errors.New("jobs: a restart is already scheduled")

// Signature is the result of an Authenticode check.
type Signature struct {
	Signed     bool
	Valid      bool   // chain, timestamp and hash all verified
	Subject    string // leaf certificate subject (CN)
	Thumbprint []byte // SHA-256 of the leaf certificate
	Detail     string
}

// RunSpec is a process to run without a shell.
type RunSpec struct {
	Exe     string
	Args    []string
	Dir     string
	Timeout time.Duration
	// LogPath, if set, is read after the run and its tail returned (e.g. msiexec /l*v).
	LogPath string
	// Helper carries what the user-context helper needs to re-verify the job
	// (set by the engine for user-scope runs; the platform completes the rest).
	Helper *HelperTask
}

// RunResult is the outcome of RunSpec.
type RunResult struct {
	ExitCode int
	TimedOut bool
	// LogTail is the tail of LogPath, or of the process output when there is no log file.
	LogTail string
}

// LockedFile holds a verified file open so it cannot be modified or deleted
// until the process using it has started (closes the TOCTOU window).
type LockedFile interface {
	io.Reader
	io.Closer
}

// Platform is everything the engine needs from the operating system.
type Platform interface {
	// StagingDir creates a protected per-job directory: SYSTEM-only for machine
	// scope, SYSTEM-write plus user read/execute for user scope.
	StagingDir(scope installer.Scope, sid, jobID string) (string, error)
	RemoveAll(path string) error
	FreeSpaceMB(path string) (uint64, error)
	OSBuild() uint32
	// Env returns an environment variable for the scope (user scope: that user's profile).
	Env(scope installer.Scope, sid, name string) string
	FileVersion(path string) (version string, exists bool, err error)
	// UninstallRoots opens the registry roots holding Uninstall keys for the scope:
	// machine = HKLM 64+32 views; user = that user's hive (HKCU view). Callers close them.
	UninstallRoots(scope installer.Scope, sid string) (roots []inventory.RegNode, err error)
	AppxPackages(sid string) ([]string, error)
	// OpenLocked reopens path read-only with sharing denied for writers and deleters.
	OpenLocked(path string) (LockedFile, error)
	VerifySignature(path string) (Signature, error)
	// Run starts a process as the service identity (machine scope).
	Run(ctx context.Context, spec RunSpec) (RunResult, error)
	// RunAsUser runs the process in the user's session through the helper
	// (docs/ARCHITECTURE.md §8). It returns ErrNoSession when the user is not signed in.
	RunAsUser(ctx context.Context, sid string, spec RunSpec) (RunResult, error)
	// HasSession reports whether the user has an interactive session.
	HasSession(sid string) bool
	// SessionEvents delivers a signal when a session is created, unlocked or reconnected.
	SessionEvents() <-chan struct{}
	// TrustedExecutable reports whether path may be run as the service identity
	// (absolute, exists, in an administrator-controlled location).
	TrustedExecutable(path string) error
	// Systemroot-resolved msiexec path.
	MsiExec() string

	// WindowsUpdate returns the Windows Update Agent client.
	WindowsUpdate() wu.Client
	// Reboot restarts the machine after delay; signed-in users see a countdown with message.
	Reboot(delay time.Duration, message string) error
	// AbortReboot cancels a countdown started by Reboot.
	AbortReboot() error
	// RebootRequired reports whether Windows has a restart pending.
	RebootRequired() bool
	// SelfUpdater gives access to the A/B slots and the rollback task (nil = unsupported).
	SelfUpdater() selfupdate.Platform
}
