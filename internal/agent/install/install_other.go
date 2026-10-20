//go:build !windows

package install

import (
	"errors"
	"io"
	"time"
)

// Options for Install.
type Options struct {
	Server      string
	Token       string
	AllowedJobs string
	// AllowScripts switches on running scripts from the console on this computer (off by default, D127).
	AllowScripts bool
	Wait         time.Duration
	Out          io.Writer
}

// Install is Windows-only; use `librepatch-agent run` on development platforms.
func Install(Options) error {
	return errors.New("install is only supported on Windows; use `librepatch-agent run` for development")
}

// Uninstall is Windows-only.
func Uninstall(io.Writer) error { return errors.New("uninstall is only supported on Windows") }
