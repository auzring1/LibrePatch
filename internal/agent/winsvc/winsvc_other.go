//go:build !windows

// Package winsvc runs the agent under the Windows Service Control Manager.
package winsvc

import (
	"context"
	"errors"
)

// IsService is always false off Windows.
func IsService() bool { return false }

// Run is unsupported off Windows.
func Run(string, func(context.Context) error) error { return errors.New("not a Windows service") }

// RequestRestart is a no-op off Windows.
func RequestRestart() {}
