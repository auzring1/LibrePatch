//go:build !windows && !linux

package hardware

import (
	"context"
	"os"
	"runtime"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

type stub struct{}

// New returns a minimal collector for unsupported development platforms.
func New() Collector { return stub{} }

func (stub) Collect(ctx context.Context) (*agentv1.HardwareInventory, error) {
	h, _ := os.Hostname()
	return &agentv1.HardwareInventory{Hostname: h, OsCaption: runtime.GOOS, Arch: runtime.GOARCH, Interfaces: Interfaces()}, ctx.Err()
}

func (stub) Heartbeat(context.Context) (*agentv1.Heartbeat, error) { return &agentv1.Heartbeat{}, nil }
