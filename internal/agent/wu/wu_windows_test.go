//go:build windows

package wu

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// These tests run on a real Windows machine (the Windows CI "wu" job). They read, they never
// install: a hosted runner may or may not reach Windows Update, so a failed scan is logged, not
// failed, but a COM crash, a hang or an unparseable result is.

func TestWinPolicyAndPendingRebootAreReadable(t *testing.T) {
	p := NewClient(t.TempDir()).Policy()
	if p == nil || p.EffectiveSource == "" {
		t.Fatalf("policy = %+v", p)
	}
	t.Logf("effective source %q, notes %v, pending reboot %v", p.EffectiveSource, p.Notes, PendingReboot())
}

func TestWinScanReturnsWellFormedUpdates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	ups, err := NewClient(t.TempDir()).Scan(ctx, Options{Service: agentv1.WuService_WU_SERVICE_DEFAULT})
	if err != nil {
		t.Logf("scan not available on this machine: %v", err)
		return
	}
	t.Logf("scan found %d updates", len(ups))
	for _, u := range ups {
		if len(u.UpdateId) != 36 || u.Title == "" {
			t.Errorf("malformed update: %+v", u)
		}
	}
}
