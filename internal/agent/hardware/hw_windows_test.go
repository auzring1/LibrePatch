//go:build windows

package hardware

import (
	"context"
	"testing"
)

func TestWindowsCollector(t *testing.T) {
	hw, err := New().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", hw)
	if hw.Hostname == "" || hw.OsBuild < 17763 || hw.RamBytes == 0 || hw.CpuLogicalCores == 0 || len(hw.Disks) == 0 {
		t.Fatalf("incomplete inventory: %+v", hw)
	}
	if hw.OsCaption == "" || hw.OsVersion == "" {
		t.Fatalf("missing OS info: %+v", hw)
	}
	hb, err := New().Heartbeat(context.Background())
	if err != nil || hb.UptimeS == 0 {
		t.Fatalf("heartbeat: %+v %v", hb, err)
	}
}
