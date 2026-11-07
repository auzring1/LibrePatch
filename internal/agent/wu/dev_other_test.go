//go:build !windows

package wu

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

func TestDevClientScansInstallsAndHides(t *testing.T) {
	dir := t.TempDir()
	body := `{"updates":[
	  {"id":"11111111-1111-1111-1111-111111111111","revision":200,"title":"2026-03 Cumulative Update (KB5000001)","kb":["5000001"],"classification":"Security Updates","severity":"Critical","needs_reboot":true},
	  {"id":"22222222-2222-2222-2222-222222222222","revision":1,"title":"Definition update","classification":"Definition Updates"},
	  {"id":"33333333-3333-3333-3333-333333333333","revision":1,"title":"Printer driver","driver":true}],
	  "fail_install":["22222222-2222-2222-2222-222222222222"]}`
	if err := os.WriteFile(filepath.Join(dir, "wu-dev.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewClient(dir)
	ctx := context.Background()
	ups, err := c.Scan(ctx, Options{})
	if err != nil || len(ups) != 2 {
		t.Fatalf("drivers are only offered when asked for: %v %v", ups, err)
	}
	if ups, _ = c.Scan(ctx, Options{IncludeDrivers: true}); len(ups) != 3 {
		t.Fatalf("with drivers: %d", len(ups))
	}
	if err := c.Hide(ctx, Options{}, []*agentv1.WuUpdateRef{{UpdateId: "22222222-2222-2222-2222-222222222222"}}, true); err != nil {
		t.Fatal(err)
	}
	ups, _ = c.Scan(ctx, Options{})
	hidden := 0
	for _, u := range ups {
		if u.State == agentv1.WuUpdateState_WU_UPDATE_STATE_HIDDEN {
			hidden++
		}
	}
	if hidden != 1 {
		t.Fatalf("hide: %v", ups)
	}
	res, err := c.Install(ctx, Options{}, []*agentv1.WuUpdateRef{
		{UpdateId: "11111111-1111-1111-1111-111111111111"}, {UpdateId: "22222222-2222-2222-2222-222222222222"}, {UpdateId: "99999999-9999-9999-9999-999999999999"}})
	if err != nil || len(res.Results) != 3 || !res.RebootRequired {
		t.Fatalf("%+v %v", res, err)
	}
	want := []agentv1.WuResult{agentv1.WuResult_WU_RESULT_INSTALLED_REBOOT, agentv1.WuResult_WU_RESULT_DOWNLOAD_FAILED, agentv1.WuResult_WU_RESULT_NOT_APPLICABLE}
	for i, r := range res.Results {
		if r.Result != want[i] {
			t.Errorf("result %d = %v, want %v", i, r.Result, want[i])
		}
	}
	if ups, _ = c.Scan(ctx, Options{}); len(ups) != 1 { // the hidden/failing one remains, the installed one is gone
		t.Fatalf("after install: %v", ups)
	}
	_ = os.WriteFile(filepath.Join(dir, "wu-dev.json"), []byte(`{"unavailable":"Windows Update service is disabled"}`), 0o600)
	if _, err := c.Scan(ctx, Options{}); err == nil {
		t.Fatal("an unavailable service must fail the scan")
	}
}
