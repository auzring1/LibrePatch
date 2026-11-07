package api

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/server/settings"
)

// Saving "Ignore WSUS" tells the update service, so every online device is scanned from the new source at once (D154).
func TestSavingIgnoreWSUSIsReportedOnlyWhenItChanges(t *testing.T) {
	f := newSSOFx(t)
	ctx := context.Background()
	var told []string
	f.s.Settings.OnChange = func(_ context.Context, org uuid.UUID, section string, changes map[string]any) {
		if _, ok := changes["ignore_wsus"]; ok && section == "updates" && org == f.org {
			told = append(told, section)
		}
	}
	save := func(in map[string]any) {
		t.Helper()
		doc, err := f.s.Settings.Get(ctx, f.org, "updates")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.Settings.Put(ctx, settings.Actor{Org: f.org, User: f.boss}, "updates", doc.Revision, in); err != nil {
			t.Fatal(err)
		}
	}
	save(map[string]any{"ignore_wsus": true})
	save(map[string]any{"ignore_wsus": true, "rule_delay_days": 3}) // another key changed, not this one
	save(map[string]any{"ignore_wsus": false})
	if len(told) != 2 {
		t.Fatalf("told %d times, want 2 (switched on, switched off)", len(told))
	}
}
