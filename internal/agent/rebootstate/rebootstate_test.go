package rebootstate

import (
	"reflect"
	"strings"
	"testing"
)

// The value from a real PC that showed "restart pending" several times a day: five deletions of Edge and Firefox
// leftovers (a source with the "*1" flag, then an empty destination each).
var realWorld = []string{
	`*1\??\C:\Program Files (x86)\Microsoft\EdgeUpdate\1.3.291.9`, "",
	`*1\??\C:\Program Files (x86)\Microsoft\Edge\Temp\11652_1489716447\old_msedge.exe`, "",
	`*1\??\C:\Program Files (x86)\Microsoft\Edge\Temp\11652_1489716447`, "",
	`*1\??\C:\Program Files (x86)\Microsoft\Edge\Temp`, "",
	`*1\??\C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice_tmp.exe`, "",
}

func TestRealWorldDeletionsDoNotNeedARestart(t *testing.T) {
	ops := ParsePendingFileRenames(realWorld)
	if len(ops.Deletes) != 5 || len(ops.Renames) != 0 {
		t.Fatalf("want 5 deletes and no renames, got %+v", ops)
	}
	if ops.Deletes[1] != `C:\Program Files (x86)\Microsoft\Edge\Temp\11652_1489716447\old_msedge.exe` {
		t.Fatalf("prefixes not removed: %q", ops.Deletes[1])
	}
	var s State
	ops.Classify(&s)
	if s.Pending() || len(s.Reasons) != 0 {
		t.Fatalf("queued deletions must not count as a pending restart: %+v", s)
	}
	if s.DeleteCount != 5 || len(s.DeleteSamples) != 5 {
		t.Fatalf("deletions must still be reported: %+v", s)
	}
}

func TestRenamesAndReplacesNeedARestart(t *testing.T) {
	ops := ParsePendingFileRenames([]string{
		`\??\C:\Windows\System32\drivers\new.sys.tmp`, `\??\C:\Windows\System32\drivers\new.sys`,
		`\??\C:\Program Files\App\a.dll.new`, `!\??\C:\Program Files\App\a.dll`,
		`\??\C:\Temp\x`, "",
	})
	if len(ops.Renames) != 2 || len(ops.Deletes) != 1 {
		t.Fatalf("got %+v", ops)
	}
	if !strings.HasSuffix(ops.Renames[1], `-> C:\Program Files\App\a.dll`) {
		t.Fatalf("replace marker not removed: %q", ops.Renames[1])
	}
	var s State
	ops.Classify(&s)
	if !s.Pending() || !reflect.DeepEqual(s.Reasons, []string{ReasonFileRename}) {
		t.Fatalf("a rename must count: %+v", s)
	}
}

func TestParseEdgeCases(t *testing.T) {
	if ops := ParsePendingFileRenames(nil); len(ops.Deletes)+len(ops.Renames) != 0 {
		t.Fatalf("nil: %+v", ops)
	}
	// An odd list: the last source has no destination, so it is a deletion.
	if ops := ParsePendingFileRenames([]string{`\??\C:\a`}); len(ops.Deletes) != 1 {
		t.Fatalf("odd list: %+v", ops)
	}
	// A pair with an empty source does nothing.
	if ops := ParsePendingFileRenames([]string{"", `\??\C:\b`}); len(ops.Deletes)+len(ops.Renames) != 0 {
		t.Fatalf("empty source: %+v", ops)
	}
	// A flag prefix of several digits, and text that merely starts with a star.
	if got := cleanPath(`*12\??\C:\x`); got != `C:\x` {
		t.Fatalf("flag prefix: %q", got)
	}
	if got := cleanPath(`*name`); got != "name" {
		t.Fatalf("star: %q", got)
	}
}

func TestSamplesAreBounded(t *testing.T) {
	var v []string
	for i := 0; i < 40; i++ {
		v = append(v, `\??\C:\Temp\f`, "")
	}
	var s State
	ParsePendingFileRenames(v).Classify(&s)
	if s.DeleteCount != 40 || len(s.DeleteSamples) != maxSamples {
		t.Fatalf("count %d samples %d", s.DeleteCount, len(s.DeleteSamples))
	}
}
