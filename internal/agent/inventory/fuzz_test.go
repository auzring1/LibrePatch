package inventory

import (
	"testing"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// FuzzScanUninstall: every string under an Uninstall key is written by an installer, or by malware.
// The scanner must not panic and must hand on only bounded, sanitized values.
func FuzzScanUninstall(f *testing.F) {
	f.Add("7-Zip", "23.01", "Igor Pavlov", `"C:\Program Files\7-Zip\Uninstall.exe"`, "20240115", "{23170F69-40C1-278A-1000-000100020000}", uint32(0))
	f.Add("", "", "", "", "", "", uint32(1))
	f.Fuzz(func(t *testing.T, name, version, publisher, uninstall, date, key string, dw uint32) {
		root := node()
		k := root.at("Uninstall\\" + "k")
		_ = key
		k.set("DisplayName", name).set("DisplayVersion", version).set("Publisher", publisher).
			set("UninstallString", uninstall).set("QuietUninstallString", uninstall).set("InstallDate", date)
		k.dw("Version", dw).dw("WindowsInstaller", dw&1).dw("SystemComponent", dw>>1&1)
		sub, err := root.Open("Uninstall")
		if err != nil {
			t.Fatal(err)
		}
		items, err := scanUninstall(sub, agentv1.SoftwareSource_SOFTWARE_SOURCE_REG64, agentv1.SoftwareScope_SOFTWARE_SCOPE_MACHINE, "")
		if err != nil {
			return
		}
		for _, it := range items {
			if len(it.Name) > maxName || len(it.UninstallString) > maxPath || len(it.Version) > maxVersion {
				t.Fatalf("unbounded value survived sanitize: %d/%d/%d", len(it.Name), len(it.UninstallString), len(it.Version))
			}
		}
	})
}
