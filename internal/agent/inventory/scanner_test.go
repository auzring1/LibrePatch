package inventory

import (
	"context"
	"errors"
	"strings"
	"testing"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

func find(items []*agentv1.SoftwareItem, source agentv1.SoftwareSource, scope agentv1.SoftwareScope, sid, key string) *agentv1.SoftwareItem {
	for _, it := range items {
		k := it.Key
		if k.Source == source && k.Scope == scope && k.UserSid == sid && k.ItemKey == key {
			return it
		}
	}
	return nil
}

func TestParseARP(t *testing.T) {
	root := node()
	u := `U`
	chrome := addApp(root, u, "Google Chrome", "Google Chrome", "130.0.6723.92")
	chrome.set("Publisher", "Google LLC").set("InstallDate", "20241015").set("InstallLocation", `C:\Program Files\Google\Chrome`).
		set("UninstallString", `"C:\setup.exe" --uninstall`).set("QuietUninstallString", `"C:\setup.exe" --uninstall --force`)
	addApp(root, u, "{ABCDEF12-3456-7890-ABCD-EF1234567890}", "Some MSI App", "1.2.3").dw("WindowsInstaller", 1)
	addApp(root, u, "MsiByName", "Name Keyed MSI", "").dw("WindowsInstaller", 1).
		set("UninstallString", `MsiExec.exe /X{11111111-2222-3333-4444-555555555555}`).dw("Version", 5<<24|2<<16|345)
	addApp(root, u, "hidden", "Hidden Thing", "1.0").dw("SystemComponent", 1)
	addApp(root, u, "noname", "", "1.0")
	addApp(root, u, "kb123", "Security Update for X (KB123)", "1").set("ParentKeyName", "OperatingSystem")
	addApp(root, u, "rollup", "Update Rollup 1", "1").set("ReleaseType", "Update Rollup")
	addApp(root, u, "baddate", "Bad Date", "1").set("InstallDate", "garbage")
	addApp(root, u, "slashdate", "Slash Date", "1").set("InstallDate", "2023/02/03")
	addApp(root, u, "badutf", "Bad\xff\xfeUTF "+strings.Repeat("x", 1000), "1")

	k, _ := root.Open(u)
	items, err := scanUninstall(k, srcReg64, scopeMach, "")
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]*agentv1.SoftwareItem{}
	for _, it := range items {
		byKey[it.Key.ItemKey] = it
	}
	for _, skipped := range []string{"noname", "kb123", "rollup"} {
		if byKey[skipped] != nil {
			t.Errorf("%s should be skipped", skipped)
		}
	}
	c := byKey["Google Chrome"]
	if c == nil || c.Version != "130.0.6723.92" || c.Publisher != "Google LLC" || c.InstallDate != "2024-10-15" ||
		c.QuietUninstallString == "" || c.ProductCode != "" || c.SystemComponent {
		t.Fatalf("chrome: %+v", c)
	}
	if m := byKey["{ABCDEF12-3456-7890-ABCD-EF1234567890}"]; m == nil || m.ProductCode != "{ABCDEF12-3456-7890-ABCD-EF1234567890}" {
		t.Fatalf("guid key product code: %+v", m)
	}
	if m := byKey["MsiByName"]; m == nil || m.ProductCode != "{11111111-2222-3333-4444-555555555555}" || m.Version != "5.2.345" {
		t.Fatalf("msi by name: %+v", m)
	}
	if h := byKey["hidden"]; h == nil || !h.SystemComponent {
		t.Fatalf("system component not flagged: %+v", h)
	}
	if byKey["baddate"].InstallDate != "" || byKey["slashdate"].InstallDate != "2023-02-03" {
		t.Fatal("date normalization")
	}
	bu := byKey["badutf"]
	if bu == nil || len(bu.Name) > maxName || !validUTF8(bu.Name) {
		t.Fatalf("name not sanitized: len=%d", len(bu.Name))
	}
}

func validUTF8(s string) bool {
	return strings.ToValidUTF8(s, "") == s || strings.Contains(s, "\uFFFD")
}

func TestScannerFullPicture(t *testing.T) {
	p := newFakePlatform()
	addApp(p.hklm, hklmUninstall, "Notepad++", "Notepad++ (64-bit x64)", "8.7.1")
	addApp(p.hklm, hklmUninstall32, "OldTool", "Old 32-bit Tool", "2.0")
	addApp(p.hklm, hklmUninstall, "{AAAAAAAA-0000-0000-0000-000000000001}", "MSI Registered", "1.0")

	alice := node()
	addApp(alice, userUninstall, "Code", "Microsoft Visual Studio Code (User)", "1.93.1")
	addApp(alice, userUninstall32, "Tool32", "User 32 Tool", "1.0")
	bob := node() // no Uninstall key at all: legitimate, zero apps
	p.hives = map[string]*fakeNode{sidAlice: alice, sidBob: bob}
	p.profiles = []Profile{
		{SID: sidAlice, Username: "alice", Domain: "ACME", Path: `C:\Users\alice`, Loaded: true, IsAdmin: true},
		{SID: sidBob, Username: "bob", Domain: "ACME", Path: `C:\Users\bob`},
	}
	// Winget portable: one registered in ARP too (must dedupe), one not.
	p.dirs[`C:\Users\alice\`+userPortableRel] = []DirEntry{{Name: "Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe", IsDir: true}, {Name: "stray.txt"}}
	addApp(alice, userUninstall, "Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe", "FFmpeg", "7.0")
	p.dirs[`C:\Users\bob\`+userPortableRel] = []DirEntry{{Name: "jqlang.jq_Microsoft.Winget.Source_8wekyb3d8bbwe", IsDir: true}}
	// MSI: one already in the registry (dedupe), one only visible through MSI enumeration, one per-user.
	p.msi = []MSIProduct{
		{Code: "{aaaaaaaa-0000-0000-0000-000000000001}", Name: "MSI Registered", Version: "1.0", Machine: true},
		{Code: "{BBBBBBBB-0000-0000-0000-000000000002}", Name: "MSI Hidden", Version: "3.1", Publisher: "Contoso", Machine: true},
		{Code: "{CCCCCCCC-0000-0000-0000-000000000003}", Name: "Per User MSI", Version: "9.9", SID: sidBob},
	}
	// AppX: provisioned (machine), user-only, resource pack (skipped), unknown SID (skipped).
	st := p.hklm.at(appxStore)
	st.at(`InboxApplications\Microsoft.WindowsCalculator_11.2.0.0_x64__8wekyb3d8bbwe`).set("Path", `C:\Program Files\WindowsApps\calc`)
	st.at(`Applications\Contoso.App_1.0.0.0_x64__abc`)
	st.at(sidAlice + `\Fabrikam.Notes_2.5.0.0_x64__xyz`)
	st.at(sidAlice + `\Microsoft.WindowsCalculator_11.2.0.0_x64__8wekyb3d8bbwe`) // provisioned: not repeated per user
	st.at(sidAlice + `\Fabrikam.Notes.Lang_2.5.0.0_x64_de-de_xyz`)               // resource package
	st.at(`S-1-5-21-9-9-9-5000\Ghost.App_1.0.0.0_x64__q`)                        // unknown profile
	st.at(sidBob + `\Microsoft.VCLibs.140.00_14.0.0.0_x64__8wekyb3d8bbwe`)

	scan, err := (&Scanner{P: p}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Failed) != 0 {
		t.Fatalf("unexpected failed groups: %+v %v", scan.Failed, scan.Warnings)
	}
	type want struct {
		src   agentv1.SoftwareSource
		scope agentv1.SoftwareScope
		sid   string
		key   string
	}
	for _, w := range []want{
		{srcReg64, scopeMach, "", "Notepad++"},
		{srcReg32, scopeMach, "", "OldTool"},
		{srcReg64, scopeMach, "", "{AAAAAAAA-0000-0000-0000-000000000001}"},
		{srcHKU, scopeUser, sidAlice, "Code"},
		{srcHKU32, scopeUser, sidAlice, "Tool32"},
		{srcHKU, scopeUser, sidAlice, "Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe"},
		{srcPortable, scopeUser, sidBob, "jqlang.jq_Microsoft.Winget.Source_8wekyb3d8bbwe"},
		{srcMSI, scopeMach, "", "{BBBBBBBB-0000-0000-0000-000000000002}"},
		{srcMSI, scopeUser, sidBob, "{CCCCCCCC-0000-0000-0000-000000000003}"},
		{srcAppx, scopeMach, "", "Microsoft.WindowsCalculator_11.2.0.0_x64__8wekyb3d8bbwe"},
		{srcAppx, scopeMach, "", "Contoso.App_1.0.0.0_x64__abc"},
		{srcAppx, scopeUser, sidAlice, "Fabrikam.Notes_2.5.0.0_x64_xyz"[:0] + "Fabrikam.Notes_2.5.0.0_x64__xyz"},
	} {
		if find(scan.Items, w.src, w.scope, w.sid, w.key) == nil {
			t.Errorf("missing %+v", w)
		}
	}
	// Must NOT be present:
	for _, bad := range []want{
		{srcPortable, scopeUser, sidAlice, "Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe"}, // duplicate of ARP
		{srcMSI, scopeMach, "", "{AAAAAAAA-0000-0000-0000-000000000001}"},                       // duplicate of ARP
		{srcAppx, scopeUser, sidAlice, "Microsoft.WindowsCalculator_11.2.0.0_x64__8wekyb3d8bbwe"},
		{srcAppx, scopeUser, sidAlice, "Fabrikam.Notes.Lang_2.5.0.0_x64_de-de_xyz"},
		{srcAppx, scopeUser, "S-1-5-21-9-9-9-5000", "Ghost.App_1.0.0.0_x64__q"},
	} {
		if find(scan.Items, bad.src, bad.scope, bad.sid, bad.key) != nil {
			t.Errorf("should not be present: %+v", bad)
		}
	}
	if calc := find(scan.Items, srcAppx, scopeMach, "", "Microsoft.WindowsCalculator_11.2.0.0_x64__8wekyb3d8bbwe"); calc == nil || !calc.SystemComponent || calc.Version != "11.2.0.0" {
		t.Errorf("provisioned appx: %+v", calc)
	}
	if vc := find(scan.Items, srcAppx, scopeUser, sidBob, "Microsoft.VCLibs.140.00_14.0.0.0_x64__8wekyb3d8bbwe"); vc == nil || !vc.SystemComponent {
		t.Errorf("framework package should be a system component: %+v", vc)
	}
	// Scope/SID invariants for every item.
	for _, it := range scan.Items {
		if (it.Key.Scope == scopeMach) != (it.Key.UserSid == "") {
			t.Errorf("scope/sid mismatch: %+v", it.Key)
		}
	}
	// Users.
	if len(scan.Users) != 2 || scan.Users[0].Username != "alice" || !scan.Users[0].Loaded || !scan.Users[0].IsAdmin {
		t.Errorf("users: %+v", scan.Users)
	}
}

func TestScannerFailureKeepsGroups(t *testing.T) {
	p := newFakePlatform()
	p.profiles = []Profile{{SID: sidAlice, Username: "alice", Path: `C:\Users\alice`}, {SID: sidBob, Username: "bob", Path: `C:\Users\bob`}}
	p.hives[sidBob] = node()
	p.hiveErr[sidAlice] = errors.New("hive locked")
	p.msiErr = errors.New("msi service down")
	scan, err := (&Scanner{P: p}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var sawAlice, sawMSI bool
	for _, g := range scan.Failed {
		if g.SID == sidAlice && g.Scope == scopeUser {
			sawAlice = true
		}
		if g.Source == srcMSI {
			sawMSI = true
		}
	}
	if !sawAlice || !sawMSI {
		t.Fatalf("failed groups not recorded: %+v", scan.Failed)
	}

	// A profile-list failure marks every user-scope group failed and omits users.
	p2 := newFakePlatform()
	p2.profErr = errors.New("registry denied")
	scan, _ = (&Scanner{P: p2}).Collect(context.Background())
	if len(scan.Failed) == 0 || scan.Failed[0].Scope != scopeUser || scan.Failed[0].SID != "" {
		t.Fatalf("profile failure: %+v", scan.Failed)
	}
}

func TestScannerTruncatesAndIsDeterministic(t *testing.T) {
	p := newFakePlatform()
	for i := 0; i < MaxItems+50; i++ {
		addApp(p.hklm, hklmUninstall, "app"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+itoa(i), "App "+itoa(i), "1.0")
	}
	scan, err := (&Scanner{P: p}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !scan.Truncated || len(scan.Items) != MaxItems {
		t.Fatalf("truncated=%v n=%d", scan.Truncated, len(scan.Items))
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

func TestParseProfileList(t *testing.T) {
	root := node()
	pl := root.at(profileListKey)
	pl.at("S-1-5-18").set("ProfileImagePath", `C:\Windows\system32\config\systemprofile`) // system: skipped
	pl.at("S-1-5-21-1-2-3-500").set("ProfileImagePath", `C:\Users\Administrator`).dw("LocalProfileLoadTimeLow", 0xD53E8000).dw("LocalProfileLoadTimeHigh", 0x01DB0000)
	pl.at("S-1-12-1-1-2-3-4").set("ProfileImagePath", `C:\Users\aad.user`)
	pl.at("S-1-5-21-1-2-3-501").set("ProfileImagePath", "  ") // empty path: skipped
	loaded := func(sid string) bool { return sid == "S-1-5-21-1-2-3-500" }
	lookup := func(sid string) (string, string, bool) {
		if sid == "S-1-5-21-1-2-3-500" {
			return "Administrator", "PC1", true
		}
		return "", "", false
	}
	ps, err := ParseProfileList(root, loaded, lookup)
	if err != nil || len(ps) != 2 {
		t.Fatalf("%v %+v", err, ps)
	}
	var admin, aad *Profile
	for i := range ps {
		if ps[i].SID == "S-1-5-21-1-2-3-500" {
			admin = &ps[i]
		} else {
			aad = &ps[i]
		}
	}
	if !admin.Loaded || !admin.IsAdmin || admin.Domain != "PC1" || admin.LastLogon < 1_600_000_000 {
		t.Fatalf("admin: %+v", admin)
	}
	if aad.Username != "aad.user" || aad.Loaded {
		t.Fatalf("aad fallback to path name: %+v", aad)
	}
	if filetimeToUnix(0, 0) != 0 || filetimeToUnix(1, 0) != 0 {
		t.Fatal("filetime edge cases")
	}
}

func TestAppxNames(t *testing.T) {
	n, ok := parseAppxFullName("Microsoft.WindowsStore_22410.1401.7.0_x64__8wekyb3d8bbwe")
	if !ok || n.Name != "Microsoft.WindowsStore" || n.Version != "22410.1401.7.0" || n.ResourceID != "" || n.PublisherID != "8wekyb3d8bbwe" {
		t.Fatalf("%+v", n)
	}
	for _, bad := range []string{"", "a_b", "x_y_z_w_v_u", "_1.0_x64__p"} {
		if _, ok := parseAppxFullName(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

// A profile whose folder was deleted is skipped without a warning, and nothing of it is kept; a profile that cannot be read
// for another reason is still reported and keeps its old items.
func TestScannerSkipsAProfileWhoseFolderIsGone(t *testing.T) {
	p := newFakePlatform()
	p.profiles = []Profile{{SID: sidAlice, Username: "alice", Path: `C:\Users\alice`}, {SID: sidBob, Username: "bob", Path: `C:\Users\bob`}}
	p.hives[sidBob] = node()
	p.hiveErr[sidAlice] = ErrProfileGone
	scan, err := (&Scanner{P: p}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range scan.Failed {
		if g.SID == sidAlice {
			t.Fatalf("a deleted profile is not a failure: %+v", scan.Failed)
		}
	}
	for _, w := range scan.Warnings {
		if strings.Contains(w, sidAlice) {
			t.Fatalf("and gives no warning: %v", scan.Warnings)
		}
	}
}
