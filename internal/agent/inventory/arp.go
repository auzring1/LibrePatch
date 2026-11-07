package inventory

import (
	"fmt"
	"regexp"
	"strings"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// Uninstall key paths relative to HKLM (64-bit view) and to a user hive root.
const (
	hklmUninstall   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	hklmUninstall32 = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
	userUninstall   = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
	userUninstall32 = `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
)

var (
	guidRe = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)
	dateRe = regexp.MustCompile(`^(\d{4})[-/]?(\d{2})[-/]?(\d{2})$`)
	// release types that mark patches/updates, not applications (Windows
	// Update is reported by the WUA collector in Phase 4).
	updateTypes = map[string]bool{"security update": true, "update rollup": true, "hotfix": true,
		"service pack": true, "update": true, "critical update": true}
)

// scanUninstall reads one Add/Remove Programs key into software items.
func scanUninstall(root RegNode, source agentv1.SoftwareSource, scope agentv1.SoftwareScope, sid string) ([]*agentv1.SoftwareItem, error) {
	names, err := root.SubKeyNames()
	if err != nil {
		return nil, err
	}
	var out []*agentv1.SoftwareItem
	for _, name := range names {
		if len(name) == 0 || len(name) > maxKey {
			continue
		}
		sub, err := root.Open(name)
		if err != nil {
			continue
		}
		it := parseARP(sub, name)
		sub.Close()
		if it == nil {
			continue
		}
		it.Key = &agentv1.SoftwareItemKey{Source: source, Scope: scope, UserSid: sid, ItemKey: name}
		sanitize(it)
		out = append(out, it)
	}
	return out, nil
}

// parseARP converts one Uninstall subkey, or returns nil for entries that are
// not applications (no name, patches/updates).
func parseARP(k RegNode, keyName string) *agentv1.SoftwareItem {
	name, _ := k.String("DisplayName")
	if strings.TrimSpace(name) == "" {
		return nil
	}
	if p, _ := k.String("ParentKeyName"); p != "" {
		return nil // patch or component of another product
	}
	if rt, _ := k.String("ReleaseType"); updateTypes[strings.ToLower(rt)] {
		return nil
	}
	it := &agentv1.SoftwareItem{Name: name}
	it.Version, _ = k.String("DisplayVersion")
	if it.Version == "" {
		// Windows Installer products often only carry the packed DWORD.
		if v, ok := k.DWord("Version"); ok && v != 0 {
			it.Version = fmt.Sprintf("%d.%d.%d", v>>24, (v>>16)&0xff, v&0xffff)
		}
	}
	it.Publisher, _ = k.String("Publisher")
	it.InstallLocation, _ = k.String("InstallLocation")
	it.UninstallString, _ = k.String("UninstallString")
	it.QuietUninstallString, _ = k.String("QuietUninstallString")
	it.InstallDate = normalizeDate(k)
	if sc, ok := k.DWord("SystemComponent"); ok && sc == 1 {
		it.SystemComponent = true
	}
	if guidRe.MatchString(keyName) {
		it.ProductCode = strings.ToUpper(keyName)
	} else if wi, ok := k.DWord("WindowsInstaller"); ok && wi == 1 {
		// MSI-based but keyed by name; the code, if any, is in the uninstall string.
		it.ProductCode = productCodeFromString(it.UninstallString)
	}
	return it
}

var guidInStringRe = regexp.MustCompile(`\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}`)

func productCodeFromString(s string) string {
	if m := guidInStringRe.FindString(s); m != "" {
		return strings.ToUpper(m)
	}
	return ""
}

// normalizeDate turns InstallDate (REG_SZ "20240115" / "2024-01-15" /
// "2024/01/15", or a DWORD) into YYYY-MM-DD, or "" when unusable.
func normalizeDate(k RegNode) string {
	s, ok := k.String("InstallDate")
	if !ok {
		if d, ok := k.DWord("InstallDate"); ok {
			s = fmt.Sprintf("%d", d)
		}
	}
	return normalizeDateString(s)
}

// normalizeDateString is normalizeDate for a plain string.
func normalizeDateString(s string) string {
	m := dateRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return ""
	}
	y, mo, d := m[1], m[2], m[3]
	if y < "1990" || y > "2100" || mo < "01" || mo > "12" || d < "01" || d > "31" {
		return ""
	}
	return y + "-" + mo + "-" + d
}
