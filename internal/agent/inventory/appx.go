package inventory

import (
	"regexp"
	"strings"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// The AppX/MSIX registration store. This layout is not formally documented;
// the collector is best-effort and covered by the Windows CI probe plus the
// Phase 3 VM matrix (decision D33).
const appxStore = `SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore`

var sidKeyRe = regexp.MustCompile(`^S-1-(5-21|12-1)(-\d+)+$`)

// frameworkPrefixes are runtime/framework packages users never think of as apps.
var frameworkPrefixes = []string{"Microsoft.NET.", "Microsoft.VCLibs", "Microsoft.UI.Xaml", "Microsoft.WindowsAppRuntime",
	"Microsoft.Services.Store", "Microsoft.WinAppRuntime", "Windows.", "MicrosoftWindows."}

type appxName struct{ Name, Version, Arch, ResourceID, PublisherID string }

// parseAppxFullName parses "Name_Version_Arch_ResourceId_PublisherId".
func parseAppxFullName(s string) (appxName, bool) {
	parts := strings.Split(s, "_")
	if len(parts) != 5 || parts[0] == "" || parts[1] == "" {
		return appxName{}, false
	}
	return appxName{parts[0], parts[1], parts[2], parts[3], parts[4]}, true
}

func isFramework(name string) bool {
	for _, p := range frameworkPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// scanAppx lists AppX/MSIX packages: provisioned/all-user ones with machine
// scope, packages registered only for specific users (known SIDs) with user
// scope. Provisioned packages are not repeated per user.
func scanAppx(hklm RegNode, knownSIDs map[string]bool) ([]*agentv1.SoftwareItem, error) {
	store, err := hklm.Open(appxStore)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	var out []*agentv1.SoftwareItem
	machine := map[string]bool{}

	emit := func(fullName string, scope agentv1.SoftwareScope, sid string, inbox bool, node RegNode) {
		n, ok := parseAppxFullName(fullName)
		if !ok || n.ResourceID != "" {
			return // resource/language packs
		}
		it := &agentv1.SoftwareItem{
			Key:  &agentv1.SoftwareItemKey{Source: agentv1.SoftwareSource_SOFTWARE_SOURCE_APPX, Scope: scope, UserSid: sid, ItemKey: fullName},
			Name: n.Name, Version: n.Version, SystemComponent: inbox || isFramework(n.Name),
		}
		if node != nil {
			it.InstallLocation, _ = node.String("Path")
		}
		sanitize(it)
		out = append(out, it)
	}

	for _, set := range []struct {
		name  string
		inbox bool
	}{{"InboxApplications", true}, {"Applications", false}} {
		k, err := store.Open(set.name)
		if err != nil {
			continue
		}
		names, _ := k.SubKeyNames()
		for _, full := range names {
			if machine[full] {
				continue
			}
			machine[full] = true
			sub, _ := k.Open(full)
			emit(full, agentv1.SoftwareScope_SOFTWARE_SCOPE_MACHINE, "", set.inbox, sub)
			if sub != nil {
				sub.Close()
			}
		}
		k.Close()
	}

	subs, err := store.SubKeyNames()
	if err != nil {
		return out, err
	}
	for _, sid := range subs {
		if !sidKeyRe.MatchString(sid) || (knownSIDs != nil && !knownSIDs[sid]) {
			continue
		}
		k, err := store.Open(sid)
		if err != nil {
			continue
		}
		names, _ := k.SubKeyNames()
		for _, full := range names {
			if machine[full] {
				continue
			}
			sub, _ := k.Open(full)
			emit(full, agentv1.SoftwareScope_SOFTWARE_SCOPE_USER, sid, false, sub)
			if sub != nil {
				sub.Close()
			}
		}
		k.Close()
	}
	return out, nil
}
