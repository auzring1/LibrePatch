package inventory

import (
	"path/filepath"
	"strings"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// DirEntry is one directory entry.
type DirEntry struct {
	Name  string
	IsDir bool
}

// portableDirs are winget's portable package locations (relative to the
// profile root, or to %ProgramFiles% for machine scope).
const (
	userPortableRel    = `AppData\Local\Microsoft\WinGet\Packages`
	machinePortableRel = `WinGet\Packages`
)

// scanPortable lists winget portable package directories.
// Directory names look like "Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe".
func scanPortable(readDir func(string) ([]DirEntry, error), base string, scope agentv1.SoftwareScope, sid string) ([]*agentv1.SoftwareItem, error) {
	entries, err := readDir(base)
	if err != nil {
		return nil, err
	}
	var out []*agentv1.SoftwareItem
	for _, e := range entries {
		if !e.IsDir || e.Name == "" {
			continue
		}
		name := e.Name
		if i := strings.Index(name, "_"); i > 0 {
			name = name[:i]
		}
		it := &agentv1.SoftwareItem{
			Key:             &agentv1.SoftwareItemKey{Source: agentv1.SoftwareSource_SOFTWARE_SOURCE_PORTABLE, Scope: scope, UserSid: sid, ItemKey: e.Name},
			Name:            name,
			InstallLocation: filepath.Join(base, e.Name),
		}
		sanitize(it)
		out = append(out, it)
	}
	return out, nil
}
