package jobs

import (
	"strings"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/inventory"
	"github.com/auzring1/librepatch/internal/shared/installer"
	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

// Detection is the result of evaluating rules for one (scope, SID).
type Detection struct {
	Present bool
	Version string // best version found, if any
}

// Detect evaluates the rules. Rules are OR-ed: the product counts as present
// if any rule is satisfied. An empty rule list means "cannot tell" and is
// reported as not present with ok=false.
func (e *Engine) Detect(rules []*agentv1.Detection, scope installer.Scope, sid string) (d Detection, ok bool, err error) {
	if len(rules) == 0 {
		return Detection{}, false, nil
	}
	var roots []inventory.RegNode
	loaded := false
	openRoots := func() error {
		if loaded {
			return nil
		}
		loaded = true
		var rerr error
		roots, rerr = e.P.UninstallRoots(scope, sid)
		return rerr
	}
	defer func() {
		for _, r := range roots {
			r.Close()
		}
	}()
	for _, r := range rules {
		var found bool
		var ver string
		switch r.Kind {
		case agentv1.DetectionKind_DETECTION_KIND_MSI_PRODUCT, agentv1.DetectionKind_DETECTION_KIND_REGISTRY:
			if err := openRoots(); err != nil {
				return Detection{}, true, err
			}
			found, ver = detectRegistry(roots, r)
		case agentv1.DetectionKind_DETECTION_KIND_FILE:
			p, perr := installer.ExpandEnv(r.Key, scope == installer.User, func(n string) string { return e.P.Env(scope, sid, n) })
			if perr != nil {
				return Detection{}, true, perr
			}
			v, exists, ferr := e.P.FileVersion(p)
			if ferr != nil {
				return Detection{}, true, ferr
			}
			found, ver = exists, v
		case agentv1.DetectionKind_DETECTION_KIND_APPX:
			pkgs, aerr := e.P.AppxPackages(sid)
			if aerr != nil {
				return Detection{}, true, aerr
			}
			for _, name := range pkgs {
				if strings.HasPrefix(strings.ToLower(name), strings.ToLower(r.Key)) {
					found, ver = true, appxVersion(name)
					break
				}
			}
		}
		if found && versionOK(ver, r) {
			return Detection{Present: true, Version: ver}, true, nil
		}
		if found && ver != "" && d.Version == "" {
			d.Version = ver
		}
	}
	return d, true, nil
}

func detectRegistry(roots []inventory.RegNode, r *agentv1.Detection) (bool, string) {
	for _, root := range roots {
		k, err := root.Open(r.Key)
		if err != nil {
			continue
		}
		var ver string
		if r.ValueName != "" {
			v, ok := k.String(r.ValueName)
			k.Close()
			if !ok {
				continue
			}
			return true, v
		}
		ver, _ = k.String("DisplayVersion")
		k.Close()
		return true, ver
	}
	return false, ""
}

// appxVersion extracts the version from Name_Version_Arch__PublisherId.
func appxVersion(full string) string {
	parts := strings.Split(full, "_")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

func versionOK(have string, r *agentv1.Detection) bool {
	if r.Cmp == agentv1.VersionCmp_VERSION_CMP_UNSPECIFIED || r.Version == "" {
		return true
	}
	if have == "" {
		return false
	}
	switch r.Cmp {
	case agentv1.VersionCmp_VERSION_CMP_EQ:
		return vercmp.Compare(have, r.Version) == 0
	case agentv1.VersionCmp_VERSION_CMP_GE:
		return vercmp.Compare(have, r.Version) >= 0
	}
	return false
}
