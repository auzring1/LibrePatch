// Package version holds build metadata injected with -ldflags.
package version

// These are overridden at build time:
//
//	-ldflags "-X github.com/auzring1/librepatch/internal/shared/version.Version=1.2.3"
var (
	Version = "0.1.0-dev"
	Commit  = "unknown"
)
