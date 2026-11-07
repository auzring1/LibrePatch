// Command brokenagent is a deliberately broken "agent release" for testing agent self-update
// rollback. It answers `version` like the real agent (so the update passes its pre-switch check)
// and exits with an error as soon as it is started as the service, so it never reaches the server.
// It is only ever signed with a throw-away test key by the CI job and the demo script.
package main

import (
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"os"

	"github.com/auzring1/librepatch/internal/shared/version"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Printf(brand.VersionBanner+" %s (%s)\n", version.Version, version.Commit)
		return
	}
	fmt.Fprintln(os.Stderr, "brokenagent: refusing to run (this build exists to test rollback)")
	os.Exit(1)
}
