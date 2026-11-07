// Command msiversion turns a release version (git tag or internal/shared/version) into the numeric
// a.b.c.d ProductVersion that Windows Installer requires.
//
//	go run ./installer/windows/msiversion [-build N] [VERSION]
//
// VERSION may be v1.2.3, 1.2.3, 1.2.3-rc.1 or 0.1.0-dev. Without it the default of
// internal/shared/version is used. The first three fields are major.minor.patch (limits: 255, 255,
// 65535 as imposed by Windows Installer). The fourth field is 0 for a release and -build N for a
// pre-release (rc, dev, ...), so CI builds are distinguishable. Windows Installer ignores the fourth
// field when it compares versions for upgrades; the MSI therefore sets AllowSameVersionUpgrades.
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/auzring1/librepatch/internal/shared/version"
)

var semver = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// MSIVersion converts a semantic version to a numeric MSI ProductVersion.
func MSIVersion(v string, build int) (string, error) {
	m := semver.FindStringSubmatch(v)
	if m == nil {
		return "", fmt.Errorf("version %q is not MAJOR.MINOR.PATCH[-prerelease] (a leading v is allowed)", v)
	}
	limits := [3]uint64{255, 255, 65535}
	var f [3]uint64
	for i := range f {
		n, err := strconv.ParseUint(m[i+1], 10, 32)
		if err != nil || n > limits[i] {
			return "", fmt.Errorf("version %q: field %d exceeds the Windows Installer limit of %d", v, i+1, limits[i])
		}
		f[i] = n
	}
	fourth := 0
	if m[4] != "" { // pre-release
		if build < 0 || build > 65535 {
			return "", fmt.Errorf("build number %d is outside 0..65535", build)
		}
		fourth = build
	}
	return fmt.Sprintf("%d.%d.%d.%d", f[0], f[1], f[2], fourth), nil
}

func main() {
	build := flag.Int("build", 0, "fourth version field for pre-release builds (CI run number)")
	flag.Parse()
	v := version.Version
	if flag.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: msiversion [-build N] [VERSION]")
		os.Exit(2)
	}
	if flag.NArg() == 1 && flag.Arg(0) != "" {
		v = flag.Arg(0)
	}
	out, err := MSIVersion(v, *build)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Println(out)
}
