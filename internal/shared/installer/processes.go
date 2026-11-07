package installer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/auzring1/librepatch/internal/shared/brand"
)

// MaxProcessNames is how many programs a package or a job may name.
const MaxProcessNames = 10

// processNameRe is a plain image name. No path, no wildcard: the name is compared with the running programs, nothing more.
var processNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ +()-]{0,62}\.exe$`)

// neverClose are programs no job may ask about or close, however the administrator spells the list: parts of Windows,
// the session shell, installers and this agent. Ending any of them could hurt the machine or the update itself.
var neverClose = map[string]bool{
	"system.exe": true, "smss.exe": true, "csrss.exe": true, "wininit.exe": true, "winlogon.exe": true, "services.exe": true,
	"lsass.exe": true, "svchost.exe": true, "dwm.exe": true, "explorer.exe": true, "sihost.exe": true, "fontdrvhost.exe": true,
	"taskhostw.exe": true, "ctfmon.exe": true, "msiexec.exe": true, "trustedinstaller.exe": true, "tiworker.exe": true,
	"wuauclt.exe": true, "wuauserv.exe": true, "searchindexer.exe": true, "runtimebroker.exe": true, "conhost.exe": true,
	"logonui.exe": true, "lockapp.exe": true, "registry.exe": true,
	strings.ToLower(brand.AgentExe): true,
}

// ProtectedProcess reports whether a program is one that must never be closed by a job.
func ProtectedProcess(name string) bool { return neverClose[strings.ToLower(name)] }

// ValidateProcessNames checks the image names an administrator, an overlay or a job lists as "the programs this package replaces".
func ValidateProcessNames(names []string) error {
	if len(names) > MaxProcessNames {
		return fmt.Errorf("at most %d programs", MaxProcessNames)
	}
	for _, n := range names {
		if !processNameRe.MatchString(n) {
			return fmt.Errorf("a program is named by its file name, for example app.exe (not %q)", n)
		}
		if ProtectedProcess(n) {
			return fmt.Errorf("%s is part of Windows or of this agent and cannot be listed", n)
		}
	}
	return nil
}
