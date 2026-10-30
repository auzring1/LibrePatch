package jobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/inventory"
	"github.com/auzring1/librepatch/internal/shared/installer"
	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

var (
	guidInRe = regexp.MustCompile(`\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}`)
	innoRe   = regexp.MustCompile(`(?i)^unins\d{3}\.exe$`)
	// nsisRe is the usual name of an NSIS uninstaller; the file is still checked for the NSIS signature before /S is trusted.
	nsisRe = regexp.MustCompile(`(?i)^(uninst|uninstall|uninstaller|remove)[^\\/]*\.exe$`)
)

// recheckDelay and recheckTries: some uninstallers hand the work to a copy of themselves and return at once (NSIS,
// Squirrel), so the Uninstall entry can outlive the process by a few seconds. A variable so tests do not wait.
var (
	recheckDelay = 1500 * time.Millisecond
	recheckTries = 10
)

// errNoSilent marks a program that cannot be removed without someone clicking through its uninstaller.
type errNoSilent struct{ msg string }

func (e errNoSilent) Error() string { return e.msg }

// readHead returns up to n bytes from the start of a file; a variable so tests need no real files.
var readHead = func(path string, n int) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- read-only, only to recognise the installer type
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, int64(n)))
}

// isNSIS reports whether the file is an NSIS uninstaller (it carries the "Nullsoft" marker), so /S is known to mean silent.
func isNSIS(path string) bool {
	b, err := readHead(path, 1<<20)
	return err == nil && bytes.Contains(b, []byte("Nullsoft"))
}

// uninstallPlan is a resolved command line plus how to run and judge it.
type uninstallPlan struct {
	exe  string
	args []string
	typ  installer.Type
	// viaHelper is true when the command must run in the user's context.
	desc string
}

// uninstall removes software named by an inventory row. The command line is
// derived locally from that row's registry entry; nothing executable is taken
// from the server (docs/ARCHITECTURE.md §7.5).
func (e *Engine) uninstall(ctx context.Context, r *Record, env *agentv1.JobEnvelope) *outcome {
	b := env.GetUninstall()
	scope, _ := scopeOf(b.Scope)
	sid := env.TargetUserSid
	timeout, _ := timeoutOf(b.TimeoutS)
	if b.ItemSource == "appx" {
		return e.uninstallAppx(ctx, r, env)
	}

	roots, err := e.P.UninstallRoots(scope, sid)
	if err != nil {
		return fail("cannot read the Uninstall registry: %v", err)
	}
	entry, closeAll := findEntry(roots, b.ItemKey)
	defer closeAll()
	if b.RemoveOlderThan != "" {
		// Cleanup of an outdated copy: never remove something that is not older than the target
		// (the inventory the server planned from may be stale, or the new installer replaced it).
		switch {
		case entry == nil:
			return &outcome{res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, DetectionPassed: true,
				AlreadySatisfied: true, Message: "the old copy is already gone; nothing to do"}}
		case !versionOlder(entry.version, b.RemoveOlderThan):
			return &outcome{res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, DetectionPassed: true,
				AlreadySatisfied: true, Message: fmt.Sprintf("left alone: installed version %q is not older than %s", entry.version, b.RemoveOlderThan)}}
		}
	}
	if entry == nil && b.ItemSource != "msi" {
		return &outcome{res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, DetectionPassed: true,
			AlreadySatisfied: true, Message: "already uninstalled; nothing to do"}}
	}

	if scope == installer.User && entry != nil {
		// The user's hive is read without expanding %LOCALAPPDATA% and friends (the service would expand them for itself).
		get := func(n string) string { return e.P.Env(scope, sid, n) }
		entry.quiet, entry.uninstall = expandVars(entry.quiet, get), expandVars(entry.uninstall, get)
	}
	plan, perr := e.planUninstall(b, scope, entry)
	if perr != nil {
		var ns errNoSilent
		if errors.As(perr, &ns) {
			return &outcome{reason: "no_silent_uninstall", res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_FAILED, Message: short(perr.Error())}}
		}
		return fail("%v", perr)
	}
	dir, derr := e.P.StagingDir(scope, sid, r.JobID)
	if derr != nil {
		return fail("cannot create the working directory: %v", derr)
	}
	defer func() { _ = e.P.RemoveAll(dir) }()
	log := filepath.Join(dir, "uninstall.log")
	exe, args := plan.exe, plan.args
	if plan.typ == installer.MSI {
		_, args = installer.MSIUninstallCommand(plan.args[0], log)
		exe = e.P.MsiExec()
	}
	spec := RunSpec{Exe: exe, Args: args, Dir: dir, Timeout: timeout, LogPath: log}
	var rr RunResult
	if scope == installer.User {
		spec.Helper = e.helperTask(r, dir, "")
		rr, err = e.P.RunAsUser(ctx, sid, spec)
		if errors.Is(err, ErrNoSession) {
			return &outcome{waitUser: true, res: &agentv1.JobResult{}}
		}
	} else {
		if plan.typ != installer.MSI {
			if terr := e.P.TrustedExecutable(exe); terr != nil {
				return fail("refusing to run %s as the service: %v", winBase(exe), terr)
			}
		}
		rr, err = e.P.Run(ctx, spec)
	}
	if err != nil {
		if ctx.Err() != nil {
			return &outcome{res: &agentv1.JobResult{}, cancelled: true}
		}
		return fail("could not run the uninstaller: %v", err)
	}
	oc := installer.Resolve(plan.typ, rr.ExitCode, nil, nil)
	if rr.TimedOut {
		oc = installer.Failed
	}
	res := &agentv1.JobResult{ExitCode: int32(rr.ExitCode), LogTail: tail(rr.LogTail), // #nosec G115 -- exit codes fit int32
		Message: fmt.Sprintf("uninstaller exit code %d (%s); %s", rr.ExitCode, oc, plan.desc)}
	switch oc {
	case installer.Success:
		res.Outcome = agentv1.JobOutcome_JOB_OUTCOME_SUCCESS
	case installer.RebootRequired:
		res.Outcome = agentv1.JobOutcome_JOB_OUTCOME_REBOOT_REQUIRED
	case installer.Retryable:
		res.Outcome = agentv1.JobOutcome_JOB_OUTCOME_RETRYABLE
	default:
		res.Outcome = agentv1.JobOutcome_JOB_OUTCOME_FAILED
	}
	if res.Outcome == agentv1.JobOutcome_JOB_OUTCOME_FAILED || res.Outcome == agentv1.JobOutcome_JOB_OUTCOME_RETRYABLE {
		return &outcome{res: res, reason: "uninstaller_failed"}
	}
	// Post-check: the Uninstall entry must be gone (given a few seconds, see recheckDelay).
	for try := 0; ; try++ {
		roots2, rerr := e.P.UninstallRoots(scope, sid)
		if rerr != nil {
			break
		}
		still, closeRoots := findEntry(roots2, b.ItemKey)
		closeRoots()
		res.DetectionPassed = still == nil
		if still != nil && try < recheckTries {
			select {
			case <-ctx.Done():
				return &outcome{res: &agentv1.JobResult{}, cancelled: true}
			case <-time.After(recheckDelay):
			}
			continue
		}
		if still != nil {
			res.Outcome = agentv1.JobOutcome_JOB_OUTCOME_FAILED
			res.Message = short("the uninstaller reported success but the program is still listed; " + res.Message)
			return &outcome{res: res, reason: "failed_detection"}
		}
		break
	}
	return &outcome{res: res}
}

// entryInfo is what the planner needs from an Uninstall key.
type entryInfo struct {
	quiet, uninstall, version string
	windowsInstaller          bool
}

// findEntry looks for the Uninstall subkey named key in any root. The returned
// closer closes every root.
func findEntry(roots []inventory.RegNode, key string) (*entryInfo, func()) {
	closeAll := func() {
		for _, r := range roots {
			r.Close()
		}
	}
	for _, r := range roots {
		k, err := r.Open(key)
		if err != nil {
			continue
		}
		info := &entryInfo{}
		info.quiet, _ = k.String("QuietUninstallString")
		info.uninstall, _ = k.String("UninstallString")
		info.version, _ = k.String("DisplayVersion")
		if v, ok := k.DWord("WindowsInstaller"); ok && v == 1 {
			info.windowsInstaller = true
		}
		k.Close()
		return info, closeAll
	}
	return nil, closeAll
}

// planUninstall picks the uninstall method in the documented order: MSI
// product code, recorded quiet string, recorded uninstall string plus known
// silent switches for the detected installer type.
func (e *Engine) planUninstall(b *agentv1.UninstallBody, scope installer.Scope, en *entryInfo) (*uninstallPlan, error) {
	code := b.ProductCode
	if code == "" && guidInRe.MatchString(b.ItemKey) && guidRe.MatchString(b.ItemKey) {
		code = b.ItemKey
	}
	if en != nil && code == "" && en.windowsInstaller {
		for _, s := range []string{en.uninstall, en.quiet} {
			if m := guidInRe.FindString(s); m != "" {
				code = m
				break
			}
		}
	}
	if code != "" && guidRe.MatchString(code) {
		return &uninstallPlan{typ: installer.MSI, args: []string{code}, desc: "msiexec /x " + code}, nil
	}
	if en == nil {
		return nil, errors.New("no uninstall information is recorded for this program")
	}
	pick := func(cmd string) (*uninstallPlan, error) {
		toks, err := installer.SplitCommandLine(cmd)
		if err != nil || len(toks) == 0 {
			return nil, errors.New("the recorded uninstall command could not be parsed")
		}
		exe := toks[0]
		if strings.EqualFold(winBase(exe), "rundll32.exe") && strings.Contains(strings.ToLower(cmd), "dfshim") {
			return nil, noSilent(&uninstallPlan{}, "rundll32.exe") // ClickOnce
		}
		if !isAbsWin(exe) {
			return nil, errors.New("the recorded uninstall command is not an absolute path")
		}
		if strings.EqualFold(winBase(exe), "msiexec.exe") {
			if m := guidInRe.FindString(cmd); m != "" {
				return &uninstallPlan{typ: installer.MSI, args: []string{m}, desc: "msiexec /x " + m}, nil
			}
			return nil, errors.New("msiexec uninstall without a product code")
		}
		return &uninstallPlan{exe: exe, args: toks[1:], typ: installer.EXE, desc: winBase(exe)}, nil
	}
	if en.quiet != "" {
		p, err := pick(en.quiet)
		if err != nil {
			return nil, err
		}
		if err := validateStringArgs(p.args); err != nil {
			return nil, err
		}
		p.args = append(p.args, b.ExtraArgs...)
		return p, nil
	}
	if en.uninstall != "" {
		p, err := pick(en.uninstall)
		if err != nil {
			return nil, err
		}
		base := winBase(p.exe)
		switch {
		case innoRe.MatchString(base):
			p.args = []string{"/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"}
			p.typ = installer.Inno
		case len(b.ExtraArgs) > 0:
			p.args = append([]string(nil), b.ExtraArgs...) // an administrator supplied the silent switches
		case strings.EqualFold(base, "update.exe") && hasArg(p.args, "--uninstall"):
			// Squirrel (many Electron apps): --uninstall with -s removes the app without asking.
			p.args = []string{"--uninstall", "-s"}
		case nsisRe.MatchString(base) && len(p.args) == 0 && isNSIS(p.exe):
			// NSIS copies itself to a temp folder and exits at once unless told to stay: _?= names the install folder
			// and must be the last argument.
			p.args = []string{"/S", "_?=" + winDir(p.exe)}
		default:
			return nil, noSilent(p, base)
		}
		return p, nil
	}
	return nil, errors.New("no uninstall command is recorded for this program")
}

// noSilent explains, in plain words, why a program cannot be removed unattended.
func noSilent(p *uninstallPlan, base string) error {
	switch {
	case strings.EqualFold(base, "selfservice.exe") || strings.Contains(strings.ToLower(strings.Join(p.args, " ")), "selfservice"):
		return errNoSilent{"this is a shortcut that Citrix Workspace delivers; it has no uninstaller of its own and goes away when the application is no longer published to the user in Citrix"}
	case strings.EqualFold(base, "rundll32.exe"):
		return errNoSilent{"this program (a ClickOnce app) can only be removed by the person it was installed for, from Settings, Apps"}
	}
	return errNoSilent{fmt.Sprintf("%s has no silent uninstall command, so removing it would wait for someone to click through a window; remove it by hand, or add its silent switches under Catalog, Overrides", base)}
}

// expandVars expands %NAME% references with the allow-listed set; a string that cannot be expanded is returned as it was.
func expandVars(s string, get func(string) string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	if out, err := installer.ExpandEnv(s, true, get); err == nil {
		return out
	}
	return s
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if strings.EqualFold(a, want) {
			return true
		}
	}
	return false
}

// winDir is the folder part of a Windows path.
func winDir(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[:i]
	}
	return p
}

// validateStringArgs accepts the arguments of a recorded quiet string. These
// come from the machine's own registry (HKLM) or the user's (HKCU), so they are
// only checked for shell metacharacters; the grammar of installer.ValidateArg is
// for administrator-entered switches.
func validateStringArgs(args []string) error {
	for _, a := range args {
		if len(a) > 1024 || strings.ContainsAny(a, "\x00\r\n") {
			return errors.New("the recorded uninstall command has unusable arguments")
		}
	}
	return nil
}

// isAbsWin reports whether p is an absolute Windows path (drive or UNC). The
// engine's logic is shared with Linux test builds, so it does not use filepath.
func isAbsWin(p string) bool {
	if len(p) >= 3 && ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	return strings.HasPrefix(p, `\\`)
}

// winBase is the last element of a Windows path.
func winBase(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// versionOlder reports whether installed is strictly older than target. An empty or unparseable
// installed version is never "older": when in doubt a copy is left alone.
func versionOlder(installed, target string) bool {
	a, b := vercmp.Key(installed), vercmp.Key(target)
	if a == nil || b == nil {
		return false
	}
	return bytes.Compare(a, b) < 0
}
