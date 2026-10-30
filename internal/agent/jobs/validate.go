package jobs

import (
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/agent/peercache"
	"net/url"
	"regexp"
	"strings"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/shared/installer"
	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

// Limits applied to every job body before anything is persisted or run.
const (
	MaxInstallerBytes = 4 << 30
	MaxTimeout        = 4 * time.Hour
	DefaultTimeout    = time.Hour
	MaxRetries        = 5
	MaxSources        = 4
	MaxDetections     = 16
)

// ErrBody is returned for a body that fails validation.
var ErrBody = errors.New("jobs: invalid job body")

var (
	guidRe     = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)
	sidRe      = regexp.MustCompile(`^S-1-\d+(-\d+)+$`)
	fileNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ +()\-]{0,127}$`)
)

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrBody, fmt.Sprintf(format, a...))
}

func scopeOf(s agentv1.InstallScope) (installer.Scope, bool) {
	switch s {
	case agentv1.InstallScope_INSTALL_SCOPE_MACHINE:
		return installer.Machine, true
	case agentv1.InstallScope_INSTALL_SCOPE_USER:
		return installer.User, true
	}
	return "", false
}

var typeNames = map[agentv1.InstallerType]installer.Type{
	agentv1.InstallerType_INSTALLER_TYPE_MSI:      installer.MSI,
	agentv1.InstallerType_INSTALLER_TYPE_MSIX:     installer.MSIX,
	agentv1.InstallerType_INSTALLER_TYPE_INNO:     installer.Inno,
	agentv1.InstallerType_INSTALLER_TYPE_NSIS:     installer.NSIS,
	agentv1.InstallerType_INSTALLER_TYPE_BURN:     installer.Burn,
	agentv1.InstallerType_INSTALLER_TYPE_EXE:      installer.EXE,
	agentv1.InstallerType_INSTALLER_TYPE_PORTABLE: installer.Portable,
	agentv1.InstallerType_INSTALLER_TYPE_ZIP:      installer.Zip,
}

func checkScopeSID(scope installer.Scope, sid string) error {
	switch scope {
	case installer.Machine:
		if sid != "" {
			return bad("machine-scope job with a user SID")
		}
	case installer.User:
		if !sidRe.MatchString(sid) || len(sid) > 128 {
			return bad("user-scope job without a valid SID")
		}
	}
	return nil
}

func validateDetections(ds []*agentv1.Detection) error {
	if len(ds) > MaxDetections {
		return bad("too many detection rules")
	}
	for _, d := range ds {
		if d.Key == "" || len(d.Key) > 512 || len(d.ValueName) > 256 || len(d.Version) > 128 {
			return bad("detection rule fields out of range")
		}
		switch d.Kind {
		case agentv1.DetectionKind_DETECTION_KIND_MSI_PRODUCT:
			if !guidRe.MatchString(d.Key) {
				return bad("MSI detection key is not a product code")
			}
		case agentv1.DetectionKind_DETECTION_KIND_REGISTRY, agentv1.DetectionKind_DETECTION_KIND_FILE, agentv1.DetectionKind_DETECTION_KIND_APPX:
		default:
			return bad("unknown detection kind")
		}
	}
	return nil
}

func timeoutOf(secs uint32) (time.Duration, error) {
	if secs == 0 {
		return DefaultTimeout, nil
	}
	d := time.Duration(secs) * time.Second
	if d > MaxTimeout {
		return 0, bad("timeout over %s", MaxTimeout)
	}
	return d, nil
}

// ValidateInstall checks an install body against the envelope's target SID.
func ValidateInstall(b *agentv1.InstallBody, targetSID string) error {
	if b == nil || b.Installer == nil {
		return bad("missing installer")
	}
	scope, ok := scopeOf(b.Scope)
	if !ok {
		return bad("unknown scope")
	}
	if err := checkScopeSID(scope, targetSID); err != nil {
		return err
	}
	in := b.Installer
	t, ok := typeNames[in.Type]
	if !ok {
		return bad("unknown installer type")
	}
	if t == installer.MSIX {
		// An MSIX/AppX package is installed for the whole computer by a script of the agent's own (D151).
		if scope != installer.Machine {
			return bad("an MSIX/AppX package is installed for the whole computer, not for one user")
		}
		if !installer.IsMSIXFileName(in.FileName) {
			return bad("an MSIX/AppX package file must end in .msix, .msixbundle, .appx or .appxbundle")
		}
		if _, err := msixName(b.Detection); err != nil {
			return bad("%v", err)
		}
	}
	if len(in.Sha256) != 32 {
		return bad("installer SHA-256 is mandatory")
	}
	if in.Size > MaxInstallerBytes {
		return bad("installer size over %d bytes", int64(MaxInstallerBytes))
	}
	if !fileNameRe.MatchString(in.FileName) || strings.Contains(in.FileName, "..") {
		return bad("installer file name must be a plain name")
	}
	if t == installer.Zip {
		nt, ok := typeNames[in.NestedType]
		if !ok || !nt.RunsProcess() {
			return bad("a ZIP package needs a process-based nested installer")
		}
		if in.NestedPath == "" || len(in.NestedPath) > 260 || strings.HasPrefix(in.NestedPath, "/") || strings.Contains(in.NestedPath, "..") ||
			strings.ContainsAny(in.NestedPath, `\:`) {
			return bad("nested path must be a relative archive path")
		}
	}
	if len(in.Sources) == 0 || len(in.Sources) > MaxSources {
		return bad("1..%d content sources required", MaxSources)
	}
	for _, s := range in.Sources {
		switch s.Kind {
		case agentv1.ContentSourceKind_CONTENT_SOURCE_KIND_SERVER:
			if in.Size == 0 {
				return bad("server content needs a known size")
			}
		case agentv1.ContentSourceKind_CONTENT_SOURCE_KIND_VENDOR:
			u, err := url.Parse(s.Url)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(s.Url) > 2048 {
				return bad("vendor sources must be https URLs")
			}
		case agentv1.ContentSourceKind_CONTENT_SOURCE_KIND_PEER:
			if _, err := peercache.ValidURL(s.Url); err != nil {
				return bad("%v", err)
			}
		default:
			return bad("unknown content source")
		}
	}
	if err := installer.ValidateArgs(in.Args); err != nil {
		return bad("%v", err)
	}
	if in.ProductCode != "" && !guidRe.MatchString(in.ProductCode) {
		return bad("product code is not a GUID")
	}
	if len(in.SuccessCodes) > 16 || len(in.CodeMap) > 32 {
		return bad("too many exit-code entries")
	}
	if err := validateDetections(b.Detection); err != nil {
		return err
	}
	if _, err := timeoutOf(b.TimeoutS); err != nil {
		return err
	}
	if b.MaxRetries > MaxRetries || b.RetryBackoffS > 3600 {
		return bad("retry limits exceeded")
	}
	if len(b.Version) > 128 || len(b.Name) > 256 || len(b.PackageId) > 200 {
		return bad("descriptive fields too long")
	}
	return validatePrompts(b.Prompts)
}

// ValidateUninstall checks an uninstall body.
func ValidateUninstall(b *agentv1.UninstallBody, targetSID string) error {
	if b == nil {
		return bad("missing body")
	}
	scope, ok := scopeOf(b.Scope)
	if !ok {
		return bad("unknown scope")
	}
	if err := checkScopeSID(scope, targetSID); err != nil {
		return err
	}
	switch b.ItemSource {
	case "reg64", "reg32", "hku", "hku32", "msi":
	case "appx":
		if scope != installer.Machine {
			return bad("an MSIX/AppX package is removed for the whole computer, not for one user")
		}
		if _, ok := installer.AppxNameFromFullName(b.ItemKey); !ok {
			return bad("the package full name is not valid")
		}
	default:
		return bad("unsupported item source %q", b.ItemSource)
	}
	if (scope == installer.Machine) == (b.ItemSource == "hku" || b.ItemSource == "hku32") {
		return bad("item source does not match the scope")
	}
	if b.ItemKey == "" || len(b.ItemKey) > 512 {
		return bad("item key out of range")
	}
	if b.ProductCode != "" && !guidRe.MatchString(b.ProductCode) {
		return bad("product code is not a GUID")
	}
	if b.ItemSource == "msi" && !guidRe.MatchString(b.ItemKey) {
		return bad("MSI items are identified by product code")
	}
	if v := b.RemoveOlderThan; v != "" && (len(v) > 128 || vercmp.Key(v) == nil) {
		return bad("remove_older_than is not a comparable version")
	}
	if err := installer.ValidateArgs(b.ExtraArgs); err != nil {
		return bad("%v", err)
	}
	if _, err := timeoutOf(b.TimeoutS); err != nil {
		return err
	}
	if b.MaxRetries > MaxRetries || b.RetryBackoffS > 3600 {
		return bad("retry limits exceeded")
	}
	return nil
}

// ValidateWindow bounds a maintenance window.
func ValidateWindow(w *agentv1.MaintenanceWindow) error {
	if w == nil {
		return nil
	}
	if w.StartMinute > 1439 || w.DurationMinutes > 1440 || len(w.Days) > 7 {
		return bad("maintenance window out of range")
	}
	for _, d := range w.Days {
		if d > 6 {
			return bad("maintenance window day out of range")
		}
	}
	if w.Tz != "" {
		if _, err := time.LoadLocation(w.Tz); err != nil {
			return bad("unknown time zone")
		}
	}
	return nil
}

// ceilingName maps a job type to its name in the local policy ceiling.
func ceilingName(t agentv1.JobType) string {
	switch t {
	case agentv1.JobType_JOB_TYPE_INVENTORY_FULL:
		return "inventory"
	case agentv1.JobType_JOB_TYPE_SOFTWARE_INSTALL:
		return "software_install"
	case agentv1.JobType_JOB_TYPE_SOFTWARE_UNINSTALL:
		return "software_uninstall"
	case agentv1.JobType_JOB_TYPE_SOFTWARE_UPDATE:
		return "software_update"
	case agentv1.JobType_JOB_TYPE_WU_SCAN:
		return "wu_scan"
	case agentv1.JobType_JOB_TYPE_WU_INSTALL:
		return "wu_install"
	case agentv1.JobType_JOB_TYPE_WU_HIDE:
		return "wu_hide"
	case agentv1.JobType_JOB_TYPE_REBOOT:
		return "reboot"
	case agentv1.JobType_JOB_TYPE_AGENT_UPDATE:
		return "agent_update"
	case agentv1.JobType_JOB_TYPE_WAKE:
		return "wake"
	case agentv1.JobType_JOB_TYPE_INSPECT:
		return "inspect"
	case agentv1.JobType_JOB_TYPE_RUN_SCRIPT:
		return "run_script"
	case agentv1.JobType_JOB_TYPE_PROFILE_DELETE:
		return "profile_delete"
	}
	return ""
}

func isWUType(t agentv1.JobType) bool {
	switch t {
	case agentv1.JobType_JOB_TYPE_WU_SCAN, agentv1.JobType_JOB_TYPE_WU_INSTALL, agentv1.JobType_JOB_TYPE_WU_HIDE, agentv1.JobType_JOB_TYPE_REBOOT:
		return true
	}
	return false
}

var updateIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// MaxWUUpdates bounds how many updates one job may name.
const MaxWUUpdates = 200

func validWuService(s agentv1.WuService) bool {
	return s >= agentv1.WuService_WU_SERVICE_UNSPECIFIED && s <= agentv1.WuService_WU_SERVICE_MICROSOFT_UPDATE
}

func validateWuRefs(refs []*agentv1.WuUpdateRef) error {
	if len(refs) == 0 || len(refs) > MaxWUUpdates {
		return bad("a job names between 1 and %d updates", MaxWUUpdates)
	}
	for _, r := range refs {
		if !updateIDRe.MatchString(r.GetUpdateId()) || r.Revision < 0 {
			return bad("malformed update reference")
		}
	}
	return nil
}

func validateRebootPolicy(p *agentv1.RebootPolicy, requireAllow bool) error {
	if p == nil {
		if requireAllow {
			return bad("missing reboot policy")
		}
		return nil
	}
	switch p.Allow {
	case agentv1.RebootAllow_REBOOT_ALLOW_UNSPECIFIED, agentv1.RebootAllow_REBOOT_ALLOW_NEVER,
		agentv1.RebootAllow_REBOOT_ALLOW_OUTSIDE_ACTIVE_HOURS, agentv1.RebootAllow_REBOOT_ALLOW_DEADLINE, agentv1.RebootAllow_REBOOT_ALLOW_NOW:
	default:
		return bad("unknown reboot policy")
	}
	if p.NotifyMinutes > 1440 {
		return bad("restart notice over 24 hours")
	}
	if a := p.ActiveHours; a != nil && (a.StartMinute > 1439 || a.EndMinute > 1439) {
		return bad("active hours out of range")
	}
	if p.Allow == agentv1.RebootAllow_REBOOT_ALLOW_DEADLINE && p.DeadlineAt <= 0 {
		return bad("deadline reboot without a deadline")
	}
	if p.Allow == agentv1.RebootAllow_REBOOT_ALLOW_NOW && p.NotifyMinutes == 0 {
		return bad("an immediate restart needs a countdown of at least one minute")
	}
	return nil
}

// ValidateWU checks a Windows Update or reboot job body. These jobs are machine-scope only.
func ValidateWU(env *agentv1.JobEnvelope) error {
	if env.TargetUserSid != "" {
		return bad("Windows Update jobs are machine-scope")
	}
	switch env.Type {
	case agentv1.JobType_JOB_TYPE_WU_SCAN:
		b := env.GetWuScan()
		if b == nil || !validWuService(b.Service) {
			return bad("bad scan body")
		}
	case agentv1.JobType_JOB_TYPE_WU_INSTALL:
		b := env.GetWuInstall()
		if b == nil || !validWuService(b.Service) {
			return bad("bad install body")
		}
		if err := validateWuRefs(b.Updates); err != nil {
			return err
		}
		if err := validateRebootPolicy(b.Reboot, false); err != nil {
			return err
		}
		if b.Reboot != nil && b.Reboot.Allow == agentv1.RebootAllow_REBOOT_ALLOW_NOW {
			return bad("an install job cannot demand an immediate restart")
		}
		if b.MaxRetries > MaxRetries {
			return bad("too many retries")
		}
		if _, err := timeoutOf(b.TimeoutS); err != nil {
			return err
		}
	case agentv1.JobType_JOB_TYPE_WU_HIDE:
		b := env.GetWuHide()
		if b == nil || !validWuService(b.Service) {
			return bad("bad hide body")
		}
		return validateWuRefs(b.Updates)
	case agentv1.JobType_JOB_TYPE_REBOOT:
		b := env.GetReboot()
		if b == nil || len(b.Reason) > 256 {
			return bad("bad reboot body")
		}
		return validateRebootPolicy(b.Reboot, true)
	}
	return nil
}

var profileSIDRe = regexp.MustCompile(`^S-1-(5-21|12-1)(-[0-9]{1,10}){4,5}$`)

// ValidateProfileDelete checks a profile removal. Only a person's own account is accepted: a domain, local or Entra ID user SID.
// The built-in accounts (SYSTEM, local service, network service) and service SIDs never match.
func ValidateProfileDelete(b *agentv1.ProfileDeleteBody) error {
	if b == nil {
		return bad("missing body")
	}
	if !profileSIDRe.MatchString(b.Sid) {
		return bad("not a user account SID")
	}
	if len(b.Username) > 256 {
		return bad("descriptive fields too long")
	}
	return nil
}
