package deploy

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/catalog"
	"github.com/auzring1/librepatch/internal/shared/installer"
)

// Prompts are the optional messages to the signed-in user that a deployment or a policy may choose (D124). The zero value,
// and nil, mean what installations always did: run silently.
type Prompts struct {
	// InUse is what to do when the programs a package replaces are open: "ignore" (default), "skip" (wait until they are
	// closed), "ask" (ask the user to let them be closed) or "close" (warn, then close).
	InUse string `json:"in_use"`
	// AskTimeoutS is how long the question (ask) or the warning (close) stays up; 0 = 300.
	AskTimeoutS int `json:"ask_timeout_s,omitempty"`
	// DeferMinutes is how long skip and ask wait before they look again; 0 = 60.
	DeferMinutes int `json:"defer_minutes,omitempty"`
	// Restart is what happens when the installer says it needs a restart: "none" (default; only reported), "ask" or "countdown".
	Restart string `json:"restart"`
	// RestartNotifyMinutes is the length of the restart countdown; 0 = 5.
	RestartNotifyMinutes int `json:"restart_notify_minutes,omitempty"`
}

var (
	inUseEnum   = map[string]agentv1.InUseAction{"": agentv1.InUseAction_IN_USE_ACTION_IGNORE, "ignore": agentv1.InUseAction_IN_USE_ACTION_IGNORE, "skip": agentv1.InUseAction_IN_USE_ACTION_SKIP, "ask": agentv1.InUseAction_IN_USE_ACTION_ASK, "close": agentv1.InUseAction_IN_USE_ACTION_CLOSE}
	restartEnum = map[string]agentv1.RestartPrompt{"": agentv1.RestartPrompt_RESTART_PROMPT_NONE, "none": agentv1.RestartPrompt_RESTART_PROMPT_NONE, "ask": agentv1.RestartPrompt_RESTART_PROMPT_ASK, "countdown": agentv1.RestartPrompt_RESTART_PROMPT_COUNTDOWN}
)

// Silent reports whether the prompts change nothing.
func (p *Prompts) Silent() bool {
	return p == nil || ((p.InUse == "" || p.InUse == "ignore") && (p.Restart == "" || p.Restart == "none"))
}

// NeedsPrograms reports whether the in-use choice needs the names of the package's programs.
func (p *Prompts) NeedsPrograms() bool {
	return p != nil && p.InUse != "" && p.InUse != "ignore"
}

// Validate checks the choices and returns the form to store (nil when silent).
func (p *Prompts) Validate() (*Prompts, error) {
	if p == nil {
		return nil, nil
	}
	if _, ok := inUseEnum[p.InUse]; !ok {
		return nil, invalid("in_use must be ignore, skip, ask or close")
	}
	if _, ok := restartEnum[p.Restart]; !ok {
		return nil, invalid("restart must be none, ask or countdown")
	}
	if p.AskTimeoutS != 0 && (p.AskTimeoutS < 30 || p.AskTimeoutS > 3600) {
		return nil, invalid("the question stays up for 30 to 3600 seconds")
	}
	if p.DeferMinutes != 0 && (p.DeferMinutes < 5 || p.DeferMinutes > 1440) {
		return nil, invalid("the wait before looking again is 5 to 1440 minutes")
	}
	if p.RestartNotifyMinutes < 0 || p.RestartNotifyMinutes > 1440 {
		return nil, invalid("the restart countdown is 1 to 1440 minutes")
	}
	if p.Silent() {
		return nil, nil
	}
	return p, nil
}

// MarshalPrompts is the stored form (nil = silent).
func MarshalPrompts(p *Prompts) []byte {
	if p.Silent() {
		return nil
	}
	b, _ := json.Marshal(p)
	return b
}

// ParsePrompts reads the stored form.
func ParsePrompts(raw []byte) *Prompts {
	if len(raw) == 0 {
		return nil
	}
	var p Prompts
	if json.Unmarshal(raw, &p) != nil || p.Silent() {
		return nil
	}
	return &p
}

// Proto is what the agent receives. processes are the package's programs (only sent when they matter).
func (p *Prompts) Proto(processes []string) *agentv1.InstallPrompts {
	if p.Silent() {
		return nil
	}
	out := &agentv1.InstallPrompts{InUse: inUseEnum[p.InUse], Restart: restartEnum[p.Restart],
		AskTimeoutS: uint32(p.AskTimeoutS), DeferMinutes: uint32(p.DeferMinutes), RestartNotifyMinutes: uint32(p.RestartNotifyMinutes)} // #nosec G115 -- validated 0..3600
	if p.NeedsPrograms() {
		out.Processes = append([]string(nil), processes...)
	}
	return out
}

// checkPrograms is the error for a package without program names when the choice needs them.
func checkPrograms(p *Prompts, processes []string, pkgName string) error {
	if !p.NeedsPrograms() {
		return nil
	}
	if len(processes) == 0 {
		return invalid("%s has no program names yet. Add them on the package's page (for example chrome.exe) before choosing to wait for, ask about or close its programs", pkgName)
	}
	if err := installer.ValidateProcessNames(processes); err != nil {
		return invalid("%v", err)
	}
	return nil
}

// PackagePrograms returns the programs a package replaces: the administrator's own list, or the signed overlay's.
func (s *Service) PackagePrograms(ctx context.Context, org uuid.UUID, pkg dbq.CatalogPackage) []string {
	var ov *dbq.PackageOverride
	if o, err := dbq.New(s.Pool).GetPackageOverride(ctx, dbq.GetPackageOverrideParams{OrgID: org, PackageID: pkg.ID}); err == nil {
		ov = &o
	}
	if o := s.overlay(); o != nil {
		if e, ok := o.EntryFor(org, pkg.Identifier); ok {
			ov = catalog.MergeOverride(ov, e)
		}
	}
	if ov == nil {
		return nil
	}
	return ov.Processes
}

// CheckPrograms is the error for choosing to wait for, ask about or close programs of a package that has no program names.
func (s *Service) CheckPrograms(ctx context.Context, org uuid.UUID, pkg dbq.CatalogPackage, p *Prompts) error {
	if !p.NeedsPrograms() {
		return nil
	}
	return checkPrograms(p, s.PackagePrograms(ctx, org, pkg), pkg.Name)
}
