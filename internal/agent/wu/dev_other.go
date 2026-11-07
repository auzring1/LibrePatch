//go:build !windows

package wu

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// devClient is the non-Windows stand-in: it reads and writes <dataDir>/wu-dev.json so tests, the
// browser test and demos can script what "Windows Update" offers. It is never shipped (the
// product agent is Windows-only).
type devClient struct {
	path string
	mu   sync.Mutex
}

// DevFile is the JSON document behind the development client.
type DevFile struct {
	Updates []DevUpdate `json:"updates"`
	// FailInstall lists update IDs whose installation fails with a download error.
	FailInstall []string `json:"fail_install,omitempty"`
	// Unavailable makes every call fail like a machine whose Windows Update service is disabled.
	Unavailable string                `json:"unavailable,omitempty"`
	Policy      *agentv1.WuPolicyInfo `json:"policy,omitempty"`
}

// DevUpdate is one scripted update.
type DevUpdate struct {
	ID             string   `json:"id"`
	Revision       int32    `json:"revision"`
	Title          string   `json:"title"`
	KB             []string `json:"kb,omitempty"`
	Classification string   `json:"classification,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	Driver         bool     `json:"driver,omitempty"`
	ReleaseDate    int64    `json:"release_date,omitempty"`
	NeedsReboot    bool     `json:"needs_reboot,omitempty"`
	Hidden         bool     `json:"hidden,omitempty"`
	Installed      bool     `json:"installed,omitempty"`
}

// DevRebootMarker is the file whose presence means the dev machine "needs a restart".
func DevRebootMarker(dataDir string) string { return filepath.Join(dataDir, "reboot-pending") }

// NewClient returns the development client rooted at dataDir.
func NewClient(dataDir string) Client { return &devClient{path: filepath.Join(dataDir, "wu-dev.json")} }

func (c *devClient) load() (*DevFile, error) {
	b, err := os.ReadFile(c.path) // #nosec G304 -- fixed dev path
	if errors.Is(err, os.ErrNotExist) {
		return &DevFile{}, nil
	}
	if err != nil {
		return nil, err
	}
	var f DevFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func (c *devClient) save(f *DevFile) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, b, 0o600)
}

func (u DevUpdate) proto(state agentv1.WuUpdateState) *agentv1.WuUpdate {
	cls := u.Classification
	if cls == "" {
		cls = "Updates"
		if u.Driver {
			cls = "Drivers"
		}
	}
	return &agentv1.WuUpdate{UpdateId: u.ID, Revision: u.Revision, Title: u.Title, Kb: u.KB, Classification: cls, Severity: u.Severity,
		Products: []string{"Windows 11"}, IsDriver: u.Driver, ReleaseDate: u.ReleaseDate, RebootRequired: u.NeedsReboot, State: state,
		SupportUrl: "https://support.microsoft.com/"}
}

func (c *devClient) Scan(_ context.Context, o Options) ([]*agentv1.WuUpdate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, err := c.load()
	if err != nil {
		return nil, err
	}
	if f.Unavailable != "" {
		return nil, errors.New(f.Unavailable)
	}
	var out []*agentv1.WuUpdate
	for _, u := range f.Updates {
		if u.Installed || (u.Driver && !o.IncludeDrivers) {
			continue
		}
		st := agentv1.WuUpdateState_WU_UPDATE_STATE_MISSING
		if u.Hidden {
			st = agentv1.WuUpdateState_WU_UPDATE_STATE_HIDDEN
		}
		out = append(out, u.proto(st))
	}
	return out, nil
}

func (c *devClient) Install(_ context.Context, o Options, refs []*agentv1.WuUpdateRef) (*InstallResult, error) {
	res, err := c.install(o, refs)
	if err == nil && res.RebootRequired {
		_ = os.WriteFile(DevRebootMarker(filepath.Dir(c.path)), []byte("1"), 0o600)
	}
	return res, err
}

func (c *devClient) install(o Options, refs []*agentv1.WuUpdateRef) (*InstallResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, err := c.load()
	if err != nil {
		return nil, err
	}
	if f.Unavailable != "" {
		return nil, errors.New(f.Unavailable)
	}
	res := &InstallResult{}
	for _, r := range refs {
		out := &agentv1.WuUpdateResult{UpdateId: r.UpdateId, Revision: r.Revision, Result: agentv1.WuResult_WU_RESULT_NOT_APPLICABLE}
		for i := range f.Updates {
			u := &f.Updates[i]
			if u.ID != r.UpdateId || u.Installed || (u.Driver && !o.IncludeDrivers) {
				continue
			}
			out.Revision = u.Revision
			failing := false
			for _, id := range f.FailInstall {
				failing = failing || id == u.ID
			}
			switch {
			case failing:
				out.Result, out.Hresult = agentv1.WuResult_WU_RESULT_DOWNLOAD_FAILED, -2145107940 // 0x80240024-ish
			case u.NeedsReboot:
				out.Result, u.Installed = agentv1.WuResult_WU_RESULT_INSTALLED_REBOOT, true
				res.RebootRequired = true
			default:
				out.Result, u.Installed = agentv1.WuResult_WU_RESULT_INSTALLED, true
			}
		}
		res.Results = append(res.Results, out)
	}
	return res, c.save(f)
}

func (c *devClient) Hide(_ context.Context, _ Options, refs []*agentv1.WuUpdateRef, hide bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, err := c.load()
	if err != nil {
		return err
	}
	for _, r := range refs {
		for i := range f.Updates {
			if f.Updates[i].ID == r.UpdateId {
				f.Updates[i].Hidden = hide
			}
		}
	}
	return c.save(f)
}

func (c *devClient) Policy() *agentv1.WuPolicyInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f, err := c.load(); err == nil && f.Policy != nil {
		return f.Policy
	}
	return &agentv1.WuPolicyInfo{EffectiveSource: "windows_update"}
}
