// Package config is the agent's on-disk configuration (config.json in the
// protected data directory). The enrollment token is erased after use.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/auzring1/librepatch/internal/shared/bundle"
)

// Config is persisted as JSON.
type Config struct {
	// Server is host:port of the agent gateway.
	Server string `json:"server"`
	// RootPin pins the server's root CA SPKI ("sha256/...").
	RootPin string `json:"root_pin"`
	OrgID   string `json:"org_id"`
	// EnrollmentToken is the secret part of the enrollment bundle; cleared after enrollment.
	EnrollmentToken string `json:"enrollment_token,omitempty"`
	// AllowedJobs is the local policy ceiling (PROTOCOL §5 step 7). The server
	// cannot raise it. Empty means the default set for this agent version.
	AllowedJobs []string `json:"allowed_jobs,omitempty"`
	LogLevel    string   `json:"log_level,omitempty"`
	// UpdateRollbackMinutes is how long a freshly updated agent has to reach the server before the
	// safety net restores the previous version (default 10, allowed 1 to 60). Meant for tests and
	// diagnosis; it can only be changed by someone who can already write the data directory.
	UpdateRollbackMinutes int `json:"update_rollback_minutes,omitempty"`
}

// RollbackWindow returns the configured rollback window (0 = the engine default).
func (c *Config) RollbackWindow() time.Duration {
	if c.UpdateRollbackMinutes < 1 || c.UpdateRollbackMinutes > 60 {
		return 0
	}
	return time.Duration(c.UpdateRollbackMinutes) * time.Minute
}

// AllJobTypes lists every job type name a ceiling may contain.
var AllJobTypes = []string{"inventory", "software_install", "software_uninstall", "software_update",
	"wu_scan", "wu_install", "wu_hide", "reboot", "agent_update", "wake", "inspect"}

// FromBundle builds a config from an enrollment string. serverOverride, if
// non-empty, replaces the gateway address in the bundle (the root pin stays).
func FromBundle(enrollment, serverOverride string) (*Config, error) {
	b, err := bundle.Parse(enrollment)
	if err != nil {
		return nil, err
	}
	c := &Config{Server: b.Gateway, RootPin: b.RootPin, OrgID: b.Org, EnrollmentToken: b.Token, LogLevel: "info"}
	if s := strings.TrimSpace(serverOverride); s != "" {
		if _, _, err := net.SplitHostPort(s); err != nil {
			return nil, fmt.Errorf("--server must be host:port: %w", err)
		}
		c.Server = s
	}
	return c, nil
}

// ParseAllowedJobs validates a comma-separated job ceiling.
func ParseAllowedJobs(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if !slices.Contains(AllJobTypes, p) {
			return nil, fmt.Errorf("unknown job type %q (allowed: %s)", p, strings.Join(AllJobTypes, ","))
		}
		out = append(out, p)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// Load reads config.json.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed, ACL-protected path
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Server == "" || c.RootPin == "" {
		return nil, errors.New("config is missing server or root pin")
	}
	return &c, nil
}

// Save writes config.json atomically (owner-only permissions; on Windows the
// directory's protected DACL applies).
func Save(path string, c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Clean(path))
}
