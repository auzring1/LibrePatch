// Package config loads server configuration from environment variables.
//
// Secrets are never read from plain environment variables in production:
// every secret has a *_FILE variant intended for Docker secrets, and the
// plain variant is only accepted when LIBREPATCH_DEV_MODE=true.
package config

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/auzring1/librepatch/internal/shared/release"
)

// Default enrollment rate limits, per minute (PROTOCOL §4.1).
const (
	DefaultEnrollRatePerIP    = 10
	DefaultEnrollRatePerToken = 60
)

// Config is the full server configuration.
type Config struct {
	DevMode bool

	// HTTPAddr serves the REST API, GUI and SSE (behind Caddy).
	HTTPAddr string
	// PublicURL is the browser-facing origin, e.g. https://librepatch.example.com.
	// Used for Origin/CSRF checks and cookie security.
	PublicURL *url.URL
	// TrustedProxies are the CIDRs whose X-Forwarded-For header is trusted.
	TrustedProxies []netip.Prefix

	// GatewayAddr is the agent mTLS listener.
	GatewayAddr string
	// GatewayPublicAddr is host:port agents dial (embedded in enrollment bundles).
	GatewayPublicAddr string
	// GatewaySANs are DNS names / IPs placed in the gateway certificate.
	GatewaySANs []string

	// DatabaseURL is the runtime (least-privilege) connection.
	DatabaseURL string
	// MigrateDatabaseURL is the schema-owner connection used for migrations.
	// Empty means "use DatabaseURL".
	MigrateDatabaseURL string
	MigrateOnStart     bool

	// MasterKey is the 32-byte key-encryption key (KEK).
	MasterKey []byte
	// MasterKeyFile is the file the key is read from ("" when it came from LIBREPATCH_MASTER_KEY).
	MasterKeyFile string
	// MasterKeyGenerated is true when LIBREPATCH_MASTER_KEY_AUTOGEN=true and the key file does not exist yet: MasterKey
	// then holds a new random key that only the maintenance service's migrate step persists (decision D109).
	MasterKeyGenerated bool

	// DeviceCertLifetime and renewal grace (shortened only in tests).
	DeviceCertLifetime time.Duration
	DeviceRenewGrace   time.Duration
	EnrollPollInterval time.Duration
	// EnrollRatePerIP and EnrollRatePerToken are the enrollment attempts allowed per minute for one
	// source IP and one enrollment token (the burst is the same number). Defaults: 10 and 60. They
	// protect token guessing; raise them only for a rollout of many machines behind one NAT address.
	EnrollRatePerIP    int
	EnrollRatePerToken int
	HeartbeatInterval  time.Duration
	// IgnoreIPAllowlist is the break-glass switch for a console IP allow-list that locked everyone out.
	IgnoreIPAllowlist  bool
	SessionIdleTimeout time.Duration
	SessionAbsTimeout  time.Duration
	LogLevel           string

	// ContentDir holds uploaded installers (a volume in compose). Empty disables custom packages.
	ContentDir string
	// GitHubToken optionally raises the GitHub API rate limit for winget imports.
	GitHubToken string
	// WingetSource is "github" (default) or "off". "off" also turns off the winget index download.
	WingetSource string
	// AgentReleaseDir is where the server image keeps the agent release it was built with (D149).
	AgentReleaseDir string
	// AgentDownloads is "github" (default: the server fetches the agent installers from the release that matches its
	// version and offers them in the console) or "off".
	AgentDownloads string
	// AgentDownloadBaseURL overrides where the installers are fetched from (a mirror); "" = the project's releases; https only.
	AgentDownloadBaseURL string
	// WingetIndexURL overrides where the winget index is downloaded from ("" = Microsoft's winget CDN); https only.
	WingetIndexURL string
	// ReleasePublicKeys are extra vendor release public keys (hex, comma-separated) the server accepts
	// agent releases for, in addition to the keys compiled in. Agents only trust their own compiled-in keys.
	ReleasePublicKeys string
}

// PlaceholderHostname is the host name the compose files ship with until the installer replaces it. It is a reserved
// example domain, so a real installation never uses it, and the server refuses to start with it.
const PlaceholderHostname = "change-me.example.com"

// Load reads configuration from the process environment.
func Load() (*Config, error) { return LoadFrom(os.LookupEnv) }

// LoadFrom reads configuration using the given lookup function (testable).
func LoadFrom(lookup func(string) (string, bool)) (*Config, error) {
	get := func(k, def string) string {
		if v, ok := lookup(k); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		return def
	}
	c := &Config{}
	var errs []error
	var err error

	c.DevMode, err = strconv.ParseBool(get("LIBREPATCH_DEV_MODE", "false"))
	if err != nil {
		errs = append(errs, fmt.Errorf("LIBREPATCH_DEV_MODE: %w", err))
	}
	secret := func(name string) (string, error) {
		if path := get(name+"_FILE", ""); path != "" {
			b, err := os.ReadFile(path) // #nosec G304 -- operator-supplied secret path
			if err != nil {
				return "", fmt.Errorf("%s_FILE: %w", name, err)
			}
			return strings.TrimSpace(string(b)), nil
		}
		if v := get(name, ""); v != "" {
			if !c.DevMode {
				return "", fmt.Errorf("%s must be provided via %s_FILE (Docker secret); plain env vars are only allowed with LIBREPATCH_DEV_MODE=true", name, name)
			}
			return v, nil
		}
		return "", nil
	}

	c.HTTPAddr = get("LIBREPATCH_HTTP_ADDR", ":8080")
	c.GatewayAddr = get("LIBREPATCH_GATEWAY_ADDR", ":8443")
	c.LogLevel = get("LIBREPATCH_LOG_LEVEL", "info")
	c.ContentDir = get("LIBREPATCH_CONTENT_DIR", "")
	if c.GitHubToken, err = secret("LIBREPATCH_GITHUB_TOKEN"); err != nil {
		errs = append(errs, err)
	}
	c.WingetSource = get("LIBREPATCH_WINGET_SOURCE", "github")
	if c.WingetIndexURL = strings.TrimSpace(get("LIBREPATCH_WINGET_INDEX_URL", "")); c.WingetIndexURL != "" {
		if u, perr := url.Parse(c.WingetIndexURL); perr != nil || u.Scheme != "https" || u.Host == "" {
			errs = append(errs, errors.New("LIBREPATCH_WINGET_INDEX_URL must be an https URL"))
		}
	}
	c.AgentReleaseDir = get("LIBREPATCH_AGENT_RELEASE_DIR", "/opt/librepatch/agent-release")
	c.AgentDownloads = get("LIBREPATCH_AGENT_DOWNLOADS", "github")
	if c.AgentDownloads != "github" && c.AgentDownloads != "off" {
		errs = append(errs, errors.New("LIBREPATCH_AGENT_DOWNLOADS must be github or off"))
	}
	if c.AgentDownloadBaseURL = strings.TrimRight(get("LIBREPATCH_AGENT_DOWNLOAD_BASE_URL", ""), "/"); c.AgentDownloadBaseURL != "" {
		if u, perr := url.Parse(c.AgentDownloadBaseURL); perr != nil || u.Host == "" || (u.Scheme != "https" && !(c.DevMode && u.Scheme == "http")) {
			errs = append(errs, errors.New("LIBREPATCH_AGENT_DOWNLOAD_BASE_URL must be an https URL"))
		}
	}
	c.ReleasePublicKeys = get("LIBREPATCH_RELEASE_PUBLIC_KEYS", "")
	if _, err := release.ParseKeys(c.ReleasePublicKeys); err != nil {
		errs = append(errs, fmt.Errorf("LIBREPATCH_RELEASE_PUBLIC_KEYS: %w", err))
	}
	if c.WingetSource != "github" && c.WingetSource != "off" {
		errs = append(errs, errors.New("LIBREPATCH_WINGET_SOURCE must be github or off"))
	}

	// The compose files only hand over the host name (and optional port settings); the full addresses are derived here, so
	// that one block of settings at the top of the compose file is all an install has to edit.
	hostname := get("LIBREPATCH_HOSTNAME", "")
	if hostname == PlaceholderHostname {
		errs = append(errs, errors.New("LIBREPATCH_HOSTNAME is still the placeholder "+PlaceholderHostname+": put the DNS name of this server in the settings block at the top of the compose file (or in deploy/.env)"))
	}
	pub := get("LIBREPATCH_PUBLIC_URL", "")
	if pub == "" && hostname != "" {
		pub = "https://" + hostname + get("LIBREPATCH_PUBLIC_PORT_SUFFIX", "")
	}
	if pub == "" {
		errs = append(errs, errors.New("LIBREPATCH_PUBLIC_URL (or LIBREPATCH_HOSTNAME) is required (e.g. https://librepatch.example.com)"))
	} else if u, perr := url.Parse(pub); perr != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		errs = append(errs, fmt.Errorf("LIBREPATCH_PUBLIC_URL %q is not a valid http(s) origin", pub))
	} else {
		if u.Scheme == "http" && !c.DevMode {
			errs = append(errs, errors.New("LIBREPATCH_PUBLIC_URL must be https unless LIBREPATCH_DEV_MODE=true"))
		}
		u.Path, u.RawQuery, u.Fragment = "", "", ""
		c.PublicURL = u
	}

	c.GatewayPublicAddr = get("LIBREPATCH_GATEWAY_PUBLIC_ADDR", "")
	if c.GatewayPublicAddr == "" && hostname != "" {
		c.GatewayPublicAddr = net.JoinHostPort(get("LIBREPATCH_GATEWAY_HOSTNAME", hostname), get("LIBREPATCH_GATEWAY_PORT", "8443"))
	}
	if c.GatewayPublicAddr == "" && c.PublicURL != nil {
		c.GatewayPublicAddr = net.JoinHostPort(c.PublicURL.Hostname(), "8443")
	}
	if c.GatewayPublicAddr != "" {
		if _, _, serr := net.SplitHostPort(c.GatewayPublicAddr); serr != nil {
			errs = append(errs, fmt.Errorf("LIBREPATCH_GATEWAY_PUBLIC_ADDR %q must be host:port", c.GatewayPublicAddr))
		}
	}
	for _, s := range strings.Split(get("LIBREPATCH_GATEWAY_SANS", ""), ",") {
		if s = strings.TrimSpace(s); s != "" {
			c.GatewaySANs = append(c.GatewaySANs, s)
		}
	}
	if host, _, serr := net.SplitHostPort(c.GatewayPublicAddr); serr == nil && host != "" {
		c.GatewaySANs = appendUnique(c.GatewaySANs, host)
	}

	// Commas or spaces separate the entries: the same list is handed to Caddy, which wants spaces.
	// LIBREPATCH_UPSTREAM_PROXIES (your own reverse proxy, as Caddy sees it) is trusted in addition to Caddy itself.
	trusted := get("LIBREPATCH_TRUSTED_PROXIES", "") + " " + get("LIBREPATCH_UPSTREAM_PROXIES", "")
	for _, s := range strings.FieldsFunc(trusted, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		p, perr := netip.ParsePrefix(s)
		if perr != nil {
			errs = append(errs, fmt.Errorf("LIBREPATCH_TRUSTED_PROXIES: %w", perr))
			continue
		}
		c.TrustedProxies = append(c.TrustedProxies, p)
	}

	if c.DatabaseURL, err = secret("LIBREPATCH_DATABASE_URL"); err != nil {
		errs = append(errs, err)
	} else if c.DatabaseURL == "" {
		errs = append(errs, errors.New("LIBREPATCH_DATABASE_URL_FILE is required"))
	}
	if c.MigrateDatabaseURL, err = secret("LIBREPATCH_MIGRATE_DATABASE_URL"); err != nil {
		errs = append(errs, err)
	}
	c.MigrateOnStart, err = strconv.ParseBool(get("LIBREPATCH_MIGRATE_ON_START", "true"))
	if err != nil {
		errs = append(errs, fmt.Errorf("LIBREPATCH_MIGRATE_ON_START: %w", err))
	}

	c.MasterKeyFile = get("LIBREPATCH_MASTER_KEY_FILE", "")
	autogen, aerr := strconv.ParseBool(get("LIBREPATCH_MASTER_KEY_AUTOGEN", "false"))
	if aerr != nil {
		errs = append(errs, fmt.Errorf("LIBREPATCH_MASTER_KEY_AUTOGEN: %w", aerr))
	}
	missingKeyFile := false
	if autogen && c.MasterKeyFile != "" {
		_, serr := os.Stat(c.MasterKeyFile)
		missingKeyFile = errors.Is(serr, fs.ErrNotExist)
	}
	mk := ""
	switch {
	case missingKeyFile:
		// First start of a stack that creates its own key: a fresh random key, written out by the migrate step.
		key := make([]byte, 32)
		if _, rerr := rand.Read(key); rerr != nil {
			errs = append(errs, fmt.Errorf("LIBREPATCH_MASTER_KEY_AUTOGEN: %w", rerr))
		}
		c.MasterKey, c.MasterKeyGenerated = key, true
	default:
		mk, err = secret("LIBREPATCH_MASTER_KEY")
	}
	if c.MasterKeyGenerated {
		// nothing to read
	} else if err != nil {
		errs = append(errs, err)
	} else if mk == "" {
		errs = append(errs, errors.New("LIBREPATCH_MASTER_KEY_FILE is required (32 random bytes, hex or base64)"))
	} else if c.MasterKey, err = decodeKey(mk); err != nil {
		errs = append(errs, fmt.Errorf("LIBREPATCH_MASTER_KEY: %w", err))
	}

	dur := func(name string, def time.Duration, min time.Duration) time.Duration {
		v := get(name, "")
		if v == "" {
			return def
		}
		d, perr := time.ParseDuration(v)
		if perr != nil || d < min {
			errs = append(errs, fmt.Errorf("%s: invalid duration %q (minimum %s)", name, v, min))
			return def
		}
		return d
	}
	count := func(name string, def int) int {
		v := get(name, "")
		if v == "" {
			return def
		}
		n, perr := strconv.Atoi(v)
		if perr != nil || n < 1 || n > 1_000_000 {
			errs = append(errs, fmt.Errorf("%s: %q is not a number between 1 and 1000000", name, v))
			return def
		}
		return n
	}
	// Short lifetimes are only for tests; the minimums keep production sane.
	minLife := 24 * time.Hour
	if c.DevMode {
		minLife = 10 * time.Second
	}
	c.DeviceCertLifetime = dur("LIBREPATCH_DEVICE_CERT_LIFETIME", 90*24*time.Hour, minLife)
	c.DeviceRenewGrace = dur("LIBREPATCH_DEVICE_RENEW_GRACE", 180*24*time.Hour, 0)
	c.EnrollPollInterval = dur("LIBREPATCH_ENROLL_POLL_INTERVAL", 60*time.Second, time.Second)
	c.EnrollRatePerIP = count("LIBREPATCH_ENROLL_RATE_PER_IP", DefaultEnrollRatePerIP)
	c.EnrollRatePerToken = count("LIBREPATCH_ENROLL_RATE_PER_TOKEN", DefaultEnrollRatePerToken)
	c.HeartbeatInterval = dur("LIBREPATCH_HEARTBEAT_INTERVAL", 5*time.Minute, time.Second)
	c.IgnoreIPAllowlist = os.Getenv("LIBREPATCH_IGNORE_IP_ALLOWLIST") == "true"
	c.SessionIdleTimeout = dur("LIBREPATCH_SESSION_IDLE_TIMEOUT", 30*time.Minute, time.Minute)
	c.SessionAbsTimeout = dur("LIBREPATCH_SESSION_ABSOLUTE_TIMEOUT", 12*time.Hour, 5*time.Minute)

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// SecureCookies reports whether cookies must carry the Secure attribute.
func (c *Config) SecureCookies() bool { return c.PublicURL.Scheme == "https" }

// Origin returns scheme://host[:port] of the public URL.
func (c *Config) Origin() string { return c.PublicURL.Scheme + "://" + c.PublicURL.Host }

func appendUnique(list []string, v string) []string {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return list
		}
	}
	return append(list, v)
}
