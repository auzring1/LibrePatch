package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func baseEnv() map[string]string {
	return map[string]string{
		"LIBREPATCH_DEV_MODE":     "true",
		"LIBREPATCH_PUBLIC_URL":   "http://localhost:8080",
		"LIBREPATCH_DATABASE_URL": "postgres://u:p@localhost/db",
		"LIBREPATCH_MASTER_KEY":   strings.Repeat("ab", 32),
	}
}

func load(env map[string]string) (*Config, error) {
	return LoadFrom(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
}

func TestEnrollRateLimitsDefaultAndOverride(t *testing.T) {
	c, err := load(baseEnv())
	if err != nil {
		t.Fatal(err)
	}
	if c.EnrollRatePerIP != 10 || c.EnrollRatePerToken != 60 {
		t.Fatalf("defaults changed: %d/%d (PROTOCOL §4.1 says 10 per IP and 60 per token per minute)", c.EnrollRatePerIP, c.EnrollRatePerToken)
	}
	env := baseEnv()
	env["LIBREPATCH_ENROLL_RATE_PER_IP"] = "500"
	env["LIBREPATCH_ENROLL_RATE_PER_TOKEN"] = "2000"
	c, err = load(env)
	if err != nil {
		t.Fatal(err)
	}
	if c.EnrollRatePerIP != 500 || c.EnrollRatePerToken != 2000 {
		t.Fatalf("override ignored: %d/%d", c.EnrollRatePerIP, c.EnrollRatePerToken)
	}
}

func TestEnrollRateLimitsRejectNonsense(t *testing.T) {
	for _, v := range []string{"0", "-5", "ten", "1000001", "1.5"} {
		env := baseEnv()
		env["LIBREPATCH_ENROLL_RATE_PER_IP"] = v
		if _, err := load(env); err == nil || !strings.Contains(err.Error(), "LIBREPATCH_ENROLL_RATE_PER_IP") {
			t.Errorf("%q accepted (err=%v)", v, err)
		}
	}
}

func TestTrustedProxiesAcceptCommasAndSpaces(t *testing.T) {
	env := baseEnv()
	env["LIBREPATCH_TRUSTED_PROXIES"] = "172.31.250.10/32,172.31.250.0/24 192.168.1.50/32"
	c, err := load(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.TrustedProxies) != 3 || c.TrustedProxies[2].String() != "192.168.1.50/32" {
		t.Fatalf("trusted proxies = %v", c.TrustedProxies)
	}
	env["LIBREPATCH_TRUSTED_PROXIES"] = "172.31.250.10/32 not-a-cidr"
	if _, err := load(env); err == nil || !strings.Contains(err.Error(), "LIBREPATCH_TRUSTED_PROXIES") {
		t.Fatalf("a bad entry must be refused, got %v", err)
	}
}

func TestMasterKeyAutogen(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "master_key")
	dbFile := filepath.Join(dir, "database_url")
	if err := os.WriteFile(dbFile, []byte("postgres://u:p@h/d"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"LIBREPATCH_PUBLIC_URL": "https://lp.example.com", "LIBREPATCH_DATABASE_URL_FILE": dbFile, "LIBREPATCH_MASTER_KEY_FILE": keyFile}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	// Without the switch a missing key file is an error, as before.
	if _, err := LoadFrom(lookup); err == nil {
		t.Fatal("a missing key file must fail without LIBREPATCH_MASTER_KEY_AUTOGEN")
	}
	// With it, the maintenance service gets a fresh key in memory that only its migrate step writes out.
	env["LIBREPATCH_MASTER_KEY_AUTOGEN"] = "true"
	c, err := LoadFrom(lookup)
	if err != nil || !c.MasterKeyGenerated || len(c.MasterKey) != 32 || c.MasterKeyFile != keyFile {
		t.Fatalf("autogen: %+v %v", c, err)
	}
	if _, serr := os.Stat(keyFile); serr == nil {
		t.Fatal("loading the configuration must not write the key")
	}
	// Once the file exists the stored key is used and nothing is generated.
	stored := strings.Repeat("ab", 32)
	if err := os.WriteFile(keyFile, []byte(stored+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	c, err = LoadFrom(lookup)
	if err != nil || c.MasterKeyGenerated || hex.EncodeToString(c.MasterKey) != stored {
		t.Fatalf("stored key: %+v %v", c, err)
	}
	env["LIBREPATCH_MASTER_KEY_AUTOGEN"] = "maybe"
	if _, err := LoadFrom(lookup); err == nil {
		t.Fatal("a malformed switch must be refused")
	}
}

func TestAddressesAreDerivedFromTheHostname(t *testing.T) {
	env := baseEnv()
	delete(env, "LIBREPATCH_PUBLIC_URL")
	env["LIBREPATCH_HOSTNAME"] = "patch.contoso.test"
	c, err := load(env)
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicURL.String() != "https://patch.contoso.test" || c.GatewayPublicAddr != "patch.contoso.test:8443" {
		t.Fatalf("defaults: %s, %s", c.PublicURL, c.GatewayPublicAddr)
	}
	env["LIBREPATCH_PUBLIC_PORT_SUFFIX"] = ":8444"
	env["LIBREPATCH_GATEWAY_PORT"] = "9443"
	env["LIBREPATCH_GATEWAY_HOSTNAME"] = "agents.contoso.test"
	c, err = load(env)
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicURL.String() != "https://patch.contoso.test:8444" || c.GatewayPublicAddr != "agents.contoso.test:9443" {
		t.Fatalf("with settings: %s, %s", c.PublicURL, c.GatewayPublicAddr)
	}
	// An explicit address still wins over the derived one.
	env["LIBREPATCH_PUBLIC_URL"] = "https://other.contoso.test"
	if c, err = load(env); err != nil || c.PublicURL.String() != "https://other.contoso.test" {
		t.Fatalf("explicit URL ignored: %v %v", c, err)
	}
}

func TestPlaceholderHostnameIsRefused(t *testing.T) {
	env := baseEnv()
	delete(env, "LIBREPATCH_PUBLIC_URL")
	env["LIBREPATCH_HOSTNAME"] = PlaceholderHostname
	if _, err := load(env); err == nil || !strings.Contains(err.Error(), "placeholder") {
		t.Fatalf("the shipped placeholder name was accepted (err=%v)", err)
	}
}

func TestUpstreamProxiesAreTrustedToo(t *testing.T) {
	env := baseEnv()
	env["LIBREPATCH_TRUSTED_PROXIES"] = "172.31.250.10/32"
	env["LIBREPATCH_UPSTREAM_PROXIES"] = "192.168.1.50/32"
	c, err := load(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.TrustedProxies) != 2 || c.TrustedProxies[1].String() != "192.168.1.50/32" {
		t.Fatalf("trusted proxies = %v", c.TrustedProxies)
	}
}

func TestAgentDownloadSettings(t *testing.T) {
	c, err := load(baseEnv())
	if err != nil || c.AgentDownloads != "github" || c.AgentDownloadBaseURL != "" {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	env := baseEnv()
	env["LIBREPATCH_AGENT_DOWNLOADS"] = "off"
	env["LIBREPATCH_AGENT_DOWNLOAD_BASE_URL"] = "https://mirror.contoso.test/releases/"
	if c, err = load(env); err != nil || c.AgentDownloads != "off" || c.AgentDownloadBaseURL != "https://mirror.contoso.test/releases" {
		t.Fatalf("explicit: %+v %v", c, err)
	}
	for k, v := range map[string]string{"LIBREPATCH_AGENT_DOWNLOADS": "maybe", "LIBREPATCH_AGENT_DOWNLOAD_BASE_URL": "http://mirror.contoso.test"} {
		env := baseEnv()
		env["LIBREPATCH_DEV_MODE"] = "false" // plain http is only for development
		env["LIBREPATCH_DATABASE_URL_FILE"] = ""
		env[k] = v
		if _, err := load(env); err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s=%q accepted (err=%v)", k, v, err)
		}
	}
}
