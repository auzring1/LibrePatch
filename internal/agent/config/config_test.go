package config

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/shared/bundle"
)

func enrollment(t *testing.T) string {
	tok := make([]byte, 32)
	_, _ = rand.Read(tok)
	s, err := bundle.Bundle{V: 1, Gateway: "a.example.com:8443", RootPin: "sha256/" + base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Token: base64.RawURLEncoding.EncodeToString(tok), Org: uuid.NewString()}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFromBundleAndOverride(t *testing.T) {
	c, err := FromBundle(enrollment(t), "")
	if err != nil || c.Server != "a.example.com:8443" || c.EnrollmentToken == "" {
		t.Fatalf("%+v %v", c, err)
	}
	c, err = FromBundle(enrollment(t), "10.0.0.5:9443")
	if err != nil || c.Server != "10.0.0.5:9443" {
		t.Fatalf("override: %+v %v", c, err)
	}
	if _, err := FromBundle(enrollment(t), "no-port"); err == nil {
		t.Fatal("bad override accepted")
	}
	p := filepath.Join(t.TempDir(), "config.json")
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(p); err != nil || got.Server != c.Server {
		t.Fatalf("load: %+v %v", got, err)
	}
}

func TestParseAllowedJobs(t *testing.T) {
	got, err := ParseAllowedJobs(" wu_scan, inventory ,inventory")
	if err != nil || len(got) != 2 || got[0] != "inventory" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := ParseAllowedJobs("format_disk"); err == nil {
		t.Fatal("unknown job type accepted")
	}
}

// Scripts are on unless the computer was installed with --no-scripts (D150). A file written before that, with or without the
// old opt-in, therefore has scripts on after the agent is updated.
func TestAnOlderConfigFileHasScriptsOnAndOnlyNoScriptsTurnsThemOff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	for name, raw := range map[string]string{
		"installed without the opt-in": `{"server":"a.example.com:8443","root_pin":"sha256/x","org_id":"o"}`,
		"installed with the opt-in":    `{"server":"a.example.com:8443","root_pin":"sha256/x","org_id":"o","allow_scripts":true}`,
	} {
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.NoScripts {
			t.Errorf("%s: scripts must be on", name)
		}
	}
	off := &Config{Server: "a.example.com:8443", RootPin: "sha256/x", OrgID: "o", NoScripts: true}
	if err := Save(path, off); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil || !c.NoScripts {
		t.Fatalf("--no-scripts must survive a save and load: %v %+v", err, c)
	}
}
