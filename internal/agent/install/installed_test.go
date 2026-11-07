package install

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstalledIn(t *testing.T) {
	yes := func() bool { return true }
	no := func() bool { return false }

	empty := t.TempDir()
	withCfg := t.TempDir()
	if err := os.WriteFile(filepath.Join(withCfg, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgIsDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(cfgIsDir, "config.json"), 0o700); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		dir  string
		svc  func() bool
		want bool
	}{
		{"service and config", withCfg, yes, true},
		{"service without config (broken install: let install report it)", empty, yes, false},
		{"config without service (leftover data)", withCfg, no, false},
		{"nothing", empty, no, false},
		{"config.json is a directory", cfgIsDir, yes, false},
		{"missing data dir", filepath.Join(empty, "nope"), yes, false},
	}
	for _, c := range cases {
		if got := installedIn(c.dir, c.svc); got != c.want {
			t.Errorf("%s: installedIn = %v, want %v", c.name, got, c.want)
		}
	}
}
