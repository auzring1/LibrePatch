// Package deployscripts tests the shell scripts under deploy/ that no Go code covers.
package deployscripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type pgSandbox struct {
	t                    *testing.T
	pg, app, owner, data string
	bin                  string
}

// newPgSandbox puts a stand-in "docker-entrypoint.sh" on PATH that records its arguments, so the wrapper can be run
// without PostgreSQL or Docker.
func newPgSandbox(t *testing.T) *pgSandbox {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	root := t.TempDir()
	s := &pgSandbox{t: t, pg: filepath.Join(root, "pg"), app: filepath.Join(root, "app"), owner: filepath.Join(root, "owner"),
		data: filepath.Join(root, "data"), bin: filepath.Join(root, "bin")}
	for _, d := range []string{s.data, s.bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fake := "#!/bin/sh\necho \"$@\" > \"" + filepath.Join(root, "args") + "\"\n"
	if err := os.WriteFile(filepath.Join(s.bin, "docker-entrypoint.sh"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *pgSandbox) run() (string, error) {
	_, f, _, _ := runtime.Caller(0)
	script := filepath.Join(filepath.Dir(f), "..", "..", "deploy", "postgres", "entrypoint.sh")
	cmd := exec.Command("sh", script, "postgres", "-c", "x=1")
	cmd.Env = append(os.Environ(), "PATH="+s.bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"LIBREPATCH_PG_SECRETS="+s.pg, "LIBREPATCH_APP_SECRETS="+s.app, "LIBREPATCH_OWNER_SECRETS="+s.owner,
		"PGDATA="+s.data, "POSTGRES_DB=librepatch", "LIBREPATCH_DB_HOST=postgres")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestFirstStartCreatesPasswordsAndConnectionStrings(t *testing.T) {
	s := newPgSandbox(t)
	if out, err := s.run(); err != nil {
		t.Fatalf("first start: %v\n%s", err, out)
	}
	seen := map[string]string{}
	for _, n := range []string{"admin", "owner", "app"} {
		p := filepath.Join(s.pg, "postgres_"+n+"_password")
		pw := read(t, p)
		if len(pw) != 48 || strings.Trim(pw, "0123456789abcdef") != "" {
			t.Errorf("%s password %q is not 48 hex characters", n, pw)
		}
		if info, _ := os.Stat(p); info.Mode().Perm() != 0o600 {
			t.Errorf("%s password has mode %v, want 0600", n, info.Mode().Perm())
		}
		seen[n] = pw
	}
	if seen["admin"] == seen["owner"] || seen["owner"] == seen["app"] || seen["admin"] == seen["app"] {
		t.Error("the three passwords must differ")
	}
	if got, want := read(t, filepath.Join(s.app, "database_url")), "postgres://librepatch_app:"+seen["app"]+"@postgres:5432/librepatch?sslmode=disable"; got != want {
		t.Errorf("database_url = %q, want %q", got, want)
	}
	if got, want := read(t, filepath.Join(s.owner, "migrate_database_url")), "postgres://librepatch_owner:"+seen["owner"]+"@postgres:5432/librepatch?sslmode=disable"; got != want {
		t.Errorf("migrate_database_url = %q, want %q", got, want)
	}
	// The unprivileged server user must be able to reach its connection string.
	for _, p := range []string{filepath.Join(s.app, "database_url"), filepath.Join(s.owner, "migrate_database_url")} {
		if info, _ := os.Stat(p); info.Mode().Perm()&0o044 != 0o044 {
			t.Errorf("%s is not world-readable: %v", p, info.Mode().Perm())
		}
		if info, _ := os.Stat(filepath.Dir(p)); info.Mode().Perm()&0o005 != 0o005 {
			t.Errorf("%s cannot be entered by other users: %v", filepath.Dir(p), info.Mode().Perm())
		}
	}
	// Control is handed to the official entrypoint with the original arguments.
	if args := strings.TrimSpace(read(t, filepath.Join(filepath.Dir(s.bin), "args"))); args != "postgres -c x=1" {
		t.Errorf("docker-entrypoint.sh got %q", args)
	}
}

func TestLaterStartsKeepThePasswords(t *testing.T) {
	s := newPgSandbox(t)
	if out, err := s.run(); err != nil {
		t.Fatalf("first start: %v\n%s", err, out)
	}
	before := read(t, filepath.Join(s.pg, "postgres_app_password"))
	// A database now exists; the saved passwords must be reused, and a lost connection string is rewritten.
	if err := os.WriteFile(filepath.Join(s.data, "PG_VERSION"), []byte("16\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(s.app, "database_url")); err != nil {
		t.Fatal(err)
	}
	if out, err := s.run(); err != nil {
		t.Fatalf("second start: %v\n%s", err, out)
	}
	if after := read(t, filepath.Join(s.pg, "postgres_app_password")); after != before {
		t.Error("the app password changed on a later start")
	}
	if !strings.Contains(read(t, filepath.Join(s.app, "database_url")), before) {
		t.Error("database_url was not rewritten from the saved password")
	}
}

func TestRefusesToInventPasswordsForAnExistingDatabase(t *testing.T) {
	s := newPgSandbox(t)
	if err := os.WriteFile(filepath.Join(s.data, "PG_VERSION"), []byte("16\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := s.run()
	if err == nil {
		t.Fatal("expected a failure: a new password would not open the existing database")
	}
	if !strings.Contains(out, "already exists") {
		t.Errorf("the message should explain the problem:\n%s", out)
	}
	if _, statErr := os.Stat(filepath.Join(s.pg, "postgres_app_password")); statErr == nil {
		t.Error("a password was created for an existing database")
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(s.bin), "args")); statErr == nil {
		t.Error("PostgreSQL must not be started after the refusal")
	}
}
