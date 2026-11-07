package backup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/auzring1/librepatch/internal/server/config"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

type cliEnv struct {
	Env
	out, errOut *bytes.Buffer
}

func newCLIEnv(url, contentDir string, key []byte, stdin io.Reader, vars map[string]string) *cliEnv {
	e := &cliEnv{out: &bytes.Buffer{}, errOut: &bytes.Buffer{}}
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	e.Env = Env{
		LoadConfig: func() (*config.Config, error) {
			return &config.Config{MigrateDatabaseURL: url, DatabaseURL: "postgres://app-role-unused", ContentDir: contentDir, MasterKey: key}, nil
		},
		Getenv: func(k string) string { return vars[k] },
		Stdin:  stdin, Stdout: e.out, Stderr: e.errOut,
	}
	return e
}

func fastScrypt(t *testing.T) {
	old := scryptWorkFactor
	scryptWorkFactor = 10
	t.Cleanup(func() { scryptWorkFactor = old })
}

func TestCLIPassphraseMode(t *testing.T) {
	fastScrypt(t)
	ctx := context.Background()
	src := pgtest.New(t)
	key := randKey()
	populate(t, src.OwnerURL, key, false)
	dir := t.TempDir()
	pf := writeFile(t, dir, "pass", "a long enough passphrase\n")
	out := filepath.Join(dir, "backups", "b.age")
	if err := os.Mkdir(filepath.Dir(out), 0o700); err != nil {
		t.Fatal(err)
	}

	e := newCLIEnv(src.OwnerURL, "", key, nil, nil)
	if err := RunBackup(ctx, []string{"--out", out, "--passphrase-file", pf}, e.Env); err != nil {
		t.Fatalf("backup: %v\n%s", err, e.errOut)
	}
	if e.out.Len() != 0 {
		t.Fatalf("file mode must not print to stdout: %q", e.out)
	}
	st, err := os.Stat(out)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("output file: %v %v", st, err)
	}
	if ents, _ := os.ReadDir(filepath.Dir(out)); len(ents) != 1 {
		t.Fatalf("temp file left behind: %v", ents)
	}
	raw, _ := os.ReadFile(out)
	if !bytes.HasPrefix(raw, []byte("age-encryption.org/v1\n-> scrypt ")) {
		t.Fatalf("not an scrypt age file: %q", raw[:40])
	}
	if bytes.Contains(raw, []byte("HOST")) || bytes.Contains(raw, []byte("organizations")) {
		t.Fatal("archive contains plaintext")
	}

	// verify, using the environment variable for the passphrase file
	v := newCLIEnv(src.OwnerURL, "", key, nil, map[string]string{"LIBREPATCH_BACKUP_PASSPHRASE_FILE": pf})
	if err := RunBackup(ctx, []string{"--verify", out}, v.Env); err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, want := range []string{"backup verified", "schema version:", "tables:", "NOT part of this backup"} {
		if !strings.Contains(v.out.String(), want) {
			t.Errorf("verify output lacks %q:\n%s", want, v.out)
		}
	}
	// wrong passphrase
	bad := writeFile(t, dir, "bad", "another long passphrase")
	w := newCLIEnv(src.OwnerURL, "", key, nil, nil)
	if err := RunBackup(ctx, []string{"--verify", out, "--passphrase-file", bad}, w.Env); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong passphrase: %v", err)
	}

	// restore with the passphrase
	dst := newEmptyDB(t)
	r := newCLIEnv(dst, "", key, nil, nil)
	if err := RunRestore(ctx, []string{"--in", out, "--passphrase-file", pf}, r.Env); err != nil {
		t.Fatalf("restore: %v\n%s", err, r.errOut)
	}
	if !strings.Contains(r.out.String(), "7 audit entries verified") {
		t.Fatalf("restore output: %s", r.out)
	}
	if !reflect.DeepEqual(tableDigests(t, connectT(t, src.OwnerURL), 7), tableDigests(t, connectT(t, dst), 7)) {
		t.Fatal("tables differ after CLI restore")
	}
	// restoring a second time is refused
	if err := RunRestore(ctx, []string{"--in", out, "--passphrase-file", pf}, newCLIEnv(dst, "", key, nil, nil).Env); !errors.Is(err, ErrTargetNotEmpty) {
		t.Fatalf("second restore: %v", err)
	}
}

func TestCLIRefusesUnencryptedAndBadInput(t *testing.T) {
	fastScrypt(t)
	ctx := context.Background()
	dir := t.TempDir()
	out := filepath.Join(dir, "x.age")
	e := newCLIEnv("postgres://127.0.0.1:1/none", "", randKey(), nil, nil)

	if err := RunBackup(ctx, []string{"--out", out}, e.Env); !errors.Is(err, ErrNoRecipient) {
		t.Fatalf("no recipient: %v", err)
	}
	short := writeFile(t, dir, "short", "tooshort")
	if err := RunBackup(ctx, []string{"--out", out, "--passphrase-file", short}, e.Env); err == nil || !strings.Contains(err.Error(), "shorter than") {
		t.Fatalf("short passphrase: %v", err)
	}
	pf := writeFile(t, dir, "pass", "a long enough passphrase")
	_, rcp := genKey(t)
	if err := RunBackup(ctx, []string{"--out", out, "--passphrase-file", pf, "--recipient", rcp.(*age.X25519Recipient).String()}, e.Env); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("recipient and passphrase: %v", err)
	}
	for _, arg := range []string{"not-a-key", "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"} {
		err := RunBackup(ctx, []string{"--out", out, "--recipient", arg}, e.Env)
		if err == nil || strings.Contains(err.Error(), "QQQQQ") {
			t.Fatalf("bad recipient %q: %v", arg, err)
		}
	}
	// A passphrase on the command line is not a thing.
	if err := RunBackup(ctx, []string{"--out", out, "--passphrase", "hunter2hunter2"}, e.Env); err == nil {
		t.Fatal("--passphrase must not exist")
	}
	if err := RunBackup(ctx, []string{"--recipient", rcp.(*age.X25519Recipient).String()}, e.Env); err == nil || !strings.Contains(err.Error(), "--out") {
		t.Fatalf("missing --out: %v", err)
	}
	// An unreachable database leaves neither a file nor a temp file, nor bytes on stdout.
	if err := RunBackup(ctx, []string{"--out", out, "--recipient", rcp.(*age.X25519Recipient).String()}, e.Env); err == nil {
		t.Fatal("backup against a dead database succeeded")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 { // short, pass
		t.Fatalf("files left behind: %v", ents)
	}
	if err := RunBackup(ctx, []string{"--out", "-", "--recipient", rcp.(*age.X25519Recipient).String()}, e.Env); err == nil || e.out.Len() != 0 {
		t.Fatalf("stdout must stay empty on early failure: %v %d", err, e.out.Len())
	}
	if err := RunRestore(ctx, []string{"--in", out}, e.Env); err == nil || !strings.Contains(err.Error(), "identity-file") {
		t.Fatalf("restore without key: %v", err)
	}
}

func TestCLIStdoutAndStdin(t *testing.T) {
	ctx := context.Background()
	src := pgtest.New(t)
	key := randKey()
	populate(t, src.OwnerURL, key, false)
	id, rcp := genKey(t)
	dir := t.TempDir()
	// two recipients from a file with comments, plus one on the command line
	id2, rcp2 := genKey(t)
	rf := writeFile(t, dir, "recipients.txt", "# ops\n"+rcp.(*age.X25519Recipient).String()+"\n\n"+rcp2.(*age.X25519Recipient).String()+"\n")
	id3, rcp3 := genKey(t)

	e := newCLIEnv(src.OwnerURL, "", key, nil, nil)
	if err := RunBackup(ctx, []string{"--out", "-", "--recipient-file", rf, "--recipient", rcp3.(*age.X25519Recipient).String()}, e.Env); err != nil {
		t.Fatalf("backup: %v\n%s", err, e.errOut)
	}
	// stdout is the archive and only the archive.
	if !bytes.HasPrefix(e.out.Bytes(), []byte("age-encryption.org/v1\n")) {
		t.Fatalf("stdout does not start with the age header: %q", e.out.Bytes()[:30])
	}
	if !strings.Contains(e.errOut.String(), "backup complete") {
		t.Fatalf("logs must go to stderr: %q", e.errOut)
	}
	for _, id := range []*age.X25519Identity{id, id2, id3} {
		if _, err := Verify(ctx, bytesSource(e.out.Bytes(), true), []age.Identity{id}); err != nil {
			t.Fatalf("every recipient must be able to read it: %v", err)
		}
	}
	// restore straight from standard input with an identity file
	kf := writeFile(t, dir, "key.txt", "# created for the test\n"+id2.String()+"\n")
	dst := newEmptyDB(t)
	r := newCLIEnv(dst, "", key, bytes.NewReader(e.out.Bytes()), nil)
	if err := RunRestore(ctx, []string{"--in", "-", "--identity-file", kf}, r.Env); err != nil {
		t.Fatalf("restore from stdin: %v\n%s", err, r.errOut)
	}
	if !reflect.DeepEqual(tableDigests(t, connectT(t, src.OwnerURL), 7), tableDigests(t, connectT(t, dst), 7)) {
		t.Fatal("tables differ after restore from stdin")
	}
	// verify from stdin too
	v := newCLIEnv(dst, "", key, bytes.NewReader(e.out.Bytes()), nil)
	if err := RunBackup(ctx, []string{"--verify", "-", "--identity-file", kf}, v.Env); err != nil {
		t.Fatal(err)
	}
}
