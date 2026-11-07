package backup

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"filippo.io/age"

	"github.com/auzring1/librepatch/internal/server/config"
)

// scryptWorkFactor lets tests lower age's default scrypt cost (0 = default).
var scryptWorkFactor = 0

// Env is what the command line functions need from the process.
type Env struct {
	LoadConfig func() (*config.Config, error)
	Getenv     func(string) string
	Stdin      io.Reader
	Stdout     io.Writer // only machine-readable results: for `backup --out -` it carries the archive and nothing else
	Stderr     io.Writer // logs and messages
}

// OSEnv is the real process environment.
func OSEnv(load func() (*config.Config, error)) Env {
	return Env{LoadConfig: load, Getenv: os.Getenv, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
}

// CommandBackup is the entry point for `librepatch-server backup`.
func CommandBackup(args []string, load func() (*config.Config, error)) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return RunBackup(ctx, args, OSEnv(load))
}

// CommandRestore is the entry point for `librepatch-server restore`.
func CommandRestore(args []string, load func() (*config.Config, error)) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return RunRestore(ctx, args, OSEnv(load))
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

const backupUsage = `usage:
  librepatch-server backup --out FILE|-  (--recipient age1... [--recipient ...] | --recipient-file F | --passphrase-file F)
  librepatch-server backup --verify FILE|-  (--identity-file KEY | --passphrase-file F)

The passphrase file can also be named by LIBREPATCH_BACKUP_PASSPHRASE_FILE. With --out - the encrypted
archive goes to standard output and nothing else does (logs go to standard error).
`

func newLogger(env Env) *slog.Logger {
	return slog.New(slog.NewTextHandler(env.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func passphraseFile(flagValue string, env Env) string {
	if flagValue != "" {
		return flagValue
	}
	return strings.TrimSpace(env.Getenv("LIBREPATCH_BACKUP_PASSPHRASE_FILE"))
}

func identitiesFor(identityFile, passFile string, env Env) ([]age.Identity, error) {
	switch {
	case identityFile != "" && passFile != "":
		return nil, errors.New("use either --identity-file or --passphrase-file, not both")
	case identityFile != "":
		return IdentitiesFromFile(identityFile)
	case passFile != "":
		p, err := ReadPassphraseFile(passFile, 1)
		if err != nil {
			return nil, err
		}
		id, err := PassphraseIdentity(p)
		if err != nil {
			return nil, err
		}
		return []age.Identity{id}, nil
	}
	return nil, errors.New("--identity-file (age secret key) or --passphrase-file is required")
}

// RunBackup implements `backup` and `backup --verify`.
func RunBackup(ctx context.Context, args []string, env Env) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.Usage = func() { _, _ = fmt.Fprint(env.Stderr, backupUsage) }
	var recips, recipFiles stringList
	out := fs.String("out", "", "output file, or - for standard output")
	fs.Var(&recips, "recipient", "age public key to encrypt to (repeatable)")
	fs.Var(&recipFiles, "recipient-file", "file with age public keys, one per line (repeatable)")
	passFlag := fs.String("passphrase-file", "", "file holding a passphrase (scrypt mode)")
	verify := fs.String("verify", "", "verify this archive (path or -) instead of creating one")
	identityFile := fs.String("identity-file", "", "age secret key file (with --verify)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	passFile := passphraseFile(*passFlag, env)

	if *verify != "" {
		ids, err := identitiesFor(*identityFile, passFile, env)
		if err != nil {
			return err
		}
		m, err := Verify(ctx, FileSource(*verify, env.Stdin), ids)
		if err != nil {
			return fmt.Errorf("backup does NOT verify: %w", err)
		}
		printSummary(env.Stdout, "backup verified", m)
		return nil
	}

	if *out == "" {
		_, _ = fmt.Fprint(env.Stderr, backupUsage)
		return errors.New("--out is required")
	}
	if *identityFile != "" {
		return errors.New("--identity-file is only used with --verify (backups are encrypted to public keys)")
	}
	var recipients []age.Recipient
	for _, r := range recips {
		rc, err := ParseRecipient(r)
		if err != nil {
			return err
		}
		recipients = append(recipients, rc)
	}
	for _, f := range recipFiles {
		rs, err := RecipientsFromFile(f)
		if err != nil {
			return err
		}
		recipients = append(recipients, rs...)
	}
	switch {
	case len(recipients) > 0 && passFile != "":
		return errors.New("use recipients or a passphrase, not both (age cannot mix them)")
	case len(recipients) == 0 && passFile != "":
		p, err := ReadPassphraseFile(passFile, MinPassphraseLen)
		if err != nil {
			return err
		}
		r, err := PassphraseRecipient(p, scryptWorkFactor)
		if err != nil {
			return err
		}
		recipients = []age.Recipient{r}
	case len(recipients) == 0:
		return ErrNoRecipient
	}

	cfg, err := env.LoadConfig()
	if err != nil {
		return err
	}
	url := cfg.MigrateDatabaseURL
	if url == "" {
		url = cfg.DatabaseURL
	}
	log := newLogger(env)
	var m *Manifest
	err = writeOut(*out, env.Stdout, func(w io.Writer) error {
		var err error
		m, err = Backup(ctx, BackupOptions{DatabaseURL: url, ContentDir: cfg.ContentDir, Out: w, Recipients: recipients, Log: log})
		return err
	})
	if err != nil {
		return err
	}
	if *out != "-" {
		log.Info("backup written", "file", *out)
	}
	printSummary(env.Stderr, "backup created", m)
	return nil
}

// writeOut gives fn a destination: standard output, or a 0600 temp file in
// the target directory that is renamed into place only after a clean finish.
func writeOut(out string, stdout io.Writer, fn func(io.Writer) error) error {
	if out == "-" {
		return fn(stdout)
	}
	if st, err := os.Stat(out); err == nil && st.IsDir() {
		return fmt.Errorf("--out %s is a directory", out)
	}
	dir, base := filepath.Split(out)
	if dir == "" {
		dir = "."
	}
	f, err := os.CreateTemp(dir, "."+base+".tmp-*") // mode 0600
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if err := fn(f); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, out); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- directory of the operator-chosen --out; fsync makes the rename durable (best effort)
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

const restoreUsage = `usage:
  librepatch-server restore --in FILE|-  (--identity-file KEY | --passphrase-file F)
                         [--force --wipe] [--skip-content] [--skip-kek-check]

Restores into the database named by LIBREPATCH_MIGRATE_DATABASE_URL (or LIBREPATCH_DATABASE_URL), which must be empty.
Stop the server first. --force --wipe DROPS everything in the public schema before restoring.
`

// RunRestore implements `restore`.
func RunRestore(ctx context.Context, args []string, env Env) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.Usage = func() { _, _ = fmt.Fprint(env.Stderr, restoreUsage) }
	in := fs.String("in", "", "backup file, or - for standard input")
	identityFile := fs.String("identity-file", "", "age secret key file")
	passFlag := fs.String("passphrase-file", "", "file holding the passphrase the backup was made with")
	force := fs.Bool("force", false, "allow replacing a database that already holds data (needs --wipe)")
	wipe := fs.Bool("wipe", false, "DROP all objects in the public schema before restoring")
	skipContent := fs.Bool("skip-content", false, "restore the database only, not the content files")
	skipKEK := fs.Bool("skip-kek-check", false, "do not check LIBREPATCH_MASTER_KEY against the CA keys in the backup")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if *in == "" {
		_, _ = fmt.Fprint(env.Stderr, restoreUsage)
		return errors.New("--in is required")
	}
	ids, err := identitiesFor(*identityFile, passphraseFile(*passFlag, env), env)
	if err != nil {
		return err
	}
	cfg, err := env.LoadConfig()
	if err != nil {
		return err
	}
	url := cfg.MigrateDatabaseURL
	if url == "" {
		url = cfg.DatabaseURL
	}
	res, err := Restore(ctx, RestoreOptions{
		DatabaseURL: url, ContentDir: cfg.ContentDir, Source: FileSource(*in, env.Stdin), Identities: ids,
		Force: *force, Wipe: *wipe, SkipContent: *skipContent, MasterKey: cfg.MasterKey, SkipKEKCheck: *skipKEK,
		Log: newLogger(env),
	})
	if res != nil && res.Manifest != nil {
		_, _ = fmt.Fprintf(env.Stdout, "restored backup of %s (schema %d) into schema %d: %d tables, %d content files, %d audit entries verified\n",
			res.Manifest.CreatedAt.Format("2006-01-02 15:04:05Z"), res.Manifest.SchemaVersion, res.SchemaVersion,
			len(res.Manifest.Tables), res.ContentFiles, res.AuditEntries)
	}
	return err
}

func printSummary(w io.Writer, title string, m *Manifest) {
	var rows int64
	for _, n := range m.RowCounts {
		rows += n
	}
	_, _ = fmt.Fprintf(w, "%s\n  created:         %s\n  app version:     %s (%s)\n  schema version:  %d\n  tables:          %d (%d rows)\n  content files:   %d (%d bytes)\n  members checked: %d\n",
		title, m.CreatedAt.Format("2006-01-02 15:04:05Z"), m.AppVersion, m.AppCommit, m.SchemaVersion,
		len(m.Tables), rows, m.Content.Files, m.Content.Bytes, len(m.Members))
	for _, n := range m.Notes {
		_, _ = fmt.Fprintf(w, "  note: %s\n", n)
	}
}
