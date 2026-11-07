// Command librepatch-server is the LibrePatch management server.
//
//	librepatch-server [serve]            run the server (default)
//	librepatch-server migrate [--down-to N]  apply database migrations and exit (or roll back to version N)
//	librepatch-server maintenance        like migrate, then stay running idle (the compose "maintenance" service)
//	librepatch-server backup --out F|-   write an age-encrypted backup (database + content files)
//	librepatch-server backup --verify F  check a backup without touching any database
//	librepatch-server restore --in F|-   restore a backup into an empty database
//	librepatch-server show-master-key    print the master key and its id (needs read access to the key file)
//	librepatch-server set-master-key [--force]   read a saved master key from standard input and store it as the key file
//	librepatch-server healthcheck        exit 0 if the local server is healthy (Docker HEALTHCHECK)
//	librepatch-server admin reset-mfa --email E   force MFA re-enrollment for a user
//	librepatch-server admin unlock --email E      clear a login lockout
//	librepatch-server admin verify-audit          verify the audit-log hash chain
//	librepatch-server version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/app"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/backup"
	"github.com/auzring1/librepatch/internal/server/config"
	"github.com/auzring1/librepatch/internal/server/masterkey"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/shared/version"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "migrate":
		err = migrate(os.Args[2:])
	case "backup":
		err = backup.CommandBackup(os.Args[2:], config.Load)
	case "restore":
		err = backup.CommandRestore(os.Args[2:], config.Load)
	case "maintenance":
		err = maintenance(os.Args[2:])
	case "show-master-key":
		err = showMasterKey()
	case "set-master-key":
		err = setMasterKey(os.Args[2:])
	case "healthcheck":
		err = healthcheck()
	case "admin":
		err = admin(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("librepatch-server %s (%s)\n", version.Version, version.Commit)
	default:
		err = fmt.Errorf("unknown command %q (serve|migrate|maintenance|backup|restore|show-master-key|set-master-key|healthcheck|admin|version)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func logger(level string) *slog.Logger {
	var l slog.Level
	_ = l.UnmarshalText([]byte(level))
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

func serve() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := logger(cfg.LogLevel)
	log.Info("starting librepatch-server", "version", version.Version, "commit", version.Commit, "dev_mode", cfg.DevMode)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, err := app.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer a.Close()
	return a.Run(ctx)
}

// migrate applies pending migrations; "--down-to N" instead rolls the schema back to
// version N (destructive for the rolled-back tables; take a backup first).
func migrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	downTo := fs.Int64("down-to", -1, "roll the schema back to this migration version (0 = empty); destructive")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	url := cfg.MigrateDatabaseURL
	if url == "" {
		url = cfg.DatabaseURL
	}
	if *downTo >= 0 {
		return store.MigrateDown(context.Background(), url, *downTo, logger(cfg.LogLevel))
	}
	log := logger(cfg.LogLevel)
	ctx := context.Background()
	if err := store.Migrate(ctx, url, log); err != nil {
		return err
	}
	if cfg.MasterKeyGenerated {
		// First start of a stack that creates its own master key (LIBREPATCH_MASTER_KEY_AUTOGEN, decision D109).
		conn, err := pgx.Connect(ctx, url)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close(ctx) }()
		if err := masterkey.Provision(ctx, conn, cfg.MasterKeyFile, cfg.MasterKey); err != nil {
			return err
		}
		id, _ := masterkey.ID(cfg.MasterKey)
		log.Info("created a new master key; the console asks the first administrator to save it", "key_id", id, "file", cfg.MasterKeyFile)
	}
	return nil
}

// maintenance is the command of the compose "maintenance" service (decision D111): it does what "migrate" does, then
// stays running and idle, so that graphical container managers show every container as
// up instead of one that "exited". It reports readiness through LIBREPATCH_HEALTH_FILE, which the container's health check
// reads; the server waits for that to be healthy. Backup and restore still run as separate one-off containers.
func maintenance(args []string) error {
	if err := migrate(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return idleUntilStopped(ctx, os.Getenv("LIBREPATCH_HEALTH_FILE"))
}

// idleUntilStopped marks the service ready by creating readyFile (if given), then waits until ctx is done. The file is
// removed again on the way out.
func idleUntilStopped(ctx context.Context, readyFile string) error {
	if readyFile != "" {
		if err := os.WriteFile(readyFile, []byte("ready\n"), 0o600); err != nil {
			return fmt.Errorf("write ready file: %w", err)
		}
		defer func() { _ = os.Remove(readyFile) }()
	}
	<-ctx.Done()
	return nil
}

// showMasterKey prints the master key for someone who has access to the server's files.
func showMasterKey() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.MasterKeyGenerated {
		return errors.New("there is no master key yet: it is created the first time the stack starts")
	}
	id, _ := masterkey.ID(cfg.MasterKey)
	fmt.Printf("Master key: %s\nKey id:     %s\n", masterkey.Grouped(cfg.MasterKey), id)
	return nil
}

// setMasterKey stores a key that was saved earlier, for example when moving to a new machine or after a restore.
func setMasterKey(args []string) error {
	fs := flag.NewFlagSet("set-master-key", flag.ContinueOnError)
	force := fs.Bool("force", false, "replace an existing key file (only if you are sure the old one is wrong)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.MasterKeyFile == "" {
		return errors.New("LIBREPATCH_MASTER_KEY_FILE is not set")
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<16))
	if err != nil {
		return err
	}
	key, err := masterkey.Parse(string(data))
	if err != nil {
		return err
	}
	if !cfg.MasterKeyGenerated { // the file exists
		if !*force {
			return errors.New("a master key file already exists; use --force to replace it (a wrong key makes the stored data unreadable)")
		}
		if err := os.Remove(cfg.MasterKeyFile); err != nil {
			return err
		}
	}
	if err := masterkey.WriteNew(cfg.MasterKeyFile, key); err != nil {
		return err
	}
	id, _ := masterkey.ID(key)
	fmt.Printf("Master key stored. Key id: %s\n", id)
	return nil
}

func healthcheck() error {
	// The maintenance service has no HTTP listener: it is healthy once its ready file exists.
	if f := os.Getenv("LIBREPATCH_HEALTH_FILE"); f != "" {
		if _, err := os.Stat(f); err != nil {
			return fmt.Errorf("not ready: %w", err)
		}
		return nil
	}
	addr := os.Getenv("LIBREPATCH_HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := &http.Client{Timeout: 3 * time.Second}
	// #nosec G704 -- probes this container's own listener from operator configuration
	resp, err := c.Get("http://" + addr + "/readyz") // NOSONAR: the container probes its own loopback listener
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unhealthy: HTTP %d", resp.StatusCode)
	}
	return nil
}

func admin(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: admin reset-mfa|unlock --email E | admin verify-audit")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	pool, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	q := dbq.New(pool)
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	email := fs.String("email", "", "user email")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "verify-audit":
		res, err := audit.Verify(ctx, q)
		if err != nil {
			return err
		}
		if res.BrokenAt != 0 {
			return fmt.Errorf("audit chain BROKEN at entry %d (%d entries verified before it)", res.BrokenAt, res.Checked)
		}
		fmt.Printf("audit chain intact: %d entries verified\n", res.Checked)
		return nil
	case "reset-mfa", "unlock":
		if *email == "" {
			return errors.New("--email is required")
		}
		u, err := q.GetUserByEmail(ctx, strings.ToLower(strings.TrimSpace(*email)))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("no user with email %q", *email)
		} else if err != nil {
			return err
		}
		return store.Tx(ctx, pool, func(tx pgx.Tx, q *dbq.Queries) error {
			if args[0] == "reset-mfa" {
				if err := q.DeleteTOTP(ctx, u.ID); err != nil {
					return err
				}
				if err := q.DeleteRecoveryCodes(ctx, u.ID); err != nil {
					return err
				}
				if err := q.DeleteUserSessions(ctx, u.ID); err != nil {
					return err
				}
			} else if err := q.SetUserLoginFailure(ctx, dbq.SetUserLoginFailureParams{ID: u.ID}); err != nil {
				return err
			}
			if _, err := audit.Write(ctx, tx, audit.Entry{OrgID: &u.OrgID, ActorType: audit.ActorSystem, ActorID: "cli",
				Action: "admin." + strings.ReplaceAll(args[0], "-", "_"), TargetType: "user", TargetIDs: []string{u.ID.String()},
				Outcome: audit.Success}, time.Now()); err != nil {
				return err
			}
			fmt.Printf("%s done for %s\n", args[0], u.Email)
			return nil
		})
	default:
		return fmt.Errorf("unknown admin command %q", args[0])
	}
}
