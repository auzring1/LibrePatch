package backup

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/auzring1/librepatch/db"
)

var migrationFileRE = regexp.MustCompile(`^(\d+)_.+\.sql$`)

// migrationVersions returns the newest embedded migration and the set of all of them.
func migrationVersions() (latest int64, all map[int64]bool, err error) {
	sub, err := fs.Sub(db.Migrations, "migrations")
	if err != nil {
		return 0, nil, err
	}
	names, err := fs.Glob(sub, "*.sql")
	if err != nil {
		return 0, nil, err
	}
	all = map[int64]bool{}
	for _, n := range names {
		m := migrationFileRE.FindStringSubmatch(n)
		if m == nil {
			continue
		}
		v, _ := strconv.ParseInt(m[1], 10, 64)
		all[v] = true
		latest = max(latest, v)
	}
	return latest, all, nil
}

// migrate applies the embedded goose migrations with the schema-owner
// connection: up to version (or all of them when version is 0).
func migrate(ctx context.Context, url string, version int64, log *slog.Logger) error {
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		return fmt.Errorf("parse database URL: %w", err)
	}
	sqldb := stdlib.OpenDB(*cfg)
	defer func() { _ = sqldb.Close() }()
	return migrateDB(ctx, sqldb, version, log)
}

func migrateDB(ctx context.Context, sqldb *sql.DB, version int64, log *slog.Logger) error {
	sub, err := fs.Sub(db.Migrations, "migrations")
	if err != nil {
		return err
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return err
	}
	p, err := goose.NewProvider(goose.DialectPostgres, sqldb, sub, goose.WithSessionLocker(locker))
	if err != nil {
		return err
	}
	var results []*goose.MigrationResult
	if version > 0 {
		results, err = p.UpTo(ctx, version)
	} else {
		results, err = p.Up(ctx)
	}
	for _, r := range results {
		log.Info("migration applied", "version", r.Source.Version, "file", r.Source.Path)
	}
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}
