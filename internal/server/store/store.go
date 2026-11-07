// Package store owns database connectivity, migrations and transactions.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/auzring1/librepatch/gen/dbq"
)

// Open connects a pgx pool and verifies connectivity.
func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	cfg.MaxConns = 32
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.ConnConfig.RuntimeParams["application_name"] = "librepatch-server"
	// Defense in depth against runaway queries.
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "30000"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database ping: %w", err)
	}
	return pool, nil
}

// Migrate applies all pending migrations using the schema-owner connection.
// goose takes a Postgres advisory lock so concurrent servers cannot race.
func Migrate(ctx context.Context, url string, log *slog.Logger) error {
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		return fmt.Errorf("parse migration URL: %w", err)
	}
	sqldb := stdlib.OpenDB(*cfg)
	defer func() { _ = sqldb.Close() }()
	provider, err := goose.NewProvider(goose.DialectPostgres, sqldb, migrationsFS(),
		goose.WithSessionLocker(mustLocker()))
	if err != nil {
		return err
	}
	results, err := provider.Up(ctx)
	for _, r := range results {
		log.Info("migration applied", "version", r.Source.Version, "file", r.Source.Path, "duration", r.Duration)
	}
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// MigrateDown rolls the schema back to version (0 removes everything), running each
// migration's Down section newest first. It is an operator escape hatch: it drops data
// held by the rolled-back migrations, so take a backup first.
func MigrateDown(ctx context.Context, url string, version int64, log *slog.Logger) error {
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		return fmt.Errorf("parse migration URL: %w", err)
	}
	sqldb := stdlib.OpenDB(*cfg)
	defer func() { _ = sqldb.Close() }()
	provider, err := goose.NewProvider(goose.DialectPostgres, sqldb, migrationsFS(),
		goose.WithSessionLocker(mustLocker()))
	if err != nil {
		return err
	}
	results, err := provider.DownTo(ctx, version)
	for _, r := range results {
		log.Info("migration rolled back", "version", r.Source.Version, "file", r.Source.Path, "duration", r.Duration)
	}
	if err != nil {
		return fmt.Errorf("migrate down: %w", err)
	}
	return nil
}

// CheckLeastPrivilege warns when the runtime connection owns the schema.
func CheckLeastPrivilege(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) {
	var current, owner string
	err := pool.QueryRow(ctx, `SELECT current_user, COALESCE((SELECT tableowner FROM pg_tables WHERE schemaname='public' AND tablename='audit_log'), '')`).Scan(&current, &owner)
	if err != nil {
		log.Warn("could not check database privileges", "err", err)
		return
	}
	if current == owner {
		log.Warn("runtime database user owns the schema; use a separate least-privilege role (librepatch_app) in production",
			"user", current)
	}
}

// Tx runs fn in a transaction, committing on success.
func Tx(ctx context.Context, pool *pgxpool.Pool, fn func(tx pgx.Tx, q *dbq.Queries) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx, dbq.New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// IsNoRows reports whether err is "no rows".
func IsNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) }
