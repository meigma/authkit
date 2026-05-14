package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	migrationLockID int64 = 0x746573746b6974
	versionBase     int   = 10
	versionBits     int   = 64
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migrate applies testkit's PostgreSQL paste schema migrations.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if pool == nil {
		return errors.New("testkit postgres: pool is required")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("testkit postgres: begin migration: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	if _, execErr := tx.Exec(ctx, `select pg_advisory_xact_lock($1)`, migrationLockID); execErr != nil {
		return fmt.Errorf("testkit postgres: acquire migration lock: %w", execErr)
	}
	if _, execErr := tx.Exec(ctx, createMigrationTableSQL); execErr != nil {
		return fmt.Errorf("testkit postgres: create migration table: %w", execErr)
	}

	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("testkit postgres: read migrations: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if err := applyMigration(ctx, tx, entry.Name()); err != nil {
			return err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("testkit postgres: commit migration: %w", err)
	}

	return nil
}

const createMigrationTableSQL = `
create table if not exists testkit_schema_migrations (
	version bigint primary key,
	name text not null,
	applied_at timestamptz not null default now()
)`

type migrationTx interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func applyMigration(ctx context.Context, tx migrationTx, name string) error {
	version, err := migrationVersion(name)
	if err != nil {
		return err
	}

	var applied bool
	if queryErr := tx.QueryRow(
		ctx,
		`select exists (select 1 from testkit_schema_migrations where version = $1)`,
		version,
	).Scan(&applied); queryErr != nil {
		return fmt.Errorf("testkit postgres: check migration %s: %w", name, queryErr)
	}
	if applied {
		return nil
	}

	sql, err := migrationFiles.ReadFile("migrations/" + name)
	if err != nil {
		return fmt.Errorf("testkit postgres: read migration %s: %w", name, err)
	}
	if _, err := tx.Exec(ctx, string(sql)); err != nil {
		return fmt.Errorf("testkit postgres: apply migration %s: %w", name, err)
	}
	if _, err := tx.Exec(
		ctx,
		`insert into testkit_schema_migrations (version, name) values ($1, $2)`,
		version,
		name,
	); err != nil {
		return fmt.Errorf("testkit postgres: record migration %s: %w", name, err)
	}

	return nil
}

func migrationVersion(name string) (int64, error) {
	prefix, _, found := strings.Cut(name, "_")
	if !found {
		return 0, fmt.Errorf("testkit postgres: migration %q has no version prefix", name)
	}

	version, err := strconv.ParseInt(prefix, versionBase, versionBits)
	if err != nil {
		return 0, fmt.Errorf("testkit postgres: parse migration version %q: %w", name, err)
	}

	return version, nil
}
