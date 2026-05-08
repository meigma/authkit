package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5/pgxpool"
)

const migrationLockID int64 = 0x617574686b6974

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migrate applies authkit's PostgreSQL schema migrations.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if pool == nil {
		return errors.New("postgres: pool is required")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin migration: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	if _, execErr := tx.Exec(ctx, "select pg_advisory_xact_lock($1)", migrationLockID); execErr != nil {
		return fmt.Errorf("postgres: acquire migration lock: %w", execErr)
	}

	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("postgres: read migrations: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		sql, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("postgres: read migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("postgres: apply migration %s: %w", name, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit migration: %w", err)
	}

	return nil
}
