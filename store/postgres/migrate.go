package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"

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

	sql, err := migrationFiles.ReadFile("migrations/000001_initial.sql")
	if err != nil {
		return fmt.Errorf("postgres: read migration: %w", err)
	}
	if _, err := tx.Exec(ctx, string(sql)); err != nil {
		return fmt.Errorf("postgres: apply migration 000001_initial: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit migration: %w", err)
	}

	return nil
}
