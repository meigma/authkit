package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/meigma/authkit/testkit/internal/paste"
)

const uniqueViolation = "23505"

// Store persists testkit pastes in PostgreSQL.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore constructs a PostgreSQL paste store around pool.
func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, errors.New("testkit postgres: pool is required")
	}

	return &Store{pool: pool}, nil
}

// Create stores a new paste.
func (s *Store) Create(ctx context.Context, created paste.Paste) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	_, err := s.pool.Exec(
		ctx,
		`insert into testkit_pastes (id, title, body, syntax, created_at)
		values ($1, $2, $3, $4, $5)`,
		created.ID,
		created.Title,
		created.Body,
		created.Syntax,
		created.CreatedAt.UTC(),
	)
	if err != nil {
		if isPostgresCode(err, uniqueViolation) {
			return paste.ErrDuplicatePasteID
		}

		return fmt.Errorf("testkit postgres: create paste: %w", err)
	}

	return nil
}

// Find returns a paste by ID.
func (s *Store) Find(ctx context.Context, id string) (paste.Paste, error) {
	if err := ctx.Err(); err != nil {
		return paste.Paste{}, err
	}

	found, err := scanPaste(s.pool.QueryRow(
		ctx,
		`select id, title, body, syntax, created_at
		from testkit_pastes
		where id = $1`,
		id,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return paste.Paste{}, paste.ErrPasteNotFound
	}
	if err != nil {
		return paste.Paste{}, err
	}

	return found, nil
}

// ListRecent returns recent pastes, newest first, up to limit.
func (s *Store) ListRecent(ctx context.Context, limit int) ([]paste.Paste, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return []paste.Paste{}, nil
	}

	rows, err := s.pool.Query(
		ctx,
		`select id, title, body, syntax, created_at
		from testkit_pastes
		order by created_at desc, id asc
		limit $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("testkit postgres: list recent pastes: %w", err)
	}
	defer rows.Close()

	var pastes []paste.Paste
	for rows.Next() {
		found, err := scanPaste(rows)
		if err != nil {
			return nil, err
		}
		pastes = append(pastes, found)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("testkit postgres: read recent pastes: %w", err)
	}

	return pastes, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanPaste(row scanner) (paste.Paste, error) {
	var found paste.Paste
	if err := row.Scan(
		&found.ID,
		&found.Title,
		&found.Body,
		&found.Syntax,
		&found.CreatedAt,
	); err != nil {
		return paste.Paste{}, err
	}
	found.CreatedAt = found.CreatedAt.UTC()

	return found, nil
}

func isPostgresCode(err error, code string) bool {
	var pgErr *pgconn.PgError

	return errors.As(err, &pgErr) && pgErr.Code == code
}
