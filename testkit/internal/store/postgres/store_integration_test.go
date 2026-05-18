//go:build integration

package postgres

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/meigma/authkit/testkit/internal/paste"
	"github.com/meigma/authkit/testkit/internal/store/storetest"
)

const (
	concurrentMigrationCalls = 5
	expectedMigrationRows    = 2
	postgresReadyOccurrences = 2
)

func TestSharedStoreBehavior(t *testing.T) {
	ctx := context.Background()
	pool := newPostgresPool(t)
	require.NoError(t, Migrate(ctx, pool))

	storetest.Run(t, func(t *testing.T) paste.Repository {
		t.Helper()
		resetStore(t, pool)

		store, err := NewStore(pool)
		require.NoError(t, err)

		return store
	})
}

func TestMigrateCreatesSchema(t *testing.T) {
	ctx := context.Background()
	pool := newPostgresPool(t)

	require.NoError(t, Migrate(ctx, pool))
	require.NoError(t, Migrate(ctx, pool))

	for _, table := range []string{
		"testkit_schema_migrations",
		"testkit_pastes",
	} {
		t.Run(table, func(t *testing.T) {
			var exists bool
			err := pool.QueryRow(
				ctx,
				`select exists (
					select 1 from information_schema.tables
					where table_schema = 'public' and table_name = $1
				)`,
				table,
			).Scan(&exists)

			require.NoError(t, err)
			assert.True(t, exists)
		})
	}

	assertMigrationRows(t, pool)
}

func TestMigrateConcurrentCalls(t *testing.T) {
	ctx := context.Background()
	pool := newPostgresPool(t)
	errs := make(chan error, concurrentMigrationCalls)
	var wg sync.WaitGroup

	for range cap(errs) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- Migrate(ctx, pool)
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
	assertMigrationRows(t, pool)
}

func newPostgresPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	ctx := context.Background()
	container, err := tcpostgres.Run(
		ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("testkit"),
		tcpostgres.WithUsername("testkit"),
		tcpostgres.WithPassword("testkit"),
		testcontainers.WithAdditionalWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(postgresReadyOccurrences).
				WithStartupTimeout(time.Minute),
		),
	)
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, container)

	connectionString, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	pool, err := pgxpool.New(ctx, connectionString)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	return pool
}

func resetStore(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	_, err := pool.Exec(context.Background(), `truncate table testkit_pastes`)
	require.NoError(t, err)
}

func assertMigrationRows(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	var migrationRows int
	err := pool.QueryRow(
		context.Background(),
		`select count(*) from testkit_schema_migrations where version in (1, 2)`,
	).Scan(&migrationRows)
	require.NoError(t, err)
	assert.Equal(t, expectedMigrationRows, migrationRows)
}
