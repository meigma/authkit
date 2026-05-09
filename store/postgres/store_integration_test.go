//go:build integration

package postgres

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/internal/storetest"
)

func TestSharedStoreBehavior(t *testing.T) {
	ctx := context.Background()
	pool := newPostgresPool(t)
	require.NoError(t, Migrate(ctx, pool))

	storetest.Run(t, func(t *testing.T) storetest.Store {
		t.Helper()
		resetStore(t, pool)

		store, err := NewStore(pool)
		require.NoError(t, err)

		return store
	})
}

func TestProvisionIdentityConcurrentCallsLeaveOnePrincipal(t *testing.T) {
	ctx := context.Background()
	pool := newPostgresPool(t)
	require.NoError(t, Migrate(ctx, pool))
	store, err := NewStore(pool)
	require.NoError(t, err)

	start := make(chan struct{})
	errs := make(chan error, 12)
	var wg sync.WaitGroup
	for range cap(errs) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, runErr := store.ProvisionIdentity(ctx, authkit.ProvisionIdentityRequest{
				Identity: authkit.Identity{
					Provider: "oidc",
					Subject:  "user-123",
				},
				Principal: authkit.CreatePrincipalRequest{
					Kind:        authkit.PrincipalKindUser,
					DisplayName: "Ada Lovelace",
				},
			})
			errs <- runErr
		}()
	}

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}

	var principals int
	err = pool.QueryRow(ctx, `select count(*) from authkit_principals`).Scan(&principals)
	require.NoError(t, err)
	assert.Equal(t, 1, principals)

	var links int
	err = pool.QueryRow(ctx, `select count(*) from authkit_external_identities`).Scan(&links)
	require.NoError(t, err)
	assert.Equal(t, 1, links)
}

func TestMigrateCreatesSchema(t *testing.T) {
	ctx := context.Background()
	pool := newPostgresPool(t)

	require.NoError(t, Migrate(ctx, pool))
	require.NoError(t, Migrate(ctx, pool))

	for _, table := range []string{
		"authkit_schema_migrations",
		"authkit_principals",
		"authkit_external_identities",
		"authkit_api_tokens",
		"authkit_oidc_providers",
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

	var migrationRows int
	err := pool.QueryRow(ctx, `select count(*) from authkit_schema_migrations where version in (1, 2)`).
		Scan(&migrationRows)
	require.NoError(t, err)
	assert.Equal(t, 2, migrationRows)
}

func TestMigrateConcurrentCalls(t *testing.T) {
	ctx := context.Background()
	pool := newPostgresPool(t)
	errs := make(chan error, 5)
	var wg sync.WaitGroup

	for i := 0; i < cap(errs); i++ {
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

	var migrationRows int
	err := pool.QueryRow(ctx, `select count(*) from authkit_schema_migrations where version in (1, 2)`).
		Scan(&migrationRows)
	require.NoError(t, err)
	assert.Equal(t, 2, migrationRows)
}

func newPostgresPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	ctx := context.Background()
	container, err := tcpostgres.Run(
		ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("authkit"),
		tcpostgres.WithUsername("authkit"),
		tcpostgres.WithPassword("authkit"),
		testcontainers.WithAdditionalWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
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

	_, err := pool.Exec(
		context.Background(),
		`truncate table
			authkit_oidc_providers,
			authkit_api_tokens,
			authkit_external_identities,
			authkit_principals
		restart identity cascade`,
	)
	require.NoError(t, err, fmt.Sprintf("reset %T", pool))
}
