//go:build integration

package authflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/meigma/authkit/httpauth"
	authpostgres "github.com/meigma/authkit/store/postgres"
	testkitpostgres "github.com/meigma/authkit/testkit/internal/store/postgres"
)

const postgresReadyOccurrences = 2

func TestRuntimeUsesPostgresAuthStore(t *testing.T) {
	ctx := context.Background()
	pool := newPostgresPool(t)
	require.NoError(t, testkitpostgres.Migrate(ctx, pool))
	require.NoError(t, authpostgres.Migrate(ctx, pool))
	require.NoError(t, authpostgres.Migrate(ctx, pool))

	store, err := authpostgres.NewStore(pool)
	require.NoError(t, err)
	runtime, err := NewRuntime(ctx, store, WithClock(fixedTime))
	require.NoError(t, err)

	result, err := runtime.ExchangeAPIToken(ctx, runtime.SeedAPIToken)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", bearer(result.AccessToken.Plaintext))
	runtime.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		principal, ok := httpauth.PrincipalFromContext(req.Context())
		assert.True(t, ok)
		if ok {
			assert.Equal(t, runtime.Principal.ID, principal.ID)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusNoContent, recorder.Code)
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
