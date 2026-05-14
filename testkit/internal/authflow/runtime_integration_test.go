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

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/httpauth"
	"github.com/meigma/authkit/oidc"
	authpostgres "github.com/meigma/authkit/store/postgres"
	testkitpostgres "github.com/meigma/authkit/testkit/internal/store/postgres"
)

const postgresReadyOccurrences = 2

func TestRuntimeUsesPostgresAuthStore(t *testing.T) {
	ctx := context.Background()
	store := newPostgresAuthStore(t)
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

func TestRuntimeUsesPostgresAuthStoreForOIDCExchange(t *testing.T) {
	ctx := context.Background()
	store := newPostgresAuthStore(t)
	issuer := newTestIssuer(t)
	provider := issuer.provider()
	provider.ForwardedClaims = []authkit.ClaimPath{{"email"}, {"name"}}
	_, err := store.TrustProvider(ctx, provider)
	require.NoError(t, err)
	runtime, err := NewRuntime(
		ctx,
		store,
		WithClock(fixedTime),
		WithOIDCOptions(oidc.WithHTTPClient(issuer.server.Client())),
	)
	require.NoError(t, err)
	token := issuer.sign(t, oidcTokenRequest{
		subject:   "user-123",
		audiences: []string{testAudience},
		expiresAt: fixedTime().Add(time.Hour),
		claims: map[string]any{
			"email": "ada@example.test",
			"name":  "Ada Lovelace",
		},
	})

	result, err := runtime.ExchangeOIDCToken(ctx, token)
	require.NoError(t, err)

	assert.Equal(t, "Ada Lovelace", result.Principal.DisplayName)
	assert.Equal(t, "ada@example.test", result.Principal.Attributes["email"])
	assert.Equal(t, result.Principal.ID, result.AccessToken.PrincipalID)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", bearer(result.AccessToken.Plaintext))
	runtime.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		principal, ok := httpauth.PrincipalFromContext(req.Context())
		assert.True(t, ok)
		if ok {
			assert.Equal(t, result.Principal.ID, principal.ID)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusNoContent, recorder.Code)
}

func newPostgresAuthStore(t *testing.T) *authpostgres.Store {
	t.Helper()

	ctx := context.Background()
	pool := newPostgresPool(t)
	require.NoError(t, testkitpostgres.Migrate(ctx, pool))
	require.NoError(t, authpostgres.Migrate(ctx, pool))
	require.NoError(t, authpostgres.Migrate(ctx, pool))

	store, err := authpostgres.NewStore(pool)
	require.NoError(t, err)

	return store
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
