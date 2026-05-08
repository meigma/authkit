package storetest

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/apikey"
	"github.com/meigma/authkit/oidc"
)

const (
	testProvider    = "oidc"
	testSubject     = "user-123"
	testDisplayName = "Ada Lovelace"
)

// Store is the complete storage surface exercised by Run.
type Store interface {
	authkit.PrincipalCreator
	authkit.IdentityLinker
	authkit.PrincipalResolver
	apikey.TokenStore
	oidc.ProviderTrustStore
}

// Run runs the shared storage behavior suite against newStore.
//
//nolint:funlen // Keeping one top-level suite makes cross-store coverage easy to audit.
func Run(t *testing.T, newStore func(t *testing.T) Store) {
	t.Helper()

	t.Run("create principal", func(t *testing.T) {
		store := newStore(t)

		tests := []struct {
			name string
			kind authkit.PrincipalKind
		}{
			{name: "creates user principal", kind: authkit.PrincipalKindUser},
			{name: "creates service principal", kind: authkit.PrincipalKindService},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
					Kind:        tt.kind,
					DisplayName: testDisplayName,
				})

				require.NoError(t, err)
				assert.NotEmpty(t, principal.ID)
				assert.Contains(t, principal.ID, "principal_")
				assert.Equal(t, tt.kind, principal.Kind)
				assert.Equal(t, testDisplayName, principal.DisplayName)
				assert.Nil(t, principal.Attributes)
			})
		}
	})

	t.Run("create principal rejects invalid kind", func(t *testing.T) {
		store := newStore(t)

		principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
			Kind:        authkit.PrincipalKind("team"),
			DisplayName: testDisplayName,
		})

		require.Error(t, err)
		assert.Empty(t, principal)
	})

	t.Run("principal attributes are copied", func(t *testing.T) {
		store := newStore(t)
		attrs := map[string]any{
			"role": "operator",
		}

		principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
			Kind:        authkit.PrincipalKindUser,
			DisplayName: testDisplayName,
			Attributes:  attrs,
		})
		require.NoError(t, err)

		attrs["role"] = "changed before resolve"
		principal.Attributes["role"] = "changed from returned principal"

		_, err = store.LinkIdentity(context.Background(), authkit.LinkIdentityRequest{
			Provider:    testProvider,
			Subject:     testSubject,
			PrincipalID: principal.ID,
		})
		require.NoError(t, err)

		resolved, err := store.ResolveIdentity(context.Background(), authkit.Identity{
			Provider: testProvider,
			Subject:  testSubject,
		})
		require.NoError(t, err)
		require.NotNil(t, resolved)
		assert.Equal(t, "operator", resolved.Attributes["role"])

		resolved.Attributes["role"] = "changed from resolved principal"
		resolvedAgain, err := store.ResolveIdentity(context.Background(), authkit.Identity{
			Provider: testProvider,
			Subject:  testSubject,
		})
		require.NoError(t, err)
		require.NotNil(t, resolvedAgain)
		assert.Equal(t, "operator", resolvedAgain.Attributes["role"])
	})

	t.Run("link identity", func(t *testing.T) {
		store := newStore(t)
		first := createPrincipal(t, store)
		second := createPrincipal(t, store)

		link, err := store.LinkIdentity(context.Background(), authkit.LinkIdentityRequest{
			Provider:    testProvider,
			Subject:     testSubject,
			PrincipalID: first.ID,
		})
		require.NoError(t, err)
		assert.Equal(t, authkit.ExternalIdentity{
			Provider:    testProvider,
			Subject:     testSubject,
			PrincipalID: first.ID,
		}, link)

		relinked, err := store.LinkIdentity(context.Background(), authkit.LinkIdentityRequest{
			Provider:    testProvider,
			Subject:     testSubject,
			PrincipalID: first.ID,
		})
		require.NoError(t, err)
		assert.Equal(t, link, relinked)

		conflicted, err := store.LinkIdentity(context.Background(), authkit.LinkIdentityRequest{
			Provider:    testProvider,
			Subject:     testSubject,
			PrincipalID: second.ID,
		})
		require.Error(t, err)
		assert.Empty(t, conflicted)
	})

	t.Run("link identity validates request", func(t *testing.T) {
		store := newStore(t)
		principal := createPrincipal(t, store)

		tests := []struct {
			name string
			req  authkit.LinkIdentityRequest
		}{
			{
				name: "missing provider",
				req: authkit.LinkIdentityRequest{
					Subject:     testSubject,
					PrincipalID: principal.ID,
				},
			},
			{
				name: "missing subject",
				req: authkit.LinkIdentityRequest{
					Provider:    testProvider,
					PrincipalID: principal.ID,
				},
			},
			{
				name: "missing principal ID",
				req: authkit.LinkIdentityRequest{
					Provider: testProvider,
					Subject:  testSubject,
				},
			},
			{
				name: "missing principal",
				req: authkit.LinkIdentityRequest{
					Provider:    testProvider,
					Subject:     testSubject,
					PrincipalID: "missing",
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				link, err := store.LinkIdentity(context.Background(), tt.req)

				require.Error(t, err)
				assert.Empty(t, link)
			})
		}
	})

	t.Run("resolve identity", func(t *testing.T) {
		store := newStore(t)
		principal := createPrincipal(t, store)

		_, err := store.LinkIdentity(context.Background(), authkit.LinkIdentityRequest{
			Provider:    testProvider,
			Subject:     testSubject,
			PrincipalID: principal.ID,
		})
		require.NoError(t, err)

		resolved, err := store.ResolveIdentity(context.Background(), authkit.Identity{
			Provider:     testProvider,
			Subject:      testSubject,
			CredentialID: "id-123",
			Claims: map[string]any{
				"ignored": true,
			},
		})

		require.NoError(t, err)
		require.NotNil(t, resolved)
		assert.Equal(t, principal, *resolved)
	})

	t.Run("resolve identity returns unresolved identity", func(t *testing.T) {
		store := newStore(t)

		tests := []struct {
			name     string
			identity authkit.Identity
		}{
			{
				name: "missing provider",
				identity: authkit.Identity{
					Subject: testSubject,
				},
			},
			{
				name: "missing subject",
				identity: authkit.Identity{
					Provider: testProvider,
				},
			},
			{
				name: "unlinked identity",
				identity: authkit.Identity{
					Provider: testProvider,
					Subject:  testSubject,
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				resolved, err := store.ResolveIdentity(context.Background(), tt.identity)

				require.ErrorIs(t, err, authkit.ErrUnresolvedIdentity)
				assert.Nil(t, resolved)
			})
		}
	})

	t.Run("trusted providers", func(t *testing.T) {
		store := newStore(t)
		provider := providerFixture()
		want := providerFixture()

		trusted, err := store.TrustProvider(context.Background(), provider)
		require.NoError(t, err)
		assert.Equal(t, want, trusted)

		provider.Audiences[0] = "changed before find"
		trusted.Audiences[0] = "changed from returned provider"
		trusted.SupportedSigningAlgorithms[0] = "ES256"

		found, err := store.FindProvider(context.Background(), want.Issuer)
		require.NoError(t, err)
		assert.Equal(t, want, found)

		found.Audiences[0] = "changed from found provider"
		found.SupportedSigningAlgorithms[0] = "ES256"
		foundAgain, err := store.FindProvider(context.Background(), want.Issuer)
		require.NoError(t, err)
		assert.Equal(t, want, foundAgain)
	})

	t.Run("trusted providers can be updated", func(t *testing.T) {
		store := newStore(t)
		provider := providerFixture()
		_, err := store.TrustProvider(context.Background(), provider)
		require.NoError(t, err)

		updated := oidc.Provider{
			Issuer:                     provider.Issuer,
			Audiences:                  []string{"updated-api"},
			JWKSURL:                    "https://issuer.example/updated-jwks.json",
			SupportedSigningAlgorithms: []string{"RS512"},
		}
		trusted, err := store.TrustProvider(context.Background(), updated)
		require.NoError(t, err)
		assert.Equal(t, updated, trusted)

		found, err := store.FindProvider(context.Background(), provider.Issuer)
		require.NoError(t, err)
		assert.Equal(t, updated, found)
	})

	t.Run("trusted providers missing behavior", func(t *testing.T) {
		store := newStore(t)

		found, err := store.FindProvider(context.Background(), "https://issuer.example")

		require.ErrorIs(t, err, oidc.ErrProviderNotFound)
		assert.Empty(t, found)
	})

	t.Run("trusted providers reject invalid configuration", func(t *testing.T) {
		store := newStore(t)
		invalid := providerFixture()
		invalid.Audiences = nil

		trusted, err := store.TrustProvider(context.Background(), invalid)
		require.Error(t, err)
		assert.Empty(t, trusted)

		found, err := store.FindProvider(context.Background(), invalid.Issuer)
		require.ErrorIs(t, err, oidc.ErrProviderNotFound)
		assert.Empty(t, found)
	})

	t.Run("returns context error", func(t *testing.T) {
		store := newStore(t)
		principal := createPrincipal(t, store)
		_, err := store.LinkIdentity(context.Background(), authkit.LinkIdentityRequest{
			Provider:    testProvider,
			Subject:     testSubject,
			PrincipalID: principal.ID,
		})
		require.NoError(t, err)
		token := tokenFixture(fixedStoreTime(), principal.ID)
		require.NoError(t, store.CreateToken(context.Background(), token))

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		tests := []struct {
			name string
			run  func() error
		}{
			{
				name: "create principal",
				run: func() error {
					_, runErr := store.CreatePrincipal(ctx, authkit.CreatePrincipalRequest{
						Kind: authkit.PrincipalKindUser,
					})

					return runErr
				},
			},
			{
				name: "link identity",
				run: func() error {
					_, runErr := store.LinkIdentity(ctx, authkit.LinkIdentityRequest{
						Provider:    "api-token",
						Subject:     "token-123",
						PrincipalID: principal.ID,
					})

					return runErr
				},
			},
			{
				name: "resolve identity",
				run: func() error {
					_, runErr := store.ResolveIdentity(ctx, authkit.Identity{
						Provider: testProvider,
						Subject:  testSubject,
					})

					return runErr
				},
			},
			{
				name: "create token",
				run: func() error {
					return store.CreateToken(ctx, tokenFixture(fixedStoreTime(), principal.ID))
				},
			},
			{
				name: "find token",
				run: func() error {
					_, runErr := store.FindToken(ctx, token.ID)

					return runErr
				},
			},
			{
				name: "update token last used",
				run: func() error {
					return store.UpdateTokenLastUsed(ctx, token.ID, fixedStoreTime())
				},
			},
			{
				name: "revoke token",
				run: func() error {
					return store.RevokeToken(ctx, token.ID, fixedStoreTime())
				},
			},
			{
				name: "trust provider",
				run: func() error {
					_, runErr := store.TrustProvider(ctx, providerFixture())

					return runErr
				},
			},
			{
				name: "find provider",
				run: func() error {
					_, runErr := store.FindProvider(ctx, "https://issuer.example")

					return runErr
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				require.ErrorIs(t, tt.run(), context.Canceled)
			})
		}
	})

	t.Run("token storage", func(t *testing.T) {
		store := newStore(t)
		principal := createPrincipal(t, store)
		now := fixedStoreTime()
		usedAt := now.Add(time.Hour)
		wantUsedAt := usedAt
		token := tokenFixture(now, principal.ID)
		token.LastUsedAt = &usedAt

		require.NoError(t, store.CreateToken(context.Background(), token))
		*token.LastUsedAt = now.Add(time.Minute)

		found, err := store.FindToken(context.Background(), token.ID)
		require.NoError(t, err)
		require.NotNil(t, found.LastUsedAt)
		assert.Equal(t, wantUsedAt, *found.LastUsedAt)
		assert.Equal(t, token.SecretHash, found.SecretHash)

		*found.LastUsedAt = now.Add(time.Minute)
		foundAgain, err := store.FindToken(context.Background(), token.ID)
		require.NoError(t, err)
		require.NotNil(t, foundAgain.LastUsedAt)
		assert.Equal(t, wantUsedAt, *foundAgain.LastUsedAt)
	})

	t.Run("token last used and revocation", func(t *testing.T) {
		store := newStore(t)
		principal := createPrincipal(t, store)
		now := fixedStoreTime()
		token := createToken(t, store, now, principal.ID)
		usedAt := now.Add(time.Hour)
		revokedAt := now.Add(time.Hour + time.Minute)

		require.NoError(t, store.UpdateTokenLastUsed(context.Background(), token.ID, usedAt))
		require.NoError(t, store.RevokeToken(context.Background(), token.ID, revokedAt))

		found, err := store.FindToken(context.Background(), token.ID)
		require.NoError(t, err)
		require.NotNil(t, found.LastUsedAt)
		require.NotNil(t, found.RevokedAt)
		assert.Equal(t, usedAt, *found.LastUsedAt)
		assert.Equal(t, revokedAt, *found.RevokedAt)

		*found.LastUsedAt = now
		*found.RevokedAt = now
		foundAgain, err := store.FindToken(context.Background(), token.ID)
		require.NoError(t, err)
		require.NotNil(t, foundAgain.LastUsedAt)
		require.NotNil(t, foundAgain.RevokedAt)
		assert.Equal(t, usedAt, *foundAgain.LastUsedAt)
		assert.Equal(t, revokedAt, *foundAgain.RevokedAt)
	})

	t.Run("token missing behavior", func(t *testing.T) {
		store := newStore(t)
		now := fixedStoreTime()

		found, err := store.FindToken(context.Background(), "missing")
		require.ErrorIs(t, err, apikey.ErrTokenNotFound)
		assert.Empty(t, found)

		require.ErrorIs(
			t,
			store.UpdateTokenLastUsed(context.Background(), "missing", now),
			apikey.ErrTokenNotFound,
		)
		require.ErrorIs(t, store.RevokeToken(context.Background(), "missing", now), apikey.ErrTokenNotFound)
	})

	t.Run("api token service integration", func(t *testing.T) {
		now := fixedStoreTime()
		store := newStore(t)
		service, err := apikey.NewService(store, apikey.WithClock(func() time.Time {
			return now
		}))
		require.NoError(t, err)
		principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
			Kind:        authkit.PrincipalKindService,
			DisplayName: "deploy service",
		})
		require.NoError(t, err)
		issued, err := service.IssueToken(context.Background(), apikey.IssueRequest{
			PrincipalID: principal.ID,
			Name:        "deploy token",
			ExpiresAt:   now.Add(time.Hour),
		})
		require.NoError(t, err)
		_, err = store.LinkIdentity(context.Background(), issued.IdentityLink)
		require.NoError(t, err)

		identity, err := service.VerifyToken(context.Background(), issued.Plaintext)
		require.NoError(t, err)
		require.NotNil(t, identity)
		resolved, err := store.ResolveIdentity(context.Background(), *identity)

		require.NoError(t, err)
		require.NotNil(t, resolved)
		assert.Equal(t, principal, *resolved)
	})
}

func createPrincipal(t *testing.T, store Store) authkit.Principal {
	t.Helper()

	principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindUser,
		DisplayName: testDisplayName,
		Attributes: map[string]any{
			"role": "operator",
		},
	})
	require.NoError(t, err)

	return principal
}

func providerFixture() oidc.Provider {
	return oidc.Provider{
		Issuer:                     "https://issuer.example",
		Audiences:                  []string{"notes-api"},
		JWKSURL:                    "https://issuer.example/.well-known/jwks.json",
		SupportedSigningAlgorithms: []string{"RS256"},
	}
}

func createToken(t *testing.T, store Store, now time.Time, principalID string) apikey.StoredToken {
	t.Helper()

	token := tokenFixture(now, principalID)
	require.NoError(t, store.CreateToken(context.Background(), token))

	return token
}

func tokenFixture(now time.Time, principalID string) apikey.StoredToken {
	return apikey.StoredToken{
		ID:          "token_1",
		PrincipalID: principalID,
		Name:        "deploy",
		SecretHash:  sha256.Sum256([]byte("secret")),
		ExpiresAt:   now.Add(time.Hour),
	}
}

func fixedStoreTime() time.Time {
	return time.Date(2026, time.May, 7, 18, 0, 0, 0, time.UTC)
}
