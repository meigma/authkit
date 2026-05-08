package memory

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

func TestStoreSatisfiesAuthkitContracts(t *testing.T) {
	var _ authkit.PrincipalCreator = (*Store)(nil)
	var _ authkit.IdentityLinker = (*Store)(nil)
	var _ authkit.PrincipalResolver = (*Store)(nil)
	var _ apikey.TokenStore = (*Store)(nil)
	var _ oidc.ProviderSource = (*Store)(nil)
	var _ oidc.ProviderTrustStore = (*Store)(nil)

	require.NotNil(t, NewStore())
}

func TestStoreCreatePrincipal(t *testing.T) {
	store := NewStore()

	tests := []struct {
		name   string
		kind   authkit.PrincipalKind
		wantID string
	}{
		{
			name:   "creates user principal",
			kind:   authkit.PrincipalKindUser,
			wantID: "principal_1",
		},
		{
			name:   "creates service principal",
			kind:   authkit.PrincipalKindService,
			wantID: "principal_2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
				Kind:        tt.kind,
				DisplayName: testDisplayName,
			})

			require.NoError(t, err)
			assert.Equal(t, tt.wantID, principal.ID)
			assert.Equal(t, tt.kind, principal.Kind)
			assert.Equal(t, testDisplayName, principal.DisplayName)
			assert.Nil(t, principal.Attributes)
		})
	}
}

func TestStoreCreatePrincipalRejectsInvalidKind(t *testing.T) {
	store := NewStore()

	principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKind("team"),
		DisplayName: testDisplayName,
	})

	require.Error(t, err)
	assert.Empty(t, principal)
}

func TestStoreCopiesPrincipalAttributes(t *testing.T) {
	store := NewStore()
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
}

func TestStoreLinkIdentity(t *testing.T) {
	store := NewStore()
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
}

func TestStoreLinkIdentityValidatesRequest(t *testing.T) {
	store := NewStore()
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
}

func TestStoreResolveIdentity(t *testing.T) {
	store := NewStore()
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
		CredentialID: "credential-123",
		Claims: map[string]any{
			"ignored": true,
		},
	})

	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, principal, *resolved)
}

func TestStoreResolveIdentityReturnsUnresolvedIdentity(t *testing.T) {
	store := NewStore()

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
}

func TestStoreResolveIdentityReturnsUnresolvedIdentityForDanglingLink(t *testing.T) {
	store := NewStore()
	store.mu.Lock()
	store.links[identityKey{
		provider: testProvider,
		subject:  testSubject,
	}] = authkit.ExternalIdentity{
		Provider:    testProvider,
		Subject:     testSubject,
		PrincipalID: "missing",
	}
	store.mu.Unlock()

	resolved, err := store.ResolveIdentity(context.Background(), authkit.Identity{
		Provider: testProvider,
		Subject:  testSubject,
	})

	require.ErrorIs(t, err, authkit.ErrUnresolvedIdentity)
	assert.Nil(t, resolved)
}

func TestStoreReturnsContextError(t *testing.T) {
	store := NewStore()
	principal := createPrincipal(t, store)
	_, err := store.LinkIdentity(context.Background(), authkit.LinkIdentityRequest{
		Provider:    testProvider,
		Subject:     testSubject,
		PrincipalID: principal.ID,
	})
	require.NoError(t, err)

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorIs(t, tt.run(), context.Canceled)
		})
	}
}

func createPrincipal(t *testing.T, store *Store) authkit.Principal {
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

func TestStoreTokenStorage(t *testing.T) {
	store := NewStore()
	now := fixedStoreTime()
	usedAt := now.Add(time.Hour)
	wantUsedAt := usedAt
	token := apikey.StoredToken{
		ID:          "token_1",
		PrincipalID: testProvider,
		Name:        "deploy",
		SecretHash:  sha256.Sum256([]byte("secret")),
		ExpiresAt:   now.Add(time.Hour),
		LastUsedAt:  &usedAt,
	}

	require.NoError(t, store.CreateToken(context.Background(), token))
	*token.LastUsedAt = now.Add(time.Minute)

	found, err := store.FindToken(context.Background(), token.ID)
	require.NoError(t, err)
	require.NotNil(t, found.LastUsedAt)
	assert.Equal(t, wantUsedAt, *found.LastUsedAt)

	*found.LastUsedAt = now.Add(time.Minute)
	foundAgain, err := store.FindToken(context.Background(), token.ID)
	require.NoError(t, err)
	require.NotNil(t, foundAgain.LastUsedAt)
	assert.Equal(t, wantUsedAt, *foundAgain.LastUsedAt)
}

func TestStoreTokenLastUsedAndRevocation(t *testing.T) {
	store := NewStore()
	now := fixedStoreTime()
	token := createToken(t, store, now)
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
}

func TestStoreTokenMissingBehavior(t *testing.T) {
	store := NewStore()
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
}

func TestStoreTokenContextCancellation(t *testing.T) {
	store := NewStore()
	now := fixedStoreTime()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.ErrorIs(t, store.CreateToken(ctx, tokenFixture(now)), context.Canceled)
	_, err := store.FindToken(ctx, "token_1")
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, store.UpdateTokenLastUsed(ctx, "token_1", now), context.Canceled)
	require.ErrorIs(t, store.RevokeToken(ctx, "token_1", now), context.Canceled)
}

func createToken(t *testing.T, store *Store, now time.Time) apikey.StoredToken {
	t.Helper()

	token := tokenFixture(now)
	require.NoError(t, store.CreateToken(context.Background(), token))

	return token
}

func tokenFixture(now time.Time) apikey.StoredToken {
	return apikey.StoredToken{
		ID:          "token_1",
		PrincipalID: "principal_1",
		Name:        "deploy",
		SecretHash:  sha256.Sum256([]byte("secret")),
		ExpiresAt:   now.Add(time.Hour),
	}
}

func fixedStoreTime() time.Time {
	return time.Date(2026, time.May, 7, 18, 0, 0, 0, time.UTC)
}
