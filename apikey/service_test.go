package apikey_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/apikey"
	"github.com/meigma/authkit/store/memory"
)

const (
	testPrincipalID = "principal_1"
	testTokenName   = "deploy token"
	tokenParts      = 3
)

func TestServiceIssueToken(t *testing.T) {
	now := fixedTime()
	expiresAt := now.Add(time.Hour)
	service, store := newService(t, now)

	issued, err := service.IssueToken(context.Background(), apikey.IssueRequest{
		PrincipalID: testPrincipalID,
		Name:        testTokenName,
		ExpiresAt:   expiresAt,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, issued.ID)
	assert.Equal(t, expiresAt, issued.ExpiresAt)
	assert.Equal(t, authkit.LinkIdentityRequest{
		Provider:    apikey.Provider,
		Subject:     issued.ID,
		PrincipalID: testPrincipalID,
	}, issued.IdentityLink)
	require.True(t, strings.HasPrefix(issued.Plaintext, "ak_"+issued.ID+"_"))
	require.Len(t, strings.Split(issued.Plaintext, "_"), tokenParts)

	stored, err := store.FindToken(context.Background(), issued.ID)
	require.NoError(t, err)
	assert.Equal(t, testPrincipalID, stored.PrincipalID)
	assert.Equal(t, testTokenName, stored.Name)
	assert.Equal(t, expiresAt, stored.ExpiresAt)
	assert.NotEqual(t, [sha256.Size]byte{}, stored.SecretHash)
	assert.Nil(t, stored.LastUsedAt)
	assert.Nil(t, stored.RevokedAt)
}

func TestServiceIssueTokenValidatesRequest(t *testing.T) {
	now := fixedTime()
	service, _ := newService(t, now)

	tests := []struct {
		name string
		req  apikey.IssueRequest
	}{
		{
			name: "missing principal ID",
			req: apikey.IssueRequest{
				ExpiresAt: now.Add(time.Hour),
			},
		},
		{
			name: "expired",
			req: apikey.IssueRequest{
				PrincipalID: testPrincipalID,
				ExpiresAt:   now,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issued, err := service.IssueToken(context.Background(), tt.req)

			require.Error(t, err)
			assert.Empty(t, issued)
		})
	}
}

func TestServiceVerifyAPIToken(t *testing.T) {
	now := fixedTime()
	service, store := newService(t, now)
	issued := issueToken(t, service, now.Add(time.Hour))

	verified, err := service.VerifyAPIToken(context.Background(), issued.Plaintext)

	require.NoError(t, err)
	assert.Equal(t, apikey.VerifiedToken{
		ID:          issued.ID,
		PrincipalID: testPrincipalID,
		ExpiresAt:   issued.ExpiresAt,
	}, verified)

	stored, err := store.FindToken(context.Background(), issued.ID)
	require.NoError(t, err)
	require.NotNil(t, stored.LastUsedAt)
	assert.Equal(t, now, *stored.LastUsedAt)
}

func TestServiceVerifyToken(t *testing.T) {
	now := fixedTime()
	service, _ := newService(t, now)
	issued := issueToken(t, service, now.Add(time.Hour))

	identity, err := service.VerifyToken(context.Background(), issued.Plaintext)

	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, &authkit.Identity{
		Provider:     apikey.Provider,
		Subject:      issued.ID,
		CredentialID: issued.ID,
	}, identity)
}

func TestServiceVerifyAPITokenRejectsInvalidTokens(t *testing.T) {
	now := fixedTime()
	service, _ := newService(t, now)
	issued := issueToken(t, service, now.Add(time.Hour))
	revoked := issueToken(t, service, now.Add(time.Hour))
	require.NoError(t, service.RevokeToken(context.Background(), revoked.ID))

	tests := []struct {
		name      string
		plaintext string
	}{
		{name: "malformed", plaintext: "not-a-token"},
		{name: "unknown ID", plaintext: "ak_missing_secret"},
		{name: "wrong secret", plaintext: replaceTokenSecret(t, issued.Plaintext, "wrong")},
		{name: "revoked", plaintext: revoked.Plaintext},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verified, err := service.VerifyAPIToken(context.Background(), tt.plaintext)

			require.ErrorIs(t, err, authkit.ErrUnauthenticated)
			assert.Empty(t, verified)
		})
	}
}

func TestServiceVerifyAPITokenRejectsExpiredToken(t *testing.T) {
	now := fixedTime()
	current := now
	service, _ := newServiceWithClock(t, func() time.Time {
		return current
	})
	issued := issueToken(t, service, now.Add(time.Hour))
	current = now.Add(time.Hour)

	verified, err := service.VerifyAPIToken(context.Background(), issued.Plaintext)

	require.ErrorIs(t, err, authkit.ErrUnauthenticated)
	assert.Empty(t, verified)
}

func TestServiceVerifyAPITokenIgnoresLastUsedUpdateErrors(t *testing.T) {
	now := fixedTime()
	service, store := newService(t, now)
	issued := issueToken(t, service, now.Add(time.Hour))
	stored, err := store.FindToken(context.Background(), issued.ID)
	require.NoError(t, err)

	service, err = apikey.NewService(&lastUsedFailStore{token: stored}, apikey.WithClock(func() time.Time {
		return now
	}))
	require.NoError(t, err)

	verified, err := service.VerifyAPIToken(context.Background(), issued.Plaintext)

	require.NoError(t, err)
	assert.Equal(t, issued.ID, verified.ID)
	assert.Equal(t, testPrincipalID, verified.PrincipalID)
}

func TestServiceRevokeToken(t *testing.T) {
	now := fixedTime()
	service, store := newService(t, now)
	issued := issueToken(t, service, now.Add(time.Hour))

	err := service.RevokeToken(context.Background(), issued.ID)

	require.NoError(t, err)
	stored, err := store.FindToken(context.Background(), issued.ID)
	require.NoError(t, err)
	require.NotNil(t, stored.RevokedAt)
	assert.Equal(t, now, *stored.RevokedAt)

	identity, err := service.VerifyToken(context.Background(), issued.Plaintext)
	require.ErrorIs(t, err, authkit.ErrUnauthenticated)
	assert.Nil(t, identity)
}

func TestAuthenticatorAcceptsBearerSchemeCaseInsensitively(t *testing.T) {
	now := fixedTime()
	service, _ := newService(t, now)
	issued := issueToken(t, service, now.Add(time.Hour))
	authenticator, err := apikey.NewAuthenticator(service)
	require.NoError(t, err)
	assert.Equal(t, apikey.Provider, authenticator.Name())

	tests := []struct {
		name   string
		scheme string
	}{
		{name: "canonical", scheme: "Bearer"},
		{name: "lowercase", scheme: "bearer"},
		{name: "mixed case", scheme: "bEaReR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", tt.scheme+" "+issued.Plaintext)

			identity, err := authenticator.Authenticate(context.Background(), req)

			require.NoError(t, err)
			require.NotNil(t, identity)
			assert.Equal(t, issued.ID, identity.Subject)
		})
	}
}

func TestAuthenticatorRejectsInvalidHeaders(t *testing.T) {
	now := fixedTime()
	service, _ := newService(t, now)
	authenticator, err := apikey.NewAuthenticator(service)
	require.NoError(t, err)

	tests := []struct {
		name   string
		header string
	}{
		{name: "missing"},
		{name: "wrong scheme", header: "Basic token"},
		{name: "empty bearer", header: "Bearer "},
		{name: "extra fields", header: "Bearer token extra"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			identity, err := authenticator.Authenticate(context.Background(), req)

			require.ErrorIs(t, err, authkit.ErrUnauthenticated)
			assert.Nil(t, identity)
		})
	}
}

func TestTokenIdentityResolvesThroughMemoryStore(t *testing.T) {
	now := fixedTime()
	store := memory.NewStore()
	service, err := apikey.NewService(store, apikey.WithClock(func() time.Time {
		return now
	}))
	require.NoError(t, err)
	principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindService,
		DisplayName: "deploy service",
	})
	require.NoError(t, err)
	issued := issueTokenForPrincipal(t, service, principal.ID, now.Add(time.Hour))
	_, err = store.LinkIdentity(context.Background(), issued.IdentityLink)
	require.NoError(t, err)

	identity, err := service.VerifyToken(context.Background(), issued.Plaintext)
	require.NoError(t, err)
	require.NotNil(t, identity)
	resolved, err := store.ResolveIdentity(context.Background(), *identity)

	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, principal, *resolved)
}

func TestConstructorsValidateRequiredDependencies(t *testing.T) {
	service, err := apikey.NewService(nil)
	require.Error(t, err)
	assert.Nil(t, service)

	authenticator, err := apikey.NewAuthenticator(nil)
	require.Error(t, err)
	assert.Nil(t, authenticator)
}

func newService(t *testing.T, now time.Time) (*apikey.Service, *memory.Store) {
	t.Helper()

	return newServiceWithClock(t, func() time.Time {
		return now
	})
}

func newServiceWithClock(t *testing.T, clock func() time.Time) (*apikey.Service, *memory.Store) {
	t.Helper()

	store := memory.NewStore()
	service, err := apikey.NewService(store, apikey.WithClock(clock))
	require.NoError(t, err)

	return service, store
}

func issueToken(t *testing.T, service *apikey.Service, expiresAt time.Time) apikey.IssuedToken {
	t.Helper()

	return issueTokenForPrincipal(t, service, testPrincipalID, expiresAt)
}

func issueTokenForPrincipal(
	t *testing.T,
	service *apikey.Service,
	principalID string,
	expiresAt time.Time,
) apikey.IssuedToken {
	t.Helper()

	issued, err := service.IssueToken(context.Background(), apikey.IssueRequest{
		PrincipalID: principalID,
		Name:        testTokenName,
		ExpiresAt:   expiresAt,
	})
	require.NoError(t, err)

	return issued
}

func replaceTokenSecret(t *testing.T, plaintext string, secret string) string {
	t.Helper()

	parts := strings.Split(plaintext, "_")
	require.Len(t, parts, tokenParts)

	return strings.Join([]string{parts[0], parts[1], secret}, "_")
}

func fixedTime() time.Time {
	return time.Date(2026, time.May, 7, 18, 0, 0, 0, time.UTC)
}

type lastUsedFailStore struct {
	token apikey.StoredToken
}

func (s *lastUsedFailStore) CreateToken(context.Context, apikey.StoredToken) error {
	return errors.New("unexpected create")
}

func (s *lastUsedFailStore) FindToken(context.Context, string) (apikey.StoredToken, error) {
	return s.token, nil
}

func (s *lastUsedFailStore) UpdateTokenLastUsed(context.Context, string, time.Time) error {
	return errors.New("last-used failed")
}

func (s *lastUsedFailStore) RevokeToken(context.Context, string, time.Time) error {
	return errors.New("unexpected revoke")
}
