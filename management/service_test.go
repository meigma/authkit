package management_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/apikey"
	"github.com/meigma/authkit/management"
	"github.com/meigma/authkit/store/memory"
)

const (
	testPrincipalID   = "principal_1"
	testTokenID       = "token_1"
	testTokenName     = "deploy token"
	testTokenSecret   = "ak_token_1_secret"
	testProvider      = "oidc"
	testSubject       = "user-123"
	testPrincipalName = "deploy service"
)

func TestNewServiceValidatesOptions(t *testing.T) {
	tests := []struct {
		name string
		opts management.Options
	}{
		{
			name: "missing principal creator",
			opts: management.Options{
				IdentityLinker: newFakeIdentityLinker(),
				APITokens:      newFakeAPITokens(),
			},
		},
		{
			name: "missing identity linker",
			opts: management.Options{
				PrincipalCreator: newFakePrincipalCreator(),
				APITokens:        newFakeAPITokens(),
			},
		},
		{
			name: "missing API tokens",
			opts: management.Options{
				PrincipalCreator: newFakePrincipalCreator(),
				IdentityLinker:   newFakeIdentityLinker(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := management.NewService(tt.opts)

			require.Error(t, err)
			assert.Nil(t, service)
		})
	}
}

func TestServiceCreatePrincipal(t *testing.T) {
	creator := newFakePrincipalCreator()
	creator.principal = authkit.Principal{
		ID:          testPrincipalID,
		Kind:        authkit.PrincipalKindService,
		DisplayName: testPrincipalName,
	}
	service := newService(t, creator, newFakeIdentityLinker(), newFakeAPITokens())
	req := authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindService,
		DisplayName: testPrincipalName,
	}

	principal, err := service.CreatePrincipal(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, creator.principal, principal)
	assert.Equal(t, []authkit.CreatePrincipalRequest{req}, creator.requests)
}

func TestServiceLinkIdentity(t *testing.T) {
	linker := newFakeIdentityLinker()
	linker.identity = authkit.ExternalIdentity{
		Provider:    testProvider,
		Subject:     testSubject,
		PrincipalID: testPrincipalID,
	}
	service := newService(t, newFakePrincipalCreator(), linker, newFakeAPITokens())
	req := authkit.LinkIdentityRequest(linker.identity)

	identity, err := service.LinkIdentity(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, linker.identity, identity)
	assert.Equal(t, []authkit.LinkIdentityRequest{req}, linker.requests)
}

func TestServiceIssueAPITokenLinksIdentity(t *testing.T) {
	now := fixedTime()
	expiresAt := now.Add(time.Hour)
	apiTokens := newFakeAPITokens()
	apiTokens.issued = apikey.IssuedToken{
		ID:        testTokenID,
		Plaintext: testTokenSecret,
		ExpiresAt: expiresAt,
		IdentityLink: authkit.LinkIdentityRequest{
			Provider:    apikey.Provider,
			Subject:     testTokenID,
			PrincipalID: testPrincipalID,
		},
	}
	linker := newFakeIdentityLinker()
	linker.identity = authkit.ExternalIdentity(apiTokens.issued.IdentityLink)
	service := newService(t, newFakePrincipalCreator(), linker, apiTokens)
	req := management.IssueAPITokenRequest{
		PrincipalID: testPrincipalID,
		Name:        testTokenName,
		ExpiresAt:   expiresAt,
	}

	issued, err := service.IssueAPIToken(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, []apikey.IssueRequest{{
		PrincipalID: testPrincipalID,
		Name:        testTokenName,
		ExpiresAt:   expiresAt,
	}}, apiTokens.issueRequests)
	assert.Equal(t, []authkit.LinkIdentityRequest{apiTokens.issued.IdentityLink}, linker.requests)
	assert.Equal(t, management.IssuedAPIToken{
		ID:        testTokenID,
		Plaintext: testTokenSecret,
		ExpiresAt: expiresAt,
		Identity:  linker.identity,
	}, issued)
}

func TestServiceIssueAPITokenReturnsIssueErrorWithoutLinking(t *testing.T) {
	issueErr := errors.New("issue failed")
	apiTokens := newFakeAPITokens()
	apiTokens.issueErr = issueErr
	linker := newFakeIdentityLinker()
	service := newService(t, newFakePrincipalCreator(), linker, apiTokens)

	issued, err := service.IssueAPIToken(context.Background(), management.IssueAPITokenRequest{
		PrincipalID: testPrincipalID,
		ExpiresAt:   fixedTime().Add(time.Hour),
	})

	require.ErrorIs(t, err, issueErr)
	assert.Empty(t, issued)
	assert.Empty(t, linker.requests)
	assert.Empty(t, apiTokens.revokedIDs)
}

func TestServiceIssueAPITokenRevokesWhenLinkingFails(t *testing.T) {
	linkErr := errors.New("link failed")
	apiTokens := newFakeAPITokens()
	apiTokens.issued = apikey.IssuedToken{
		ID:        testTokenID,
		Plaintext: testTokenSecret,
		ExpiresAt: fixedTime().Add(time.Hour),
		IdentityLink: authkit.LinkIdentityRequest{
			Provider:    apikey.Provider,
			Subject:     testTokenID,
			PrincipalID: testPrincipalID,
		},
	}
	apiTokens.revokeErr = errors.New("cleanup failed")
	linker := newFakeIdentityLinker()
	linker.err = linkErr
	service := newService(t, newFakePrincipalCreator(), linker, apiTokens)

	issued, err := service.IssueAPIToken(context.Background(), management.IssueAPITokenRequest{
		PrincipalID: testPrincipalID,
		ExpiresAt:   fixedTime().Add(time.Hour),
	})

	require.ErrorIs(t, err, linkErr)
	assert.Empty(t, issued)
	assert.Equal(t, []string{testTokenID}, apiTokens.revokedIDs)
}

func TestServiceRevokeAPIToken(t *testing.T) {
	apiTokens := newFakeAPITokens()
	service := newService(t, newFakePrincipalCreator(), newFakeIdentityLinker(), apiTokens)

	err := service.RevokeAPIToken(context.Background(), testTokenID)

	require.NoError(t, err)
	assert.Equal(t, []string{testTokenID}, apiTokens.revokedIDs)
}

func TestServiceRevokeAPITokenReturnsError(t *testing.T) {
	revokeErr := errors.New("revoke failed")
	apiTokens := newFakeAPITokens()
	apiTokens.revokeErr = revokeErr
	service := newService(t, newFakePrincipalCreator(), newFakeIdentityLinker(), apiTokens)

	err := service.RevokeAPIToken(context.Background(), testTokenID)

	require.ErrorIs(t, err, revokeErr)
}

func TestServicePropagatesContextCancellation(t *testing.T) {
	now := fixedTime()
	store := memory.NewStore()
	tokenService, err := apikey.NewService(store, apikey.WithClock(func() time.Time {
		return now
	}))
	require.NoError(t, err)
	service := newManagementService(t, store, tokenService)
	principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
		Kind: authkit.PrincipalKindService,
	})
	require.NoError(t, err)
	token, err := tokenService.IssueToken(context.Background(), apikey.IssueRequest{
		PrincipalID: principal.ID,
		ExpiresAt:   now.Add(time.Hour),
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
				_, runErr := service.CreatePrincipal(ctx, authkit.CreatePrincipalRequest{
					Kind: authkit.PrincipalKindService,
				})

				return runErr
			},
		},
		{
			name: "link identity",
			run: func() error {
				_, runErr := service.LinkIdentity(ctx, token.IdentityLink)

				return runErr
			},
		},
		{
			name: "issue API token",
			run: func() error {
				_, runErr := service.IssueAPIToken(ctx, management.IssueAPITokenRequest{
					PrincipalID: principal.ID,
					ExpiresAt:   now.Add(time.Hour),
				})

				return runErr
			},
		},
		{
			name: "revoke API token",
			run: func() error {
				return service.RevokeAPIToken(ctx, token.ID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorIs(t, tt.run(), context.Canceled)
		})
	}
}

func TestServiceIssueAPITokenResolvesThroughMemoryStore(t *testing.T) {
	now := fixedTime()
	store := memory.NewStore()
	tokenService, err := apikey.NewService(store, apikey.WithClock(func() time.Time {
		return now
	}))
	require.NoError(t, err)
	service := newManagementService(t, store, tokenService)
	principal, err := service.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindService,
		DisplayName: testPrincipalName,
	})
	require.NoError(t, err)

	issued, err := service.IssueAPIToken(context.Background(), management.IssueAPITokenRequest{
		PrincipalID: principal.ID,
		Name:        testTokenName,
		ExpiresAt:   now.Add(time.Hour),
	})
	require.NoError(t, err)
	identity, err := tokenService.VerifyToken(context.Background(), issued.Plaintext)
	require.NoError(t, err)
	require.NotNil(t, identity)
	resolved, err := store.ResolveIdentity(context.Background(), *identity)

	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, principal, *resolved)
	assert.Equal(t, authkit.ExternalIdentity{
		Provider:    apikey.Provider,
		Subject:     issued.ID,
		PrincipalID: principal.ID,
	}, issued.Identity)
}

func newService(
	t *testing.T,
	creator authkit.PrincipalCreator,
	linker authkit.IdentityLinker,
	apiTokens management.APITokens,
) *management.Service {
	t.Helper()

	service, err := management.NewService(management.Options{
		PrincipalCreator: creator,
		IdentityLinker:   linker,
		APITokens:        apiTokens,
	})
	require.NoError(t, err)

	return service
}

func newManagementService(
	t *testing.T,
	store *memory.Store,
	tokenService *apikey.Service,
) *management.Service {
	t.Helper()

	return newService(t, store, store, tokenService)
}

func newFakePrincipalCreator() *fakePrincipalCreator {
	return &fakePrincipalCreator{}
}

func newFakeIdentityLinker() *fakeIdentityLinker {
	return &fakeIdentityLinker{}
}

func newFakeAPITokens() *fakeAPITokens {
	return &fakeAPITokens{}
}

func fixedTime() time.Time {
	return time.Date(2026, time.May, 8, 12, 0, 0, 0, time.UTC)
}

type fakePrincipalCreator struct {
	requests  []authkit.CreatePrincipalRequest
	principal authkit.Principal
	err       error
}

func (f *fakePrincipalCreator) CreatePrincipal(
	_ context.Context,
	req authkit.CreatePrincipalRequest,
) (authkit.Principal, error) {
	f.requests = append(f.requests, req)
	if f.err != nil {
		return authkit.Principal{}, f.err
	}

	return f.principal, nil
}

type fakeIdentityLinker struct {
	requests []authkit.LinkIdentityRequest
	identity authkit.ExternalIdentity
	err      error
}

func (f *fakeIdentityLinker) LinkIdentity(
	_ context.Context,
	req authkit.LinkIdentityRequest,
) (authkit.ExternalIdentity, error) {
	f.requests = append(f.requests, req)
	if f.err != nil {
		return authkit.ExternalIdentity{}, f.err
	}

	return f.identity, nil
}

type fakeAPITokens struct {
	issueRequests []apikey.IssueRequest
	issued        apikey.IssuedToken
	issueErr      error
	revokedIDs    []string
	revokeErr     error
}

func (f *fakeAPITokens) IssueToken(
	_ context.Context,
	req apikey.IssueRequest,
) (apikey.IssuedToken, error) {
	f.issueRequests = append(f.issueRequests, req)
	if f.issueErr != nil {
		return apikey.IssuedToken{}, f.issueErr
	}

	return f.issued, nil
}

func (f *fakeAPITokens) RevokeToken(_ context.Context, tokenID string) error {
	f.revokedIDs = append(f.revokedIDs, tokenID)
	if f.revokeErr != nil {
		return f.revokeErr
	}

	return nil
}
