package authkit_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/apikey"
	"github.com/meigma/authkit/store/memory"
)

func testIdentity() authkit.Identity {
	return authkit.Identity{
		Provider:     "test",
		Subject:      "subject-123",
		CredentialID: "credential-123",
	}
}

func testPrincipal() authkit.Principal {
	return authkit.Principal{
		ID:          "principal_1",
		Kind:        authkit.PrincipalKindUser,
		DisplayName: "Ada Lovelace",
	}
}

func testResource() authkit.Resource {
	return authkit.Resource{
		Type:       "note",
		ID:         "note-1",
		Attributes: map[string]any{"owner": "principal_1"},
	}
}

func TestNewPipelineValidatesRequiredDependencies(t *testing.T) {
	tests := []struct {
		name string
		opts authkit.PipelineOptions
	}{
		{
			name: "missing authenticators",
			opts: authkit.PipelineOptions{
				Resolver:   allowResolver(),
				Authorizer: allowAuthorizer(),
			},
		},
		{
			name: "nil authenticator",
			opts: authkit.PipelineOptions{
				Authenticators: []authkit.Authenticator{nil},
				Resolver:       allowResolver(),
				Authorizer:     allowAuthorizer(),
			},
		},
		{
			name: "nil principal authenticator",
			opts: authkit.PipelineOptions{
				PrincipalAuthenticators: []authkit.PrincipalAuthenticator{nil},
				Authorizer:              allowAuthorizer(),
			},
		},
		{
			name: "missing resolver",
			opts: authkit.PipelineOptions{
				Authenticators: []authkit.Authenticator{allowAuthenticator()},
				Authorizer:     allowAuthorizer(),
			},
		},
		{
			name: "missing authorizer",
			opts: authkit.PipelineOptions{
				Authenticators: []authkit.Authenticator{allowAuthenticator()},
				Resolver:       allowResolver(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline, err := authkit.NewPipeline(tt.opts)

			require.Error(t, err)
			assert.Nil(t, pipeline)
		})
	}
}

func TestNewPipelineAllowsPrincipalAuthenticatorWithoutResolver(t *testing.T) {
	pipeline, err := authkit.NewPipeline(authkit.PipelineOptions{
		PrincipalAuthenticators: []authkit.PrincipalAuthenticator{allowPrincipalAuthenticator()},
		Authorizer:              allowAuthorizer(),
	})

	require.NoError(t, err)
	assert.NotNil(t, pipeline)
}

func TestPipelineAuthenticateUsesFirstSuccessfulPrincipalAuthenticator(t *testing.T) {
	firstCalls := 0
	secondCalls := 0
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	pipeline := newTestPipeline(t, authkit.PipelineOptions{
		PrincipalAuthenticators: []authkit.PrincipalAuthenticator{
			testPrincipalAuthenticator{
				name: "first",
				authenticate: func(context.Context, *http.Request) (*authkit.PrincipalAuthentication, error) {
					firstCalls++

					return nil, fmtUnauthenticated("missing first credential")
				},
			},
			testPrincipalAuthenticator{
				name: "second",
				authenticate: func(context.Context, *http.Request) (*authkit.PrincipalAuthentication, error) {
					secondCalls++

					return &authkit.PrincipalAuthentication{
						Principal: testPrincipal(),
					}, nil
				},
			},
		},
		Authorizer: allowAuthorizer(),
	})

	authentication, err := pipeline.Authenticate(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, "second", authentication.AuthenticatorName)
	assert.Empty(t, authentication.Identity)
	assert.Equal(t, testPrincipal(), authentication.Principal)
	assert.Equal(t, 1, firstCalls)
	assert.Equal(t, 1, secondCalls)
}

func TestPipelineAuthenticateUsesFirstSuccessfulAuthenticator(t *testing.T) {
	firstCalls := 0
	secondCalls := 0
	resolverCalls := 0
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	pipeline := newTestPipeline(t, authkit.PipelineOptions{
		Authenticators: []authkit.Authenticator{
			testAuthenticator{
				name: "first",
				authenticate: func(context.Context, *http.Request) (*authkit.Identity, error) {
					firstCalls++

					return nil, fmtUnauthenticated("missing first credential")
				},
			},
			testAuthenticator{
				name: "second",
				authenticate: func(context.Context, *http.Request) (*authkit.Identity, error) {
					secondCalls++

					identity := testIdentity()

					return &identity, nil
				},
			},
		},
		Resolver: testResolver{
			resolve: func(_ context.Context, identity authkit.Identity) (*authkit.Principal, error) {
				resolverCalls++
				assert.Equal(t, testIdentity(), identity)

				principal := testPrincipal()

				return &principal, nil
			},
		},
		Authorizer: allowAuthorizer(),
	})

	authentication, err := pipeline.Authenticate(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, "second", authentication.AuthenticatorName)
	assert.Equal(t, testIdentity(), authentication.Identity)
	assert.Equal(t, testPrincipal(), authentication.Principal)
	assert.Equal(t, 1, firstCalls)
	assert.Equal(t, 1, secondCalls)
	assert.Equal(t, 1, resolverCalls)
}

func TestPipelineAuthenticateReturnsUnauthenticatedWhenAllAuthenticatorsReject(t *testing.T) {
	resolverCalls := 0
	pipeline := newTestPipeline(t, authkit.PipelineOptions{
		PrincipalAuthenticators: []authkit.PrincipalAuthenticator{
			denyPrincipalAuthenticator("principal"),
		},
		Authenticators: []authkit.Authenticator{
			denyAuthenticator("first"),
			denyAuthenticator("second"),
		},
		Resolver: testResolver{
			resolve: func(context.Context, authkit.Identity) (*authkit.Principal, error) {
				resolverCalls++

				principal := testPrincipal()

				return &principal, nil
			},
		},
		Authorizer: allowAuthorizer(),
	})

	authentication, err := pipeline.Authenticate(context.Background(), httptest.NewRequest(http.MethodGet, "/", nil))

	require.ErrorIs(t, err, authkit.ErrUnauthenticated)
	assert.Empty(t, authentication)
	assert.Equal(t, 0, resolverCalls)
}

func TestPipelineAuthenticateWrapsUnexpectedPrincipalAuthenticatorErrors(t *testing.T) {
	authenticatorErr := errors.New("provider failed")
	pipeline := newTestPipeline(t, authkit.PipelineOptions{
		PrincipalAuthenticators: []authkit.PrincipalAuthenticator{
			testPrincipalAuthenticator{
				name: "provider",
				authenticate: func(context.Context, *http.Request) (*authkit.PrincipalAuthentication, error) {
					return nil, authenticatorErr
				},
			},
		},
		Authorizer: allowAuthorizer(),
	})

	authentication, err := pipeline.Authenticate(context.Background(), httptest.NewRequest(http.MethodGet, "/", nil))

	require.ErrorIs(t, err, authkit.ErrInternal)
	require.ErrorIs(t, err, authenticatorErr)
	assert.Empty(t, authentication)
}

func TestPipelineAuthenticatePreservesUnresolvedIdentity(t *testing.T) {
	pipeline := newTestPipeline(t, authkit.PipelineOptions{
		Authenticators: []authkit.Authenticator{allowAuthenticator()},
		Resolver: testResolver{
			resolve: func(context.Context, authkit.Identity) (*authkit.Principal, error) {
				return nil, fmt.Errorf("%w: identity is not linked", authkit.ErrUnresolvedIdentity)
			},
		},
		Authorizer: allowAuthorizer(),
	})

	authentication, err := pipeline.Authenticate(context.Background(), httptest.NewRequest(http.MethodGet, "/", nil))

	require.ErrorIs(t, err, authkit.ErrUnresolvedIdentity)
	assert.Equal(t, "test", authentication.AuthenticatorName)
	assert.Equal(t, testIdentity(), authentication.Identity)
	assert.Empty(t, authentication.Principal)
}

func TestPipelineAuthenticateWrapsUnexpectedAuthenticatorErrors(t *testing.T) {
	authenticatorErr := errors.New("provider failed")
	pipeline := newTestPipeline(t, authkit.PipelineOptions{
		Authenticators: []authkit.Authenticator{
			testAuthenticator{
				name: "provider",
				authenticate: func(context.Context, *http.Request) (*authkit.Identity, error) {
					return nil, authenticatorErr
				},
			},
		},
		Resolver:   allowResolver(),
		Authorizer: allowAuthorizer(),
	})

	authentication, err := pipeline.Authenticate(context.Background(), httptest.NewRequest(http.MethodGet, "/", nil))

	require.ErrorIs(t, err, authkit.ErrInternal)
	require.ErrorIs(t, err, authenticatorErr)
	assert.Empty(t, authentication)
}

func TestPipelineAuthenticateWrapsUnexpectedResolverErrors(t *testing.T) {
	storeErr := errors.New("store failed")
	pipeline := newTestPipeline(t, authkit.PipelineOptions{
		Authenticators: []authkit.Authenticator{allowAuthenticator()},
		Resolver: testResolver{
			resolve: func(context.Context, authkit.Identity) (*authkit.Principal, error) {
				return nil, storeErr
			},
		},
		Authorizer: allowAuthorizer(),
	})

	authentication, err := pipeline.Authenticate(context.Background(), httptest.NewRequest(http.MethodGet, "/", nil))

	require.ErrorIs(t, err, authkit.ErrInternal)
	require.ErrorIs(t, err, storeErr)
	assert.Equal(t, testIdentity(), authentication.Identity)
	assert.Empty(t, authentication.Principal)
}

func TestPipelineAuthenticateWrapsBadCollaboratorContracts(t *testing.T) {
	tests := []struct {
		name string
		opts authkit.PipelineOptions
	}{
		{
			name: "authenticator returns nil identity without error",
			opts: authkit.PipelineOptions{
				Authenticators: []authkit.Authenticator{
					testAuthenticator{
						name: "bad",
						authenticate: func(context.Context, *http.Request) (*authkit.Identity, error) {
							//nolint:nilnil // Intentionally exercises bad collaborator contract handling.
							return nil, nil
						},
					},
				},
				Resolver:   allowResolver(),
				Authorizer: allowAuthorizer(),
			},
		},
		{
			name: "resolver returns nil principal without error",
			opts: authkit.PipelineOptions{
				Authenticators: []authkit.Authenticator{allowAuthenticator()},
				Resolver: testResolver{
					resolve: func(context.Context, authkit.Identity) (*authkit.Principal, error) {
						//nolint:nilnil // Intentionally exercises bad collaborator contract handling.
						return nil, nil
					},
				},
				Authorizer: allowAuthorizer(),
			},
		},
		{
			name: "principal authenticator returns nil authentication without error",
			opts: authkit.PipelineOptions{
				PrincipalAuthenticators: []authkit.PrincipalAuthenticator{
					testPrincipalAuthenticator{
						name: "bad",
						authenticate: func(context.Context, *http.Request) (*authkit.PrincipalAuthentication, error) {
							//nolint:nilnil // Intentionally exercises bad collaborator contract handling.
							return nil, nil
						},
					},
				},
				Authorizer: allowAuthorizer(),
			},
		},
		{
			name: "principal authenticator returns principal without ID",
			opts: authkit.PipelineOptions{
				PrincipalAuthenticators: []authkit.PrincipalAuthenticator{
					testPrincipalAuthenticator{
						name: "bad",
						authenticate: func(context.Context, *http.Request) (*authkit.PrincipalAuthentication, error) {
							return &authkit.PrincipalAuthentication{}, nil
						},
					},
				},
				Authorizer: allowAuthorizer(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline := newTestPipeline(t, tt.opts)

			authentication, err := pipeline.Authenticate(
				context.Background(),
				httptest.NewRequest(http.MethodGet, "/", nil),
			)

			require.ErrorIs(t, err, authkit.ErrInternal)
			assert.Empty(t, authentication.Principal)
		})
	}
}

func TestPipelineAuthenticatePassesThroughContextErrors(t *testing.T) {
	tests := []struct {
		name    string
		opts    authkit.PipelineOptions
		wantErr error
	}{
		{
			name:    "authenticator context error",
			wantErr: context.Canceled,
			opts: authkit.PipelineOptions{
				Authenticators: []authkit.Authenticator{
					testAuthenticator{
						name: "canceled",
						authenticate: func(context.Context, *http.Request) (*authkit.Identity, error) {
							return nil, context.Canceled
						},
					},
				},
				Resolver:   allowResolver(),
				Authorizer: allowAuthorizer(),
			},
		},
		{
			name:    "resolver context error",
			wantErr: context.DeadlineExceeded,
			opts: authkit.PipelineOptions{
				Authenticators: []authkit.Authenticator{allowAuthenticator()},
				Resolver: testResolver{
					resolve: func(context.Context, authkit.Identity) (*authkit.Principal, error) {
						return nil, context.DeadlineExceeded
					},
				},
				Authorizer: allowAuthorizer(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline := newTestPipeline(t, tt.opts)

			_, err := pipeline.Authenticate(context.Background(), httptest.NewRequest(http.MethodGet, "/", nil))

			require.ErrorIs(t, err, tt.wantErr)
			assert.NotErrorIs(t, err, authkit.ErrInternal)
		})
	}
}

func TestPipelineAuthorizeAllowsDecision(t *testing.T) {
	facts := authkit.Facts{
		"tenant_id": "tenant-1",
	}
	pipeline := newTestPipeline(t, authkit.PipelineOptions{
		Authenticators: []authkit.Authenticator{allowAuthenticator()},
		Resolver:       allowResolver(),
		Authorizer: testAuthorizer{
			can: func(_ context.Context, check authkit.AuthorizationCheck) (authkit.Decision, error) {
				assert.Equal(t, authkit.AuthorizationCheck{
					Principal: testPrincipal(),
					Action:    "note:update",
					Resource:  testResource(),
					Facts:     facts,
				}, check)

				return authkit.Decision{Allowed: true, Reason: "allowed"}, nil
			},
		},
	})

	authorization, err := pipeline.Authorize(
		context.Background(),
		httptest.NewRequest(http.MethodPost, "/notes/note-1", nil),
		authkit.AuthorizationRequest{
			Action:   "note:update",
			Resource: testResource(),
			Facts:    facts,
		},
	)

	require.NoError(t, err)
	assert.Equal(t, testPrincipal(), authorization.Authentication.Principal)
	assert.Equal(t, authkit.AuthorizationCheck{
		Principal: testPrincipal(),
		Action:    "note:update",
		Resource:  testResource(),
		Facts:     facts,
	}, authorization.Check)
	assert.Equal(t, authkit.Decision{Allowed: true, Reason: "allowed"}, authorization.Decision)
}

func TestPipelineAuthorizeAuthenticatedUsesExistingAuthentication(t *testing.T) {
	facts := authkit.Facts{
		"tenant_id": "tenant-1",
	}
	pipeline := newTestPipeline(t, authkit.PipelineOptions{
		Authenticators: []authkit.Authenticator{denyAuthenticator("unused")},
		Resolver:       allowResolver(),
		Authorizer: testAuthorizer{
			can: func(_ context.Context, check authkit.AuthorizationCheck) (authkit.Decision, error) {
				assert.Equal(t, authkit.AuthorizationCheck{
					Principal: testPrincipal(),
					Action:    "note:update",
					Resource:  testResource(),
					Facts:     facts,
				}, check)

				return authkit.Decision{Allowed: true, Reason: "allowed"}, nil
			},
		},
	})

	authorization, err := pipeline.AuthorizeAuthenticated(
		context.Background(),
		authkit.Authentication{
			AuthenticatorName: "pre-authenticated",
			Identity:          testIdentity(),
			Principal:         testPrincipal(),
		},
		authkit.AuthorizationRequest{
			Action:   "note:update",
			Resource: testResource(),
			Facts:    facts,
		},
	)

	require.NoError(t, err)
	assert.Equal(t, "pre-authenticated", authorization.Authentication.AuthenticatorName)
	assert.Equal(t, authkit.Decision{Allowed: true, Reason: "allowed"}, authorization.Decision)
}

func TestPipelineAuthorizeReturnsUnauthorizedForDeniedDecision(t *testing.T) {
	denied := authkit.Decision{
		Allowed: false,
		Reason:  "policy denied",
	}
	pipeline := newTestPipeline(t, authkit.PipelineOptions{
		Authenticators: []authkit.Authenticator{allowAuthenticator()},
		Resolver:       allowResolver(),
		Authorizer: testAuthorizer{
			can: func(_ context.Context, check authkit.AuthorizationCheck) (authkit.Decision, error) {
				assert.Equal(t, testPrincipal(), check.Principal)
				assert.Equal(t, "note:update", check.Action)
				assert.Equal(t, testResource(), check.Resource)

				return denied, nil
			},
		},
	})

	authorization, err := pipeline.Authorize(
		context.Background(),
		httptest.NewRequest(http.MethodPost, "/notes/note-1", nil),
		authkit.AuthorizationRequest{
			Action:   "note:update",
			Resource: testResource(),
		},
	)

	require.ErrorIs(t, err, authkit.ErrUnauthorized)
	assert.Equal(t, testPrincipal(), authorization.Authentication.Principal)
	assert.Equal(t, denied, authorization.Decision)
}

func TestPipelineAuthorizeWrapsUnexpectedAuthorizerErrors(t *testing.T) {
	authorizerErr := errors.New("policy backend failed")
	pipeline := newTestPipeline(t, authkit.PipelineOptions{
		Authenticators: []authkit.Authenticator{allowAuthenticator()},
		Resolver:       allowResolver(),
		Authorizer: testAuthorizer{
			can: func(context.Context, authkit.AuthorizationCheck) (authkit.Decision, error) {
				return authkit.Decision{}, authorizerErr
			},
		},
	})

	authorization, err := pipeline.Authorize(
		context.Background(),
		httptest.NewRequest(http.MethodPost, "/notes/note-1", nil),
		authkit.AuthorizationRequest{
			Action:   "note:update",
			Resource: testResource(),
		},
	)

	require.ErrorIs(t, err, authkit.ErrInternal)
	require.ErrorIs(t, err, authorizerErr)
	assert.Equal(t, testPrincipal(), authorization.Authentication.Principal)
}

func TestPipelineAuthorizePassesThroughContextErrors(t *testing.T) {
	pipeline := newTestPipeline(t, authkit.PipelineOptions{
		Authenticators: []authkit.Authenticator{allowAuthenticator()},
		Resolver:       allowResolver(),
		Authorizer: testAuthorizer{
			can: func(context.Context, authkit.AuthorizationCheck) (authkit.Decision, error) {
				return authkit.Decision{}, context.Canceled
			},
		},
	})

	_, err := pipeline.Authorize(
		context.Background(),
		httptest.NewRequest(http.MethodPost, "/notes/note-1", nil),
		authkit.AuthorizationRequest{
			Action:   "note:update",
			Resource: testResource(),
		},
	)

	require.ErrorIs(t, err, context.Canceled)
	assert.NotErrorIs(t, err, authkit.ErrInternal)
}

func TestPipelineAuthenticateWithAPITokenAndMemoryStore(t *testing.T) {
	now := time.Date(2026, time.May, 7, 18, 0, 0, 0, time.UTC)
	store := memory.NewStore()
	tokenService, err := apikey.NewService(store, apikey.WithClock(func() time.Time {
		return now
	}))
	require.NoError(t, err)
	tokenAuthenticator, err := apikey.NewAuthenticator(tokenService)
	require.NoError(t, err)
	principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindService,
		DisplayName: "deploy service",
	})
	require.NoError(t, err)
	issued, err := tokenService.IssueToken(context.Background(), apikey.IssueRequest{
		PrincipalID: principal.ID,
		Name:        "deploy token",
		ExpiresAt:   now.Add(time.Hour),
	})
	require.NoError(t, err)
	_, err = store.LinkIdentity(context.Background(), issued.IdentityLink)
	require.NoError(t, err)
	pipeline := newTestPipeline(t, authkit.PipelineOptions{
		Authenticators: []authkit.Authenticator{tokenAuthenticator},
		Resolver:       store,
		Authorizer:     allowAuthorizer(),
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+issued.Plaintext)

	authentication, err := pipeline.Authenticate(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, apikey.Provider, authentication.AuthenticatorName)
	assert.Equal(t, authkit.Identity{
		Provider:     apikey.Provider,
		Subject:      issued.ID,
		CredentialID: issued.ID,
	}, authentication.Identity)
	assert.Equal(t, principal, authentication.Principal)
}

func newTestPipeline(t *testing.T, opts authkit.PipelineOptions) *authkit.Pipeline {
	t.Helper()

	pipeline, err := authkit.NewPipeline(opts)
	require.NoError(t, err)

	return pipeline
}

type testAuthenticator struct {
	name         string
	authenticate func(context.Context, *http.Request) (*authkit.Identity, error)
}

func (a testAuthenticator) Name() string {
	return a.name
}

func (a testAuthenticator) Authenticate(ctx context.Context, req *http.Request) (*authkit.Identity, error) {
	return a.authenticate(ctx, req)
}

type testPrincipalAuthenticator struct {
	name         string
	authenticate func(context.Context, *http.Request) (*authkit.PrincipalAuthentication, error)
}

func (a testPrincipalAuthenticator) Name() string {
	return a.name
}

func (a testPrincipalAuthenticator) AuthenticatePrincipal(
	ctx context.Context,
	req *http.Request,
) (*authkit.PrincipalAuthentication, error) {
	return a.authenticate(ctx, req)
}

type testResolver struct {
	resolve func(context.Context, authkit.Identity) (*authkit.Principal, error)
}

func (r testResolver) ResolveIdentity(ctx context.Context, identity authkit.Identity) (*authkit.Principal, error) {
	return r.resolve(ctx, identity)
}

type testAuthorizer struct {
	can func(context.Context, authkit.AuthorizationCheck) (authkit.Decision, error)
}

func (a testAuthorizer) Can(ctx context.Context, check authkit.AuthorizationCheck) (authkit.Decision, error) {
	return a.can(ctx, check)
}

func allowAuthenticator() testAuthenticator {
	return testAuthenticator{
		name: "test",
		authenticate: func(context.Context, *http.Request) (*authkit.Identity, error) {
			identity := testIdentity()

			return &identity, nil
		},
	}
}

func allowPrincipalAuthenticator() testPrincipalAuthenticator {
	return testPrincipalAuthenticator{
		name: "test",
		authenticate: func(context.Context, *http.Request) (*authkit.PrincipalAuthentication, error) {
			return &authkit.PrincipalAuthentication{
				Principal: testPrincipal(),
			}, nil
		},
	}
}

func denyAuthenticator(name string) testAuthenticator {
	return testAuthenticator{
		name: name,
		authenticate: func(context.Context, *http.Request) (*authkit.Identity, error) {
			return nil, fmtUnauthenticated("not found")
		},
	}
}

func denyPrincipalAuthenticator(name string) testPrincipalAuthenticator {
	return testPrincipalAuthenticator{
		name: name,
		authenticate: func(context.Context, *http.Request) (*authkit.PrincipalAuthentication, error) {
			return nil, fmtUnauthenticated("not found")
		},
	}
}

func allowResolver() testResolver {
	return testResolver{
		resolve: func(context.Context, authkit.Identity) (*authkit.Principal, error) {
			principal := testPrincipal()

			return &principal, nil
		},
	}
}

func allowAuthorizer() testAuthorizer {
	return testAuthorizer{
		can: func(context.Context, authkit.AuthorizationCheck) (authkit.Decision, error) {
			return authkit.Decision{Allowed: true, Reason: "allowed"}, nil
		},
	}
}

func fmtUnauthenticated(reason string) error {
	return fmt.Errorf("%w: %s", authkit.ErrUnauthenticated, reason)
}
