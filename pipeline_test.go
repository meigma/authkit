package authkit_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
)

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
			name: "missing principal authenticators",
			opts: authkit.PipelineOptions{
				Authorizer: allowAuthorizer(),
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
			name: "missing authorizer",
			opts: authkit.PipelineOptions{
				PrincipalAuthenticators: []authkit.PrincipalAuthenticator{allowPrincipalAuthenticator()},
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
	assert.Equal(t, testPrincipal(), authentication.Principal)
	assert.Equal(t, 1, firstCalls)
	assert.Equal(t, 1, secondCalls)
}

func TestPipelineAuthenticateReturnsUnauthenticatedWhenAllPrincipalAuthenticatorsReject(t *testing.T) {
	pipeline := newTestPipeline(t, authkit.PipelineOptions{
		PrincipalAuthenticators: []authkit.PrincipalAuthenticator{
			denyPrincipalAuthenticator("first"),
			denyPrincipalAuthenticator("second"),
		},
		Authorizer: allowAuthorizer(),
	})

	authentication, err := pipeline.Authenticate(context.Background(), httptest.NewRequest(http.MethodGet, "/", nil))

	require.ErrorIs(t, err, authkit.ErrUnauthenticated)
	assert.Empty(t, authentication)
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

func TestPipelineAuthenticateWrapsBadCollaboratorContracts(t *testing.T) {
	tests := []struct {
		name string
		opts authkit.PipelineOptions
	}{
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
	pipeline := newTestPipeline(t, authkit.PipelineOptions{
		PrincipalAuthenticators: []authkit.PrincipalAuthenticator{
			testPrincipalAuthenticator{
				name: "canceled",
				authenticate: func(context.Context, *http.Request) (*authkit.PrincipalAuthentication, error) {
					return nil, context.Canceled
				},
			},
		},
		Authorizer: allowAuthorizer(),
	})

	_, err := pipeline.Authenticate(context.Background(), httptest.NewRequest(http.MethodGet, "/", nil))

	require.ErrorIs(t, err, context.Canceled)
	assert.NotErrorIs(t, err, authkit.ErrInternal)
}

func TestPipelineAuthorizeAllowsDecision(t *testing.T) {
	facts := authkit.Facts{
		"tenant_id": "tenant-1",
	}
	pipeline := newTestPipeline(t, authkit.PipelineOptions{
		PrincipalAuthenticators: []authkit.PrincipalAuthenticator{allowPrincipalAuthenticator()},
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
		PrincipalAuthenticators: []authkit.PrincipalAuthenticator{denyPrincipalAuthenticator("unused")},
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
		PrincipalAuthenticators: []authkit.PrincipalAuthenticator{allowPrincipalAuthenticator()},
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
		PrincipalAuthenticators: []authkit.PrincipalAuthenticator{allowPrincipalAuthenticator()},
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
		PrincipalAuthenticators: []authkit.PrincipalAuthenticator{allowPrincipalAuthenticator()},
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

func newTestPipeline(t *testing.T, opts authkit.PipelineOptions) *authkit.Pipeline {
	t.Helper()

	pipeline, err := authkit.NewPipeline(opts)
	require.NoError(t, err)

	return pipeline
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

type testAuthorizer struct {
	can func(context.Context, authkit.AuthorizationCheck) (authkit.Decision, error)
}

func (a testAuthorizer) Can(ctx context.Context, check authkit.AuthorizationCheck) (authkit.Decision, error) {
	return a.can(ctx, check)
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

func denyPrincipalAuthenticator(name string) testPrincipalAuthenticator {
	return testPrincipalAuthenticator{
		name: name,
		authenticate: func(context.Context, *http.Request) (*authkit.PrincipalAuthentication, error) {
			return nil, fmtUnauthenticated("not found")
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
