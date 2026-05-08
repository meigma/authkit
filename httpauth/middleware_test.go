package httpauth_test

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
	"github.com/meigma/authkit/httpauth"
	"github.com/meigma/authkit/store/memory"
)

func TestNewMiddlewareValidatesPipeline(t *testing.T) {
	middleware, err := httpauth.NewMiddleware(nil)

	require.Error(t, err)
	assert.Nil(t, middleware)
}

func TestContextHelpersReturnFalseWhenMissing(t *testing.T) {
	authentication, ok := httpauth.AuthenticationFromContext(context.Background())
	assert.False(t, ok)
	assert.Empty(t, authentication)

	identity, ok := httpauth.IdentityFromContext(context.Background())
	assert.False(t, ok)
	assert.Empty(t, identity)

	principal, ok := httpauth.PrincipalFromContext(context.Background())
	assert.False(t, ok)
	assert.Empty(t, principal)
}

func TestMiddlewareAuthenticatePopulatesContext(t *testing.T) {
	pipeline := newTestPipeline(t, authkit.Decision{Allowed: true})
	middleware := newMiddleware(t, pipeline)
	handlerCalled := false
	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		handlerCalled = true

		assertAuthenticationContext(req.Context(), t)
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusNoContent, recorder.Code)
}

func TestMiddlewareAuthenticateRendersUnauthenticated(t *testing.T) {
	pipeline := newTestPipelineWithAuthenticator(t, denyAuthenticator("test"), allowAuthorizer())
	middleware := newMiddleware(t, pipeline)
	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Equal(t, "Unauthorized\n", recorder.Body.String())
}

func TestMiddlewareRequireAllowsRequest(t *testing.T) {
	authorizer := testAuthorizer{
		can: func(
			_ context.Context,
			principal authkit.Principal,
			action string,
			resource authkit.Resource,
		) (authkit.Decision, error) {
			assert.Equal(t, testPrincipal(), principal)
			assert.Equal(t, "note:update", action)
			assert.Equal(t, testResource("note-1"), resource)

			return authkit.Decision{Allowed: true}, nil
		},
	}
	pipeline := newTestPipelineWithAuthorizer(t, authorizer)
	middleware := newMiddleware(t, pipeline)
	handlerCalled := false
	handler := middleware.Require("note:update", testResource("note-1"))(
		http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			handlerCalled = true

			assertAuthenticationContext(req.Context(), t)
			w.WriteHeader(http.StatusAccepted)
		}),
	)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/notes/note-1", nil))

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusAccepted, recorder.Code)
}

func TestMiddlewareRequireRendersDeniedDecision(t *testing.T) {
	pipeline := newTestPipeline(t, authkit.Decision{
		Allowed: false,
		Reason:  "policy denied",
	})
	middleware := newMiddleware(t, pipeline)
	handler := middleware.Require("note:update", testResource("note-1"))(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/notes/note-1", nil))

	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Equal(t, "Forbidden\n", recorder.Body.String())
}

func TestMiddlewareRequireFuncExtractsResource(t *testing.T) {
	authorizer := testAuthorizer{
		can: func(
			_ context.Context,
			_ authkit.Principal,
			action string,
			resource authkit.Resource,
		) (authkit.Decision, error) {
			assert.Equal(t, "note:read", action)
			assert.Equal(t, testResource("42"), resource)

			return authkit.Decision{Allowed: true}, nil
		},
	}
	pipeline := newTestPipelineWithAuthorizer(t, authorizer)
	middleware := newMiddleware(t, pipeline)
	handler := middleware.RequireFunc("note:read", func(req *http.Request) (authkit.Resource, error) {
		return testResource(req.PathValue("noteID")), nil
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mux := http.NewServeMux()
	mux.Handle("GET /notes/{noteID}", handler)

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/notes/42", nil))

	assert.Equal(t, http.StatusOK, recorder.Code)
}

func TestMiddlewareRequireFuncRendersExtractorFailureAsInternal(t *testing.T) {
	extractErr := errors.New("missing resource")
	pipeline := newTestPipeline(t, authkit.Decision{Allowed: true})
	middleware := newMiddleware(t, pipeline)
	handler := middleware.RequireFunc("note:read", func(*http.Request) (authkit.Resource, error) {
		return authkit.Resource{}, extractErr
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Equal(t, "Internal Server Error\n", recorder.Body.String())
}

func TestMiddlewareRendersUnresolvedIdentityAsUnauthorized(t *testing.T) {
	pipeline := newTestPipelineWithResolver(t, testResolver{
		resolve: func(context.Context, authkit.Identity) (*authkit.Principal, error) {
			return nil, fmt.Errorf("%w: identity is not linked", authkit.ErrUnresolvedIdentity)
		},
	})
	middleware := newMiddleware(t, pipeline)
	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Equal(t, "Unauthorized\n", recorder.Body.String())
}

func TestMiddlewareRendersInternalFailures(t *testing.T) {
	pipeline := newTestPipelineWithAuthenticator(
		t,
		failingAuthenticator("test", errors.New("provider failed")),
		allowAuthorizer(),
	)
	middleware := newMiddleware(t, pipeline)
	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Equal(t, "Internal Server Error\n", recorder.Body.String())
}

func TestMiddlewareUsesCustomRenderer(t *testing.T) {
	var renderedErr error
	pipeline := newTestPipelineWithAuthenticator(t, denyAuthenticator("test"), allowAuthorizer())
	middleware, err := httpauth.NewMiddleware(
		pipeline,
		httpauth.WithErrorRenderer(func(w http.ResponseWriter, _ *http.Request, err error) {
			renderedErr = err
			http.Error(w, "custom", http.StatusTeapot)
		}),
	)
	require.NoError(t, err)
	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	require.ErrorIs(t, renderedErr, authkit.ErrUnauthenticated)
	assert.Equal(t, http.StatusTeapot, recorder.Code)
	assert.Equal(t, "custom\n", recorder.Body.String())
}

func TestMiddlewareAuthenticatesAPITokenThroughHTTPPath(t *testing.T) {
	now := time.Date(2026, time.May, 7, 19, 45, 0, 0, time.UTC)
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
	pipeline, err := authkit.NewPipeline(authkit.PipelineOptions{
		Authenticators: []authkit.Authenticator{tokenAuthenticator},
		Resolver:       store,
		Authorizer:     allowAuthorizer(),
	})
	require.NoError(t, err)
	middleware := newMiddleware(t, pipeline)
	handler := middleware.Require("deploy", authkit.Resource{Type: "service", ID: "deploy"})(
		http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			got, ok := httpauth.PrincipalFromContext(req.Context())
			if assert.True(t, ok) {
				assert.Equal(t, principal, got)
			}

			w.WriteHeader(http.StatusNoContent)
		}),
	)
	req := httptest.NewRequest(http.MethodPost, "/deploy", nil)
	req.Header.Set("Authorization", "Bearer "+issued.Plaintext)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusNoContent, recorder.Code)
}

func newMiddleware(t *testing.T, pipeline *authkit.Pipeline) *httpauth.Middleware {
	t.Helper()

	middleware, err := httpauth.NewMiddleware(pipeline)
	require.NoError(t, err)

	return middleware
}

func newTestPipeline(t *testing.T, decision authkit.Decision) *authkit.Pipeline {
	t.Helper()

	return newTestPipelineWithAuthorizer(t, testAuthorizer{
		can: func(context.Context, authkit.Principal, string, authkit.Resource) (authkit.Decision, error) {
			return decision, nil
		},
	})
}

func newTestPipelineWithAuthorizer(t *testing.T, authorizer authkit.Authorizer) *authkit.Pipeline {
	t.Helper()

	return newTestPipelineWithOptions(t, authkit.PipelineOptions{
		Authenticators: []authkit.Authenticator{allowAuthenticator()},
		Resolver:       allowResolver(),
		Authorizer:     authorizer,
	})
}

func newTestPipelineWithResolver(t *testing.T, resolver authkit.PrincipalResolver) *authkit.Pipeline {
	t.Helper()

	return newTestPipelineWithOptions(t, authkit.PipelineOptions{
		Authenticators: []authkit.Authenticator{allowAuthenticator()},
		Resolver:       resolver,
		Authorizer:     allowAuthorizer(),
	})
}

func newTestPipelineWithAuthenticator(
	t *testing.T,
	authenticator authkit.Authenticator,
	authorizer authkit.Authorizer,
) *authkit.Pipeline {
	t.Helper()

	return newTestPipelineWithOptions(t, authkit.PipelineOptions{
		Authenticators: []authkit.Authenticator{authenticator},
		Resolver:       allowResolver(),
		Authorizer:     authorizer,
	})
}

func newTestPipelineWithOptions(t *testing.T, opts authkit.PipelineOptions) *authkit.Pipeline {
	t.Helper()

	pipeline, err := authkit.NewPipeline(opts)
	require.NoError(t, err)

	return pipeline
}

func assertAuthenticationContext(ctx context.Context, t *testing.T) {
	t.Helper()

	authentication, ok := httpauth.AuthenticationFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, testAuthentication(), authentication)

	identity, ok := httpauth.IdentityFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, testIdentity(), identity)

	principal, ok := httpauth.PrincipalFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, testPrincipal(), principal)
}

func testAuthentication() authkit.Authentication {
	return authkit.Authentication{
		AuthenticatorName: "test",
		Identity:          testIdentity(),
		Principal:         testPrincipal(),
	}
}

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

func testResource(id string) authkit.Resource {
	return authkit.Resource{
		Type: "note",
		ID:   id,
	}
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

type testResolver struct {
	resolve func(context.Context, authkit.Identity) (*authkit.Principal, error)
}

func (r testResolver) ResolveIdentity(ctx context.Context, identity authkit.Identity) (*authkit.Principal, error) {
	return r.resolve(ctx, identity)
}

type testAuthorizer struct {
	can func(context.Context, authkit.Principal, string, authkit.Resource) (authkit.Decision, error)
}

func (a testAuthorizer) Can(
	ctx context.Context,
	principal authkit.Principal,
	action string,
	resource authkit.Resource,
) (authkit.Decision, error) {
	return a.can(ctx, principal, action, resource)
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

func denyAuthenticator(name string) testAuthenticator {
	return failingAuthenticator(name, fmt.Errorf("%w: credential missing", authkit.ErrUnauthenticated))
}

func failingAuthenticator(name string, err error) testAuthenticator {
	return testAuthenticator{
		name: name,
		authenticate: func(context.Context, *http.Request) (*authkit.Identity, error) {
			return nil, err
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
		can: func(context.Context, authkit.Principal, string, authkit.Resource) (authkit.Decision, error) {
			return authkit.Decision{Allowed: true}, nil
		},
	}
}
