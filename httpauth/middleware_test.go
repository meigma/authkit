package httpauth_test

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
	"github.com/meigma/authkit/httpauth"
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
	pipeline := newTestPipelineWithPrincipalAuthenticator(t, denyPrincipalAuthenticator("test"), allowAuthorizer())
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
		can: func(_ context.Context, check authkit.AuthorizationCheck) (authkit.Decision, error) {
			assert.Equal(t, testPrincipal(), check.Principal)
			assert.Equal(t, "note:update", check.Action)
			assert.Equal(t, testResource("note-1"), check.Resource)
			assert.Empty(t, check.Facts)

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
		can: func(_ context.Context, check authkit.AuthorizationCheck) (authkit.Decision, error) {
			assert.Equal(t, "note:read", check.Action)
			assert.Equal(t, testResource("42"), check.Resource)
			assert.Empty(t, check.Facts)

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

func TestMiddlewareRequireAuthorizationExtractsFacts(t *testing.T) {
	authenticatorCalls := 0
	authorizer := testAuthorizer{
		can: func(_ context.Context, check authkit.AuthorizationCheck) (authkit.Decision, error) {
			assert.Equal(t, "note:read", check.Action)
			assert.Equal(t, testResource("42"), check.Resource)
			assert.Equal(t, authkit.Facts{
				"request_method": "GET",
				"tenant_id":      "tenant-1",
			}, check.Facts)

			return authkit.Decision{Allowed: true}, nil
		},
	}
	pipeline := newTestPipelineWithPrincipalAuthenticator(
		t,
		testPrincipalAuthenticator{
			name: "test",
			authenticate: func(context.Context, *http.Request) (*authkit.PrincipalAuthentication, error) {
				authenticatorCalls++

				return &authkit.PrincipalAuthentication{
					Principal: testPrincipal(),
				}, nil
			},
		},
		authorizer,
	)
	middleware := newMiddleware(t, pipeline)
	handler := middleware.RequireAuthorization(func(req *http.Request) (authkit.AuthorizationRequest, error) {
		assertAuthenticationContext(req.Context(), t)

		return authkit.AuthorizationRequest{
			Action:   "note:read",
			Resource: testResource(req.PathValue("noteID")),
			Facts: authkit.Facts{
				"request_method": req.Method,
				"tenant_id":      req.Header.Get("X-Tenant-Id"),
			},
		}, nil
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mux := http.NewServeMux()
	mux.Handle("GET /notes/{noteID}", handler)
	req := httptest.NewRequest(http.MethodGet, "/notes/42", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, 1, authenticatorCalls)
}

func TestMiddlewareRequireAuthorizationDoesNotExtractWhenUnauthenticated(t *testing.T) {
	extractorCalls := 0
	pipeline := newTestPipelineWithPrincipalAuthenticator(t, denyPrincipalAuthenticator("test"), allowAuthorizer())
	middleware := newMiddleware(t, pipeline)
	handler := middleware.RequireAuthorization(func(*http.Request) (authkit.AuthorizationRequest, error) {
		extractorCalls++

		return authkit.AuthorizationRequest{
			Action:   "note:read",
			Resource: testResource("42"),
		}, nil
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/notes/42", nil))

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Equal(t, 0, extractorCalls)
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

func TestMiddlewareRendersInternalFailures(t *testing.T) {
	pipeline := newTestPipelineWithPrincipalAuthenticator(
		t,
		failingPrincipalAuthenticator("test", errors.New("provider failed")),
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
	pipeline := newTestPipelineWithPrincipalAuthenticator(t, denyPrincipalAuthenticator("test"), allowAuthorizer())
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

func newMiddleware(t *testing.T, pipeline *authkit.Pipeline) *httpauth.Middleware {
	t.Helper()

	middleware, err := httpauth.NewMiddleware(pipeline)
	require.NoError(t, err)

	return middleware
}

func newTestPipeline(t *testing.T, decision authkit.Decision) *authkit.Pipeline {
	t.Helper()

	return newTestPipelineWithAuthorizer(t, testAuthorizer{
		can: func(context.Context, authkit.AuthorizationCheck) (authkit.Decision, error) {
			return decision, nil
		},
	})
}

func newTestPipelineWithAuthorizer(t *testing.T, authorizer authkit.Authorizer) *authkit.Pipeline {
	t.Helper()

	return newTestPipelineWithOptions(t, authkit.PipelineOptions{
		PrincipalAuthenticators: []authkit.PrincipalAuthenticator{allowPrincipalAuthenticator()},
		Authorizer:              authorizer,
	})
}

func newTestPipelineWithPrincipalAuthenticator(
	t *testing.T,
	authenticator authkit.PrincipalAuthenticator,
	authorizer authkit.Authorizer,
) *authkit.Pipeline {
	t.Helper()

	return newTestPipelineWithOptions(t, authkit.PipelineOptions{
		PrincipalAuthenticators: []authkit.PrincipalAuthenticator{authenticator},
		Authorizer:              authorizer,
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

	principal, ok := httpauth.PrincipalFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, testPrincipal(), principal)
}

func testAuthentication() authkit.Authentication {
	return authkit.Authentication{
		AuthenticatorName: "test",
		Principal:         testPrincipal(),
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
	return failingPrincipalAuthenticator(name, fmt.Errorf("%w: credential missing", authkit.ErrUnauthenticated))
}

func failingPrincipalAuthenticator(name string, err error) testPrincipalAuthenticator {
	return testPrincipalAuthenticator{
		name: name,
		authenticate: func(context.Context, *http.Request) (*authkit.PrincipalAuthentication, error) {
			return nil, err
		},
	}
}

func allowAuthorizer() testAuthorizer {
	return testAuthorizer{
		can: func(context.Context, authkit.AuthorizationCheck) (authkit.Decision, error) {
			return authkit.Decision{Allowed: true}, nil
		},
	}
}
