package roleauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/accessjwt"
	"github.com/meigma/authkit/accessjwtauth"
	"github.com/meigma/authkit/httpauth"
	"github.com/meigma/authkit/internal/authtest"
	"github.com/meigma/authkit/roleauth"
	"github.com/meigma/authkit/store/memory"
)

const (
	testAction      = "notes:read"
	testPrincipalID = "principal_1"
	testRoleID      = "notes-reader"
)

func TestNewAuthorizerValidatesResolver(t *testing.T) {
	authorizer, err := roleauth.NewAuthorizer(nil)

	require.Error(t, err)
	assert.Nil(t, authorizer)
}

func TestAuthorizerCan(t *testing.T) {
	resolverErr := errors.New("resolver failed")

	tests := []struct {
		name        string
		resolver    *fakeActionResolver
		check       authkit.AuthorizationCheck
		assertError func(t *testing.T, err error)
		want        authkit.Decision
	}{
		{
			name:     "allows granted action",
			resolver: &fakeActionResolver{actions: []string{"notes:write", testAction}},
			check:    testCheck(),
			assertError: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
			want: authkit.Decision{Allowed: true},
		},
		{
			name:     "denies ungranted action",
			resolver: &fakeActionResolver{actions: []string{"notes:write"}},
			check:    testCheck(),
			assertError: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
			want: authkit.Decision{
				Allowed: false,
				Reason:  "action not granted",
			},
		},
		{
			name:     "rejects missing principal ID",
			resolver: &fakeActionResolver{actions: []string{testAction}},
			check: authkit.AuthorizationCheck{
				Action: testAction,
			},
			assertError: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "principal ID is required")
			},
		},
		{
			name:     "rejects missing action",
			resolver: &fakeActionResolver{actions: []string{testAction}},
			check: authkit.AuthorizationCheck{
				Principal: testPrincipal(),
			},
			assertError: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "action is required")
			},
		},
		{
			name:     "propagates resolver error",
			resolver: &fakeActionResolver{err: resolverErr},
			check:    testCheck(),
			assertError: func(t *testing.T, err error) {
				require.ErrorIs(t, err, resolverErr)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorizer, err := roleauth.NewAuthorizer(tt.resolver)
			require.NoError(t, err)

			decision, err := authorizer.Can(context.Background(), tt.check)

			tt.assertError(t, err)
			assert.Equal(t, tt.want, decision)
			if err == nil {
				assert.Equal(t, []string{tt.check.Principal.ID}, tt.resolver.requests)
			}
		})
	}
}

func TestAuthorizerRespectsContextCancellation(t *testing.T) {
	authorizer, err := roleauth.NewAuthorizer(&fakeActionResolver{actions: []string{testAction}})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	decision, err := authorizer.Can(ctx, testCheck())

	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, decision)
}

func TestAuthorizerAllowsHTTPMiddlewareThroughAccessJWT(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	principal, err := store.CreatePrincipal(ctx, authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindUser,
		DisplayName: "Ada Lovelace",
	})
	require.NoError(t, err)
	_, err = store.CreateRole(ctx, authkit.CreateRoleRequest{
		ID:          testRoleID,
		DisplayName: "Notes reader",
	})
	require.NoError(t, err)
	require.NoError(t, store.GrantRoleAction(ctx, authkit.GrantRoleActionRequest{
		RoleID: testRoleID,
		Action: testAction,
	}))
	require.NoError(t, store.AssignPrincipalRole(ctx, authkit.AssignPrincipalRoleRequest{
		PrincipalID: principal.ID,
		RoleID:      testRoleID,
	}))
	issuer, verifier := authtest.NewAccessJWTIssuerAndVerifier(t)
	issued, err := issuer.IssueToken(ctx, accessjwt.IssueRequest{
		PrincipalID: principal.ID,
	})
	require.NoError(t, err)
	authenticator, err := accessjwtauth.NewAuthenticator(verifier, store)
	require.NoError(t, err)
	authorizer, err := roleauth.NewAuthorizer(store)
	require.NoError(t, err)
	pipeline, err := authkit.NewPipeline(authkit.PipelineOptions{
		PrincipalAuthenticators: []authkit.PrincipalAuthenticator{authenticator},
		Authorizer:              authorizer,
	})
	require.NoError(t, err)
	middleware, err := httpauth.NewMiddleware(pipeline)
	require.NoError(t, err)
	handler := middleware.RequireFunc(testAction, func(req *http.Request) (authkit.Resource, error) {
		return authkit.Resource{
			Type: "note",
			ID:   req.PathValue("noteID"),
		}, nil
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	mux := http.NewServeMux()
	mux.Handle("GET /notes/{noteID}", handler)
	req := httptest.NewRequest(http.MethodGet, "/notes/42", nil)
	req.Header.Set("Authorization", "Bearer "+issued.Plaintext)

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusNoContent, recorder.Code)
}

type fakeActionResolver struct {
	actions  []string
	requests []string
	err      error
}

func (f *fakeActionResolver) ResolvePrincipalActions(
	_ context.Context,
	principalID string,
) ([]string, error) {
	f.requests = append(f.requests, principalID)
	if f.err != nil {
		return nil, f.err
	}

	return f.actions, nil
}

func testCheck() authkit.AuthorizationCheck {
	return authkit.AuthorizationCheck{
		Principal: testPrincipal(),
		Action:    testAction,
	}
}

func testPrincipal() authkit.Principal {
	return authkit.Principal{
		ID:          testPrincipalID,
		Kind:        authkit.PrincipalKindUser,
		DisplayName: "Ada Lovelace",
	}
}
