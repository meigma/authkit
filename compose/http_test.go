package compose_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/accessjwt"
	"github.com/meigma/authkit/apikey"
	"github.com/meigma/authkit/compose"
	"github.com/meigma/authkit/httpauth"
	"github.com/meigma/authkit/oidc"
	"github.com/meigma/authkit/store/memory"
)

func TestNewHTTPValidatesInputs(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name    string
		options compose.HTTPOptions
		want    string
		wantIs  error
	}{
		{
			name: "requires at least one authenticator",
			options: compose.HTTPOptions{
				Resolver:   testResolver{},
				Authorizer: testAuthorizer{},
			},
			want: "compose: at least one authenticator is required",
		},
		{
			name: "rejects nil authenticator spec",
			options: compose.HTTPOptions{
				Authenticators: []compose.AuthenticatorSpec{nil},
				Resolver:       testResolver{},
				Authorizer:     testAuthorizer{},
			},
			want: "compose: authenticator spec 0 is required",
		},
		{
			name: "rejects nil principal authenticator spec",
			options: compose.HTTPOptions{
				PrincipalAuthenticators: []compose.PrincipalAuthenticatorSpec{nil},
				Authorizer:              testAuthorizer{},
			},
			want: "compose: principal authenticator spec 0 is required",
		},
		{
			name: "wraps authenticator build errors",
			options: compose.HTTPOptions{
				Authenticators: []compose.AuthenticatorSpec{
					authenticatorSpecFunc(func() (authkit.Authenticator, error) {
						return nil, boom
					}),
				},
				Resolver:   testResolver{},
				Authorizer: testAuthorizer{},
			},
			want:   "compose: build authenticator 0: boom",
			wantIs: boom,
		},
		{
			name: "wraps principal authenticator build errors",
			options: compose.HTTPOptions{
				PrincipalAuthenticators: []compose.PrincipalAuthenticatorSpec{
					principalAuthenticatorSpecFunc(func() (authkit.PrincipalAuthenticator, error) {
						return nil, boom
					}),
				},
				Authorizer: testAuthorizer{},
			},
			want:   "compose: build principal authenticator 0: boom",
			wantIs: boom,
		},
		{
			name: "rejects nil built authenticator",
			options: compose.HTTPOptions{
				Authenticators: []compose.AuthenticatorSpec{
					authenticatorSpecFunc(func() (authkit.Authenticator, error) {
						var authenticator authkit.Authenticator

						return authenticator, nil
					}),
				},
				Resolver:   testResolver{},
				Authorizer: testAuthorizer{},
			},
			want: "compose: authenticator 0 built nil authenticator",
		},
		{
			name: "rejects nil built principal authenticator",
			options: compose.HTTPOptions{
				PrincipalAuthenticators: []compose.PrincipalAuthenticatorSpec{
					principalAuthenticatorSpecFunc(func() (authkit.PrincipalAuthenticator, error) {
						var authenticator authkit.PrincipalAuthenticator

						return authenticator, nil
					}),
				},
				Authorizer: testAuthorizer{},
			},
			want: "compose: principal authenticator 0 built nil authenticator",
		},
		{
			name: "wraps missing resolver error",
			options: compose.HTTPOptions{
				Authenticators: []compose.AuthenticatorSpec{compose.Existing(newTestAuthenticator("test"))},
				Authorizer:     testAuthorizer{},
			},
			want: "compose: create pipeline: authkit: principal resolver is required",
		},
		{
			name: "wraps missing authorizer error",
			options: compose.HTTPOptions{
				Authenticators: []compose.AuthenticatorSpec{compose.Existing(newTestAuthenticator("test"))},
				Resolver:       testResolver{},
			},
			want: "compose: create pipeline: authkit: authorizer is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := compose.NewHTTP(tt.options)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			if tt.wantIs != nil {
				assert.ErrorIs(t, err, tt.wantIs)
			}
		})
	}
}

func TestNewHTTPWithAccessJWTDoesNotRequireResolver(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	principal, err := store.CreatePrincipal(ctx, authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindService,
		DisplayName: "notes service",
	})
	require.NoError(t, err)
	issuer, verifier := newAccessJWTIssuerAndVerifier(t)
	issued, err := issuer.IssueToken(ctx, accessjwt.IssueRequest{
		PrincipalID: principal.ID,
	})
	require.NoError(t, err)
	kit, err := compose.NewHTTP(compose.HTTPOptions{
		PrincipalAuthenticators: []compose.PrincipalAuthenticatorSpec{
			compose.AccessJWT(verifier, store),
		},
		Authorizer: testAuthorizer{},
	})
	require.NoError(t, err)

	authentication, err := kit.Pipeline.Authenticate(ctx, requestWithBearer(issued.Plaintext))

	require.NoError(t, err)
	assert.Empty(t, authentication.Identity)
	assert.Equal(t, principal.ID, authentication.Principal.ID)
}

func TestNewHTTPPreservesAuthenticatorOrder(t *testing.T) {
	first := newTestAuthenticator("first")
	second := newTestAuthenticator("second")
	kit, err := compose.NewHTTP(compose.HTTPOptions{
		Authenticators: []compose.AuthenticatorSpec{
			compose.Existing(first),
			compose.Existing(second),
		},
		Resolver:   testResolver{},
		Authorizer: testAuthorizer{},
	})
	require.NoError(t, err)

	authentication, err := kit.Pipeline.Authenticate(context.Background(), requestWithBearer("token"))

	require.NoError(t, err)
	assert.Equal(t, "first", authentication.AuthenticatorName)
	assert.Equal(t, "principal_first", authentication.Principal.ID)
	assert.Equal(t, 1, first.calls)
	assert.Zero(t, second.calls)
}

func TestNewHTTPReturnsUsableMiddleware(t *testing.T) {
	kit, err := compose.NewHTTP(compose.HTTPOptions{
		Authenticators: []compose.AuthenticatorSpec{
			compose.Existing(newTestAuthenticator("test")),
		},
		Resolver:   testResolver{},
		Authorizer: testAuthorizer{},
	})
	require.NoError(t, err)

	var principal authkit.Principal
	var ok bool
	handler := kit.Middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		principal, ok = httpauth.PrincipalFromContext(req.Context())

		_, _ = w.Write([]byte(principal.ID))
	}))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, requestWithBearer("token"))

	assert.Equal(t, http.StatusOK, recorder.Code)
	require.True(t, ok)
	assert.Equal(t, "principal_test", recorder.Body.String())
}

func TestNewHTTPAppliesMiddlewareOptions(t *testing.T) {
	kit, err := compose.NewHTTP(compose.HTTPOptions{
		Authenticators: []compose.AuthenticatorSpec{
			compose.Existing(newTestAuthenticator("test")),
		},
		Resolver:   testResolver{},
		Authorizer: testAuthorizer{},
		MiddlewareOptions: []httpauth.Option{
			httpauth.WithErrorRenderer(func(w http.ResponseWriter, _ *http.Request, _ error) {
				http.Error(w, "custom auth error", http.StatusTeapot)
			}),
		},
	})
	require.NoError(t, err)

	handler := kit.Middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusTeapot, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "custom auth error")
}

func TestAPITokenSpecBuildsUsableAuthenticator(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	principal, err := store.CreatePrincipal(ctx, authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindService,
		DisplayName: "test service",
	})
	require.NoError(t, err)
	tokenService, err := apikey.NewService(store)
	require.NoError(t, err)
	issued, err := tokenService.IssueToken(ctx, apikey.IssueRequest{
		PrincipalID: principal.ID,
		Name:        "test token",
		ExpiresAt:   time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	_, err = store.LinkIdentity(ctx, issued.IdentityLink)
	require.NoError(t, err)
	kit, err := compose.NewHTTP(compose.HTTPOptions{
		Authenticators: []compose.AuthenticatorSpec{
			compose.APIToken(tokenService),
		},
		Resolver:   store,
		Authorizer: testAuthorizer{},
	})
	require.NoError(t, err)

	authentication, err := kit.Pipeline.Authenticate(ctx, requestWithBearer(issued.Plaintext))

	require.NoError(t, err)
	assert.Equal(t, apikey.Provider, authentication.Identity.Provider)
	assert.Equal(t, principal.ID, authentication.Principal.ID)
}

func TestOIDCSpecBuildsAuthenticator(t *testing.T) {
	source, err := oidc.NewStaticProviderSource()
	require.NoError(t, err)
	kit, err := compose.NewHTTP(compose.HTTPOptions{
		Authenticators: []compose.AuthenticatorSpec{
			compose.OIDC(source),
		},
		Resolver:   testResolver{},
		Authorizer: testAuthorizer{},
	})
	require.NoError(t, err)

	_, err = kit.Pipeline.Authenticate(context.Background(), httptest.NewRequest(http.MethodGet, "/", nil))

	require.ErrorIs(t, err, authkit.ErrUnauthenticated)
}

func TestHelperSpecsWrapConstructorErrors(t *testing.T) {
	tests := []struct {
		name string
		spec compose.AuthenticatorSpec
		want string
	}{
		{
			name: "API token service is required",
			spec: compose.APIToken(nil),
			want: "compose: build authenticator 0: apikey: service is required",
		},
		{
			name: "OIDC provider source is required",
			spec: compose.OIDC(nil),
			want: "compose: build authenticator 0: oidc: provider source is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := compose.NewHTTP(compose.HTTPOptions{
				Authenticators: []compose.AuthenticatorSpec{tt.spec},
				Resolver:       testResolver{},
				Authorizer:     testAuthorizer{},
			})

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestAccessJWTSpecWrapsConstructorErrors(t *testing.T) {
	_, verifier := newAccessJWTIssuerAndVerifier(t)
	store := memory.NewStore()

	tests := []struct {
		name string
		spec compose.PrincipalAuthenticatorSpec
		want string
	}{
		{
			name: "verifier is required",
			spec: compose.AccessJWT(nil, store),
			want: "compose: build principal authenticator 0: accessjwtauth: verifier is required",
		},
		{
			name: "principal finder is required",
			spec: compose.AccessJWT(verifier, nil),
			want: "compose: build principal authenticator 0: accessjwtauth: principal finder is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := compose.NewHTTP(compose.HTTPOptions{
				PrincipalAuthenticators: []compose.PrincipalAuthenticatorSpec{tt.spec},
				Authorizer:              testAuthorizer{},
			})

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

type authenticatorSpecFunc func() (authkit.Authenticator, error)

func (f authenticatorSpecFunc) BuildAuthenticator() (authkit.Authenticator, error) {
	return f()
}

type principalAuthenticatorSpecFunc func() (authkit.PrincipalAuthenticator, error)

func (f principalAuthenticatorSpecFunc) BuildPrincipalAuthenticator() (authkit.PrincipalAuthenticator, error) {
	return f()
}

type testAuthenticator struct {
	name     string
	identity authkit.Identity
	calls    int
}

func newTestAuthenticator(name string) *testAuthenticator {
	return &testAuthenticator{
		name: name,
		identity: authkit.Identity{
			Provider: name,
			Subject:  "subject",
		},
	}
}

func (a *testAuthenticator) Name() string {
	return a.name
}

func (a *testAuthenticator) Authenticate(_ context.Context, req *http.Request) (*authkit.Identity, error) {
	a.calls++
	if req.Header.Get("Authorization") == "" {
		return nil, authkit.ErrUnauthenticated
	}

	identity := a.identity

	return &identity, nil
}

type testResolver struct{}

func (r testResolver) ResolveIdentity(
	_ context.Context,
	identity authkit.Identity,
) (*authkit.Principal, error) {
	return &authkit.Principal{
		ID:   "principal_" + identity.Provider,
		Kind: authkit.PrincipalKindService,
	}, nil
}

type testAuthorizer struct{}

func (a testAuthorizer) Can(_ context.Context, _ authkit.AuthorizationCheck) (authkit.Decision, error) {
	return authkit.Decision{Allowed: true}, nil
}

func requestWithBearer(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	return req
}

func newAccessJWTIssuerAndVerifier(t *testing.T) (*accessjwt.Issuer, *accessjwt.Verifier) {
	t.Helper()

	rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privateKey, err := jwk.Import(rawKey)
	require.NoError(t, err)
	require.NoError(t, privateKey.Set(jwk.KeyIDKey, "test-key"))
	require.NoError(t, privateKey.Set(jwk.AlgorithmKey, jwa.RS256()))
	publicKey, err := jwk.PublicKeyOf(privateKey)
	require.NoError(t, err)
	keySet := jwk.NewSet()
	require.NoError(t, keySet.AddKey(publicKey))

	issuer, err := accessjwt.NewIssuer(accessjwt.IssuerOptions{
		Issuer:     "https://auth.example.test",
		Audience:   "notes-api",
		TTL:        time.Hour,
		SigningKey: privateKey,
		Clock: func() time.Time {
			return time.Date(2026, time.May, 13, 22, 0, 0, 0, time.UTC)
		},
	})
	require.NoError(t, err)
	verifier, err := accessjwt.NewVerifier(accessjwt.VerifierOptions{
		Issuer:   "https://auth.example.test",
		Audience: "notes-api",
		KeySet:   keySet,
		Clock: func() time.Time {
			return time.Date(2026, time.May, 13, 22, 0, 0, 0, time.UTC)
		},
	})
	require.NoError(t, err)

	return issuer, verifier
}
