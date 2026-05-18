package authflow

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/httpauth"
	"github.com/meigma/authkit/oidc"
	"github.com/meigma/authkit/store/memory"
)

func TestRuntimeExchangesSeedAPITokenForAccessJWT(t *testing.T) {
	runtime := newTestRuntime(t)

	result, err := runtime.ExchangeAPIToken(context.Background(), runtime.SeedAPIToken)
	require.NoError(t, err)

	assert.Equal(t, runtime.Principal.ID, result.Principal.ID)
	assert.Equal(t, runtime.Principal.ID, result.AccessToken.PrincipalID)
	assert.Equal(t, fixedTime().Add(AccessTokenTTL), result.AccessToken.ExpiresAt)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", bearer(result.AccessToken.Plaintext))
	runtime.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		principal, ok := httpauth.PrincipalFromContext(req.Context())
		assert.True(t, ok)
		if ok {
			assert.Equal(t, runtime.Principal.ID, principal.ID)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusNoContent, recorder.Code)
}

func TestRuntimeRejectsDirectAPITokenAsProtectedBearer(t *testing.T) {
	runtime := newTestRuntime(t)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", bearer(runtime.SeedAPIToken))
	runtime.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusSeeOther, recorder.Code)
	assert.Equal(t, LoginPath, recorder.Header().Get("Location"))
	assert.Equal(t, -1, findSetCookie(t, recorder, CookieName).MaxAge)
}

func TestRuntimeAuthorizesPasteActions(t *testing.T) {
	runtime := newTestRuntime(t)
	result, err := runtime.ExchangeAPIToken(context.Background(), runtime.SeedAPIToken)
	require.NoError(t, err)
	authentication := authkit.Authentication{
		AuthenticatorName: "test",
		Principal:         result.Principal,
	}

	tests := []struct {
		name      string
		request   authkit.AuthorizationRequest
		assertErr func(*testing.T, error)
	}{
		{
			name: "create",
			request: authkit.AuthorizationRequest{
				Action:   ActionPasteCreate,
				Resource: pasteResource(),
			},
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
		{
			name: "owner update",
			request: authkit.AuthorizationRequest{
				Action:   ActionPasteUpdate,
				Resource: pasteResource(),
				Facts: authkit.Facts{
					PasteOwnerPrincipalIDFact: result.Principal.ID,
				},
			},
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
		{
			name: "owner delete",
			request: authkit.AuthorizationRequest{
				Action:   ActionPasteDelete,
				Resource: pasteResource(),
				Facts: authkit.Facts{
					PasteOwnerPrincipalIDFact: result.Principal.ID,
				},
			},
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
		{
			name: "non-owner update",
			request: authkit.AuthorizationRequest{
				Action:   ActionPasteUpdate,
				Resource: pasteResource(),
				Facts: authkit.Facts{
					PasteOwnerPrincipalIDFact: "principal-other",
				},
			},
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, authkit.ErrUnauthorized)
			},
		},
		{
			name: "missing owner fact",
			request: authkit.AuthorizationRequest{
				Action:   ActionPasteDelete,
				Resource: pasteResource(),
			},
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, authkit.ErrUnauthorized)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := runtime.AuthorizeAuthenticated(context.Background(), authentication, tt.request)

			tt.assertErr(t, err)
		})
	}
}

func TestRuntimeRejectsInvalidAPITokenExchange(t *testing.T) {
	runtime := newTestRuntime(t)

	_, err := runtime.ExchangeAPIToken(context.Background(), "invalid")

	require.ErrorIs(t, err, authkit.ErrUnauthenticated)
}

func TestRuntimeExchangesOIDCTokenForAccessJWT(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	issuer := newTestIssuer(t)
	provider := issuer.provider()
	provider.ForwardedClaims = []authkit.ClaimPath{{"email"}, {"name"}}
	_, err := store.TrustProvider(ctx, provider)
	require.NoError(t, err)
	runtime, err := NewRuntime(
		ctx,
		store,
		WithClock(fixedTime),
		WithOIDCOptions(oidc.WithHTTPClient(issuer.server.Client())),
	)
	require.NoError(t, err)
	token := issuer.sign(t, oidcTokenRequest{
		subject:   "user-123",
		audiences: []string{testAudience},
		expiresAt: fixedTime().Add(time.Hour),
		claims: map[string]any{
			"email": "ada@example.test",
			"name":  "Ada Lovelace",
		},
	})

	result, err := runtime.ExchangeOIDCToken(ctx, token)
	require.NoError(t, err)

	assert.Equal(t, issuer.issuer, result.Identity.Provider)
	assert.Equal(t, "user-123", result.Identity.Subject)
	assert.Equal(t, "Ada Lovelace", result.Principal.DisplayName)
	assert.Equal(t, "ada@example.test", result.Principal.Attributes["email"])
	assert.Equal(t, result.Principal.ID, result.AccessToken.PrincipalID)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", bearer(result.AccessToken.Plaintext))
	runtime.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		principal, ok := httpauth.PrincipalFromContext(req.Context())
		assert.True(t, ok)
		if ok {
			assert.Equal(t, result.Principal.ID, principal.ID)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusNoContent, recorder.Code)
}

func TestRuntimeRejectsDirectOIDCTokenAsProtectedBearer(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	issuer := newTestIssuer(t)
	_, err := store.TrustProvider(ctx, issuer.provider())
	require.NoError(t, err)
	runtime, err := NewRuntime(
		ctx,
		store,
		WithClock(fixedTime),
		WithOIDCOptions(oidc.WithHTTPClient(issuer.server.Client())),
	)
	require.NoError(t, err)
	token := issuer.sign(t, oidcTokenRequest{
		subject:   "user-123",
		audiences: []string{testAudience},
		expiresAt: fixedTime().Add(time.Hour),
	})

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", bearer(token))
	runtime.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusSeeOther, recorder.Code)
	assert.Equal(t, LoginPath, recorder.Header().Get("Location"))
	assert.Equal(t, -1, findSetCookie(t, recorder, CookieName).MaxAge)
}

func TestRuntimeReusesBootstrapPrincipal(t *testing.T) {
	store := memory.NewStore()
	first, err := NewRuntime(context.Background(), store, WithClock(fixedTime))
	require.NoError(t, err)
	second, err := NewRuntime(context.Background(), store, WithClock(fixedTime))
	require.NoError(t, err)

	assert.Equal(t, first.Principal.ID, second.Principal.ID)
	principals, err := store.ListPrincipals(context.Background())
	require.NoError(t, err)
	assert.Len(t, principals, 1)
}

func newTestRuntime(t *testing.T) *Runtime {
	t.Helper()

	runtime, err := NewRuntime(context.Background(), memory.NewStore(), WithClock(fixedTime))
	require.NoError(t, err)

	return runtime
}

func findSetCookie(t *testing.T, recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()

	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	require.Failf(t, "missing cookie", "cookie %q was not set", name)

	return nil
}

func bearer(token string) string {
	return "Bearer " + token
}

func pasteResource() authkit.Resource {
	return authkit.Resource{
		Type: "paste",
		ID:   "paste-1",
	}
}

func fixedTime() time.Time {
	return time.Date(2026, time.May, 14, 10, 0, 0, 0, time.UTC)
}

const testAudience = "testkit"

type testIssuer struct {
	server     *httptest.Server
	issuer     string
	jwksURL    string
	signingKey jwk.Key
	publicSet  jwk.Set
}

type oidcTokenRequest struct {
	subject   string
	audiences []string
	expiresAt time.Time
	claims    map[string]any
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()

	rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signingKey, err := jwk.Import(rawKey)
	require.NoError(t, err)
	require.NoError(t, signingKey.Set(jwk.KeyIDKey, "test-key"))
	require.NoError(t, signingKey.Set(jwk.AlgorithmKey, jwa.RS256()))

	privateSet := jwk.NewSet()
	require.NoError(t, privateSet.AddKey(signingKey))
	publicSet, err := jwk.PublicSetOf(privateSet)
	require.NoError(t, err)

	issuer := &testIssuer{
		signingKey: signingKey,
		publicSet:  publicSet,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(issuer.publicSet); err != nil {
			t.Errorf("encode JWKS: %v", err)
		}
	})
	issuer.server = httptest.NewTLSServer(mux)
	t.Cleanup(issuer.server.Close)
	issuer.issuer = issuer.server.URL
	issuer.jwksURL = issuer.server.URL + "/jwks"

	return issuer
}

func (i *testIssuer) provider() oidc.Provider {
	return oidc.Provider{
		Issuer:    i.issuer,
		Audiences: []string{testAudience},
		JWKSURL:   i.jwksURL,
	}
}

func (i *testIssuer) sign(t *testing.T, req oidcTokenRequest) string {
	t.Helper()

	builder := jwt.NewBuilder().
		Issuer(i.issuer).
		Subject(req.subject).
		Audience(req.audiences).
		IssuedAt(fixedTime().Add(-time.Minute)).
		Expiration(req.expiresAt)
	for name, value := range req.claims {
		builder.Claim(name, value)
	}

	token, err := builder.Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), i.signingKey))
	require.NoError(t, err)

	return string(signed)
}
