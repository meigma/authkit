package main

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
	"github.com/meigma/authkit/oidc"
	"github.com/meigma/authkit/testkit/internal/authflow"
)

func TestOIDCProviderFromEnv(t *testing.T) {
	tests := []struct {
		name      string
		env       map[string]string
		assertion func(*testing.T, *oidc.Provider, error)
	}{
		{
			name: "disabled without issuer",
			env: map[string]string{
				oidcJWKSURLEnv:   "https://issuer.example/jwks",
				oidcAudiencesEnv: "testkit",
			},
			assertion: func(t *testing.T, provider *oidc.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Nil(t, provider)
			},
		},
		{
			name: "issuer requires JWKS URL",
			env: map[string]string{
				oidcIssuerEnv:    "https://issuer.example",
				oidcAudiencesEnv: "testkit",
			},
			assertion: func(t *testing.T, _ *oidc.Provider, err error) {
				t.Helper()
				require.Error(t, err)
				require.ErrorContains(t, err, oidcJWKSURLEnv)
			},
		},
		{
			name: "issuer requires audiences",
			env: map[string]string{
				oidcIssuerEnv:  "https://issuer.example",
				oidcJWKSURLEnv: "https://issuer.example/jwks",
			},
			assertion: func(t *testing.T, _ *oidc.Provider, err error) {
				t.Helper()
				require.Error(t, err)
				require.ErrorContains(t, err, oidcAudiencesEnv)
			},
		},
		{
			name: "trims comma-separated values",
			env: map[string]string{
				oidcIssuerEnv:            " https://issuer.example ",
				oidcJWKSURLEnv:           " https://issuer.example/jwks ",
				oidcAudiencesEnv:         " testkit, admin ",
				oidcForwardedClaimsEnv:   " email, name, realm_access.roles ",
				oidcSigningAlgorithmsEnv: " RS256, ES256 ",
			},
			assertion: func(t *testing.T, provider *oidc.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, provider)
				assert.Equal(t, "https://issuer.example", provider.Issuer)
				assert.Equal(t, "https://issuer.example/jwks", provider.JWKSURL)
				assert.Equal(t, []string{"testkit", "admin"}, provider.Audiences)
				assert.Equal(t, []string{"RS256", "ES256"}, provider.SupportedSigningAlgorithms)
				assert.Equal(t, []authkit.ClaimPath{
					{"email"},
					{"name"},
					{"realm_access", "roles"},
				}, provider.ForwardedClaims)
			},
		},
		{
			name: "rejects empty audience items",
			env: map[string]string{
				oidcIssuerEnv:    "https://issuer.example",
				oidcJWKSURLEnv:   "https://issuer.example/jwks",
				oidcAudiencesEnv: "testkit,,admin",
			},
			assertion: func(t *testing.T, _ *oidc.Provider, err error) {
				t.Helper()
				require.Error(t, err)
				require.ErrorContains(t, err, oidcAudiencesEnv)
				require.ErrorContains(t, err, "item 2")
			},
		},
		{
			name: "rejects invalid forwarded claim paths",
			env: map[string]string{
				oidcIssuerEnv:          "https://issuer.example",
				oidcJWKSURLEnv:         "https://issuer.example/jwks",
				oidcAudiencesEnv:       "testkit",
				oidcForwardedClaimsEnv: "email,realm_access..roles",
			},
			assertion: func(t *testing.T, _ *oidc.Provider, err error) {
				t.Helper()
				require.Error(t, err)
				require.ErrorContains(t, err, oidcForwardedClaimsEnv)
				require.ErrorContains(t, err, "realm_access..roles")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, configured, err := oidcProviderFromEnv(mapGetenv(tt.env))
			var providerPtr *oidc.Provider
			if configured {
				providerPtr = &provider
			}

			tt.assertion(t, providerPtr, err)
		})
	}
}

func TestNewStoresTrustsConfiguredOIDCProvider(t *testing.T) {
	ctx := context.Background()
	issuer := newTestIssuer(t)
	t.Setenv(oidcIssuerEnv, issuer.issuer)
	t.Setenv(oidcJWKSURLEnv, issuer.jwksURL)
	t.Setenv(oidcAudiencesEnv, testAudience)
	t.Setenv(oidcForwardedClaimsEnv, "email,name")

	stores, cleanup, err := newStores(ctx)
	require.NoError(t, err)
	t.Cleanup(cleanup)

	provider, err := stores.auth.FindProvider(ctx, issuer.issuer)
	require.NoError(t, err)
	assert.Equal(t, []authkit.ClaimPath{{"email"}, {"name"}}, provider.ForwardedClaims)

	runtime, err := authflow.NewRuntime(
		ctx,
		stores.auth,
		authflow.WithClock(fixedTime),
		authflow.WithOIDCOptions(oidc.WithHTTPClient(issuer.server.Client())),
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
}

func mapGetenv(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

func fixedTime() time.Time {
	return time.Date(2026, time.May, 17, 10, 0, 0, 0, time.UTC)
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
