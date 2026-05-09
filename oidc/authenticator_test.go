package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
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
	authkitoidc "github.com/meigma/authkit/oidc"
	"github.com/meigma/authkit/provisioning"
	"github.com/meigma/authkit/store/memory"
)

const (
	testAudience = "authkit-api"
	testSubject  = "user-123"
)

func TestNewAuthenticatorValidatesDependencies(t *testing.T) {
	authenticator, err := authkitoidc.NewAuthenticator(nil)

	require.Error(t, err)
	assert.Nil(t, authenticator)
}

func TestProviderValidation(t *testing.T) {
	tests := []struct {
		name     string
		provider authkitoidc.Provider
	}{
		{
			name: "missing issuer",
			provider: authkitoidc.Provider{
				Audiences: []string{testAudience},
				JWKSURL:   "https://issuer.example/jwks",
			},
		},
		{
			name: "missing audience",
			provider: authkitoidc.Provider{
				Issuer:  "https://issuer.example",
				JWKSURL: "https://issuer.example/jwks",
			},
		},
		{
			name: "missing JWKS URL",
			provider: authkitoidc.Provider{
				Issuer:    "https://issuer.example",
				Audiences: []string{testAudience},
			},
		},
		{
			name: "insecure issuer",
			provider: authkitoidc.Provider{
				Issuer:    "http://issuer.example",
				Audiences: []string{testAudience},
				JWKSURL:   "https://issuer.example/jwks",
			},
		},
		{
			name: "relative issuer",
			provider: authkitoidc.Provider{
				Issuer:    "/issuer",
				Audiences: []string{testAudience},
				JWKSURL:   "https://issuer.example/jwks",
			},
		},
		{
			name: "insecure JWKS URL",
			provider: authkitoidc.Provider{
				Issuer:    "https://issuer.example",
				Audiences: []string{testAudience},
				JWKSURL:   "http://issuer.example/jwks",
			},
		},
		{
			name: "symmetric algorithm",
			provider: authkitoidc.Provider{
				Issuer:                     "https://issuer.example",
				Audiences:                  []string{testAudience},
				JWKSURL:                    "https://issuer.example/jwks",
				SupportedSigningAlgorithms: []string{"HS256"},
			},
		},
		{
			name: "unknown algorithm",
			provider: authkitoidc.Provider{
				Issuer:                     "https://issuer.example",
				Audiences:                  []string{testAudience},
				JWKSURL:                    "https://issuer.example/jwks",
				SupportedSigningAlgorithms: []string{"unknown"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.provider.Validate()

			require.Error(t, err)
		})
	}
}

func TestStaticProviderSourceFindsProvidersByIssuer(t *testing.T) {
	source, err := authkitoidc.NewStaticProviderSource(authkitoidc.Provider{
		Issuer:                     "https://issuer.example",
		Audiences:                  []string{testAudience},
		JWKSURL:                    "https://issuer.example/jwks",
		SupportedSigningAlgorithms: []string{"RS256"},
	})
	require.NoError(t, err)

	provider, err := source.FindProvider(context.Background(), "https://issuer.example")
	require.NoError(t, err)
	assert.Equal(t, "https://issuer.example", provider.Issuer)

	provider.Audiences[0] = "mutated"
	provider, err = source.FindProvider(context.Background(), "https://issuer.example")
	require.NoError(t, err)
	assert.Equal(t, []string{testAudience}, provider.Audiences)
}

func TestStaticProviderSourceRejectsDuplicateIssuers(t *testing.T) {
	provider := authkitoidc.Provider{
		Issuer:    "https://issuer.example",
		Audiences: []string{testAudience},
		JWKSURL:   "https://issuer.example/jwks",
	}

	source, err := authkitoidc.NewStaticProviderSource(provider, provider)

	require.Error(t, err)
	assert.Nil(t, source)
}

func TestStaticProviderSourceReturnsProviderNotFound(t *testing.T) {
	source, err := authkitoidc.NewStaticProviderSource()
	require.NoError(t, err)

	provider, err := source.FindProvider(context.Background(), "https://issuer.example")

	require.ErrorIs(t, err, authkitoidc.ErrProviderNotFound)
	assert.Empty(t, provider)
}

func TestAuthenticatorAuthenticatesValidJWTBearerToken(t *testing.T) {
	now := fixedTime()
	issuer := newTestIssuer(t)
	authenticator := issuer.authenticator(t, authkitoidc.WithClock(func() time.Time {
		return now
	}))
	token := issuer.sign(t, tokenRequest{
		subject:   testSubject,
		audiences: []string{testAudience},
		expiresAt: now.Add(time.Hour),
		jwtID:     "jwt-123",
	})
	req := bearerRequest(token)

	identity, err := authenticator.Authenticate(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, &authkit.Identity{
		Provider:     issuer.issuer,
		Subject:      testSubject,
		CredentialID: "jwt-123",
	}, identity)
}

func TestAuthenticatorForwardsSelectedVerifiedClaims(t *testing.T) {
	now := fixedTime()
	issuer := newTestIssuer(t)
	authenticator := issuer.authenticator(
		t,
		authkitoidc.WithClock(func() time.Time {
			return now
		}),
		authkitoidc.WithForwardedClaims("email", "scope", "missing"),
	)
	token := issuer.sign(t, tokenRequest{
		subject:   testSubject,
		audiences: []string{testAudience},
		expiresAt: now.Add(time.Hour),
		claims: map[string]any{
			"email": "ada@example.com",
			"scope": "notes:read notes:write",
		},
	})

	identity, err := authenticator.Authenticate(context.Background(), bearerRequest(token))

	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"email": "ada@example.com",
		"scope": "notes:read notes:write",
	}, identity.Claims)
}

func TestAuthenticatorRejectsInvalidHeaders(t *testing.T) {
	now := fixedTime()
	issuer := newTestIssuer(t)
	authenticator := issuer.authenticator(t, authkitoidc.WithClock(func() time.Time {
		return now
	}))

	tests := []struct {
		name   string
		header string
	}{
		{name: "missing"},
		{name: "wrong scheme", header: "Basic token"},
		{name: "empty bearer", header: "Bearer "},
		{name: "extra fields", header: "Bearer token extra"},
		{name: "non JWT bearer token", header: "Bearer ak_token_secret"},
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

func TestAuthenticatorRejectsInvalidTokens(t *testing.T) {
	now := fixedTime()
	issuer := newTestIssuer(t)
	otherIssuer := newTestIssuer(t)
	authenticator := issuer.authenticator(t, authkitoidc.WithClock(func() time.Time {
		return now
	}))

	futureNotBefore := now.Add(time.Minute)
	tests := []struct {
		name  string
		token string
	}{
		{
			name: "wrong issuer",
			token: issuer.sign(t, tokenRequest{
				issuer:    "https://untrusted.example",
				subject:   testSubject,
				audiences: []string{testAudience},
				expiresAt: now.Add(time.Hour),
			}),
		},
		{
			name: "wrong audience",
			token: issuer.sign(t, tokenRequest{
				subject:   testSubject,
				audiences: []string{"other-api"},
				expiresAt: now.Add(time.Hour),
			}),
		},
		{
			name: "bad signature",
			token: otherIssuer.sign(t, tokenRequest{
				issuer:    issuer.issuer,
				subject:   testSubject,
				audiences: []string{testAudience},
				expiresAt: now.Add(time.Hour),
			}),
		},
		{
			name: "expired",
			token: issuer.sign(t, tokenRequest{
				subject:   testSubject,
				audiences: []string{testAudience},
				expiresAt: now.Add(-time.Minute),
			}),
		},
		{
			name: "not yet valid",
			token: issuer.sign(t, tokenRequest{
				subject:   testSubject,
				audiences: []string{testAudience},
				expiresAt: now.Add(time.Hour),
				notBefore: &futureNotBefore,
			}),
		},
		{
			name: "missing subject",
			token: issuer.sign(t, tokenRequest{
				audiences: []string{testAudience},
				expiresAt: now.Add(time.Hour),
			}),
		},
		{
			name: "missing expiration",
			token: issuer.sign(t, tokenRequest{
				subject:   testSubject,
				audiences: []string{testAudience},
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := authenticator.Authenticate(context.Background(), bearerRequest(tt.token))

			require.ErrorIs(t, err, authkit.ErrUnauthenticated)
			assert.Nil(t, identity)
		})
	}
}

func TestAuthenticatorAcceptsJWKsMarkedForVerification(t *testing.T) {
	now := fixedTime()
	issuer := newTestIssuerWithPublicKey(t, func(t *testing.T, key jwk.Key) {
		t.Helper()
		require.NoError(t, key.Set(jwk.KeyUsageKey, jwk.ForSignature))
		require.NoError(t, key.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpVerify}))
	})
	authenticator := issuer.authenticator(t, authkitoidc.WithClock(func() time.Time {
		return now
	}))
	token := issuer.sign(t, tokenRequest{
		subject:   testSubject,
		audiences: []string{testAudience},
		expiresAt: now.Add(time.Hour),
	})

	identity, err := authenticator.Authenticate(context.Background(), bearerRequest(token))

	require.NoError(t, err)
	assert.Equal(t, testSubject, identity.Subject)
}

func TestAuthenticatorRejectsJWKsNotUsableForVerification(t *testing.T) {
	now := fixedTime()
	tests := []struct {
		name      string
		configure func(*testing.T, jwk.Key)
	}{
		{
			name: "encryption use",
			configure: func(t *testing.T, key jwk.Key) {
				t.Helper()
				require.NoError(t, key.Set(jwk.KeyUsageKey, jwk.ForEncryption))
			},
		},
		{
			name: "key operations without verify",
			configure: func(t *testing.T, key jwk.Key) {
				t.Helper()
				require.NoError(t, key.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpSign}))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := newTestIssuerWithPublicKey(t, tt.configure)
			authenticator := issuer.authenticator(t, authkitoidc.WithClock(func() time.Time {
				return now
			}))
			token := issuer.sign(t, tokenRequest{
				subject:   testSubject,
				audiences: []string{testAudience},
				expiresAt: now.Add(time.Hour),
			})

			identity, err := authenticator.Authenticate(context.Background(), bearerRequest(token))

			require.Error(t, err)
			assert.Nil(t, identity)
		})
	}
}

func TestAuthenticatorReturnsOperationalErrorsForProviderAndJWKSSourceFailures(t *testing.T) {
	now := fixedTime()
	issuer := newTestIssuer(t)
	sourceErr := errors.New("source unavailable")
	sourceFailingAuthenticator, err := authkitoidc.NewAuthenticator(
		failingProviderSource{err: sourceErr},
		authkitoidc.WithClock(func() time.Time {
			return now
		}),
	)
	require.NoError(t, err)
	jwksFailingAuthenticator := newAuthenticator(
		t,
		authkitoidc.Provider{
			Issuer:    issuer.issuer,
			Audiences: []string{testAudience},
			JWKSURL:   issuer.server.URL + "/unavailable",
		},
		authkitoidc.WithHTTPClient(issuer.server.Client()),
		authkitoidc.WithClock(func() time.Time {
			return now
		}),
	)
	token := issuer.sign(t, tokenRequest{
		subject:   testSubject,
		audiences: []string{testAudience},
		expiresAt: now.Add(time.Hour),
	})

	identity, err := sourceFailingAuthenticator.Authenticate(context.Background(), bearerRequest(token))
	require.ErrorIs(t, err, sourceErr)
	require.NotErrorIs(t, err, authkit.ErrUnauthenticated)
	assert.Nil(t, identity)

	identity, err = jwksFailingAuthenticator.Authenticate(context.Background(), bearerRequest(token))
	require.Error(t, err)
	require.NotErrorIs(t, err, authkit.ErrUnauthenticated)
	assert.Nil(t, identity)
}

func TestOIDCIdentityResolvesThroughPipeline(t *testing.T) {
	now := fixedTime()
	issuer := newTestIssuer(t)
	store := memory.NewStore()
	principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindUser,
		DisplayName: "Ada Lovelace",
	})
	require.NoError(t, err)
	_, err = store.LinkIdentity(context.Background(), authkit.LinkIdentityRequest{
		Provider:    issuer.issuer,
		Subject:     testSubject,
		PrincipalID: principal.ID,
	})
	require.NoError(t, err)
	authenticator := issuer.authenticator(t, authkitoidc.WithClock(func() time.Time {
		return now
	}))
	pipeline := newPipeline(t, authenticator, store)
	token := issuer.sign(t, tokenRequest{
		subject:   testSubject,
		audiences: []string{testAudience},
		expiresAt: now.Add(time.Hour),
	})

	authentication, err := pipeline.Authenticate(context.Background(), bearerRequest(token))

	require.NoError(t, err)
	assert.Equal(t, authkitoidc.Name, authentication.AuthenticatorName)
	assert.Equal(t, issuer.issuer, authentication.Identity.Provider)
	assert.Equal(t, testSubject, authentication.Identity.Subject)
	assert.Equal(t, principal, authentication.Principal)
}

func TestValidUnlinkedOIDCIdentityReturnsUnresolvedIdentity(t *testing.T) {
	now := fixedTime()
	issuer := newTestIssuer(t)
	store := memory.NewStore()
	authenticator := issuer.authenticator(t, authkitoidc.WithClock(func() time.Time {
		return now
	}))
	pipeline := newPipeline(t, authenticator, store)
	token := issuer.sign(t, tokenRequest{
		subject:   testSubject,
		audiences: []string{testAudience},
		expiresAt: now.Add(time.Hour),
	})

	authentication, err := pipeline.Authenticate(context.Background(), bearerRequest(token))

	require.ErrorIs(t, err, authkit.ErrUnresolvedIdentity)
	assert.Equal(t, issuer.issuer, authentication.Identity.Provider)
	assert.Equal(t, testSubject, authentication.Identity.Subject)
	assert.Empty(t, authentication.Principal)
}

func TestOIDCIdentityAutoProvisionsThroughResolver(t *testing.T) {
	now := fixedTime()
	issuer := newTestIssuer(t)
	store := memory.NewStore()
	authenticator := issuer.authenticator(
		t,
		authkitoidc.WithClock(func() time.Time {
			return now
		}),
		authkitoidc.WithForwardedClaims("email", "name"),
	)
	resolver, err := provisioning.NewResolver(provisioning.ResolverOptions{
		Resolver:    store,
		Provisioner: store,
		Factory: func(_ context.Context, identity authkit.Identity) (authkit.CreatePrincipalRequest, bool, error) {
			if identity.Provider != issuer.issuer {
				return authkit.CreatePrincipalRequest{}, false, nil
			}

			displayName := stringClaim(identity.Claims, "name")
			if displayName == "" {
				displayName = stringClaim(identity.Claims, "email")
			}
			if displayName == "" {
				displayName = identity.Subject
			}

			return authkit.CreatePrincipalRequest{
				Kind:        authkit.PrincipalKindUser,
				DisplayName: displayName,
				Attributes: map[string]any{
					"email": stringClaim(identity.Claims, "email"),
				},
			}, true, nil
		},
	})
	require.NoError(t, err)
	pipeline := newPipeline(t, authenticator, resolver)
	token := issuer.sign(t, tokenRequest{
		subject:   testSubject,
		audiences: []string{testAudience},
		expiresAt: now.Add(time.Hour),
		claims: map[string]any{
			"email": "ada@example.test",
			"name":  "Ada Lovelace",
		},
	})

	first, err := pipeline.Authenticate(context.Background(), bearerRequest(token))
	require.NoError(t, err)
	second, err := pipeline.Authenticate(context.Background(), bearerRequest(token))
	require.NoError(t, err)

	assert.Equal(t, authkitoidc.Name, first.AuthenticatorName)
	assert.Equal(t, issuer.issuer, first.Identity.Provider)
	assert.Equal(t, testSubject, first.Identity.Subject)
	assert.Equal(t, map[string]any{
		"email": "ada@example.test",
		"name":  "Ada Lovelace",
	}, first.Identity.Claims)
	assert.Equal(t, authkit.PrincipalKindUser, first.Principal.Kind)
	assert.Equal(t, "Ada Lovelace", first.Principal.DisplayName)
	assert.Equal(t, "ada@example.test", first.Principal.Attributes["email"])
	assert.Equal(t, first.Principal, second.Principal)

	resolved, err := store.ResolveIdentity(context.Background(), first.Identity)
	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, first.Principal, *resolved)

	deniedPipeline, err := authkit.NewPipeline(authkit.PipelineOptions{
		Authenticators: []authkit.Authenticator{authenticator},
		Resolver:       resolver,
		Authorizer:     denyAuthorizer{},
	})
	require.NoError(t, err)
	middleware, err := httpauth.NewMiddleware(deniedPipeline)
	require.NoError(t, err)
	handler := middleware.Require("note:read", authkit.Resource{Type: "note", ID: "allowed"})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	)
	req := bearerRequest(token)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusForbidden, recorder.Code)
}

type failingProviderSource struct {
	err error
}

func (s failingProviderSource) FindProvider(context.Context, string) (authkitoidc.Provider, error) {
	return authkitoidc.Provider{}, s.err
}

type testIssuer struct {
	server     *httptest.Server
	issuer     string
	jwksURL    string
	signingKey jwk.Key
	publicSet  jwk.Set
}

type tokenRequest struct {
	issuer    string
	subject   string
	audiences []string
	expiresAt time.Time
	notBefore *time.Time
	jwtID     string
	claims    map[string]any
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()

	return newTestIssuerWithPublicKey(t, nil)
}

func newTestIssuerWithPublicKey(t *testing.T, configure func(*testing.T, jwk.Key)) *testIssuer {
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
	if configure != nil {
		publicKey, ok := publicSet.Key(0)
		require.True(t, ok)
		configure(t, publicKey)
	}

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
	mux.HandleFunc("/unavailable", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	})
	issuer.server = httptest.NewTLSServer(mux)
	t.Cleanup(issuer.server.Close)
	issuer.issuer = issuer.server.URL
	issuer.jwksURL = issuer.server.URL + "/jwks"

	return issuer
}

func (i *testIssuer) provider() authkitoidc.Provider {
	return authkitoidc.Provider{
		Issuer:    i.issuer,
		Audiences: []string{testAudience},
		JWKSURL:   i.jwksURL,
	}
}

func (i *testIssuer) authenticator(t *testing.T, opts ...authkitoidc.Option) *authkitoidc.Authenticator {
	t.Helper()

	opts = append([]authkitoidc.Option{authkitoidc.WithHTTPClient(i.server.Client())}, opts...)

	return newAuthenticator(t, i.provider(), opts...)
}

func (i *testIssuer) sign(t *testing.T, req tokenRequest) string {
	t.Helper()

	issuer := req.issuer
	if issuer == "" {
		issuer = i.issuer
	}
	builder := jwt.NewBuilder().
		Issuer(issuer).
		Audience(req.audiences).
		IssuedAt(fixedTime().Add(-time.Minute))
	if req.subject != "" {
		builder.Subject(req.subject)
	}
	if !req.expiresAt.IsZero() {
		builder.Expiration(req.expiresAt)
	}
	if req.notBefore != nil {
		builder.NotBefore(*req.notBefore)
	}
	if req.jwtID != "" {
		builder.JwtID(req.jwtID)
	}
	for name, value := range req.claims {
		builder.Claim(name, value)
	}

	token, err := builder.Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), i.signingKey))
	require.NoError(t, err)

	return string(signed)
}

func newAuthenticator(
	t *testing.T,
	provider authkitoidc.Provider,
	opts ...authkitoidc.Option,
) *authkitoidc.Authenticator {
	t.Helper()

	source, err := authkitoidc.NewStaticProviderSource(provider)
	require.NoError(t, err)
	authenticator, err := authkitoidc.NewAuthenticator(source, opts...)
	require.NoError(t, err)

	return authenticator
}

func newPipeline(
	t *testing.T,
	authenticator authkit.Authenticator,
	resolver authkit.PrincipalResolver,
) *authkit.Pipeline {
	t.Helper()

	pipeline, err := authkit.NewPipeline(authkit.PipelineOptions{
		Authenticators: []authkit.Authenticator{authenticator},
		Resolver:       resolver,
		Authorizer:     allowAuthorizer{},
	})
	require.NoError(t, err)

	return pipeline
}

type allowAuthorizer struct{}

func (allowAuthorizer) Can(context.Context, authkit.Principal, string, authkit.Resource) (authkit.Decision, error) {
	return authkit.Decision{Allowed: true}, nil
}

type denyAuthorizer struct{}

func (denyAuthorizer) Can(context.Context, authkit.Principal, string, authkit.Resource) (authkit.Decision, error) {
	return authkit.Decision{Allowed: false, Reason: "policy denied"}, nil
}

func bearerRequest(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	return req
}

func fixedTime() time.Time {
	return time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
}

func stringClaim(claims map[string]any, name string) string {
	value, _ := claims[name].(string)

	return value
}
