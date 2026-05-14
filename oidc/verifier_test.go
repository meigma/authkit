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
	authkitoidc "github.com/meigma/authkit/oidc"
)

const (
	testAudience = "authkit-api"
	testSubject  = "user-123"
)

func TestNewVerifierValidatesDependencies(t *testing.T) {
	verifier, err := authkitoidc.NewVerifier(nil)

	require.Error(t, err)
	assert.Nil(t, verifier)
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

func TestVerifierVerifiesValidJWTBearerToken(t *testing.T) {
	now := fixedTime()
	issuer := newTestIssuer(t)
	verifier := issuer.verifier(t, authkitoidc.WithClock(func() time.Time {
		return now
	}))
	token := issuer.sign(t, tokenRequest{
		subject:   testSubject,
		audiences: []string{testAudience},
		expiresAt: now.Add(time.Hour),
		jwtID:     "jwt-123",
	})

	identity, err := verifier.VerifyToken(context.Background(), token)

	require.NoError(t, err)
	assert.Equal(t, authkit.Identity{
		Provider:     issuer.issuer,
		Subject:      testSubject,
		CredentialID: "jwt-123",
	}, identity)
}

func TestVerifierRejectsMissingToken(t *testing.T) {
	now := fixedTime()
	issuer := newTestIssuer(t)
	verifier := issuer.verifier(t, authkitoidc.WithClock(func() time.Time {
		return now
	}))

	identity, err := verifier.VerifyToken(context.Background(), "")

	require.ErrorIs(t, err, authkit.ErrUnauthenticated)
	assert.Empty(t, identity)
}

func TestVerifierForwardsSelectedVerifiedClaims(t *testing.T) {
	now := fixedTime()
	issuer := newTestIssuer(t)
	verifier := issuer.verifier(
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

	identity, err := verifier.VerifyToken(context.Background(), token)

	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"email": "ada@example.com",
		"scope": "notes:read notes:write",
	}, identity.Claims)
}

func TestVerifierForwardsProviderConfiguredClaims(t *testing.T) {
	now := fixedTime()
	issuer := newTestIssuer(t)
	provider := issuer.provider()
	provider.ForwardedClaims = []authkit.ClaimPath{
		{"groups"},
		{"realm_access", "roles"},
	}
	verifier := newVerifier(
		t,
		provider,
		authkitoidc.WithHTTPClient(issuer.server.Client()),
		authkitoidc.WithClock(func() time.Time {
			return now
		}),
	)
	token := issuer.sign(t, tokenRequest{
		subject:   testSubject,
		audiences: []string{testAudience},
		expiresAt: now.Add(time.Hour),
		claims: map[string]any{
			"groups": []string{"/engineering"},
			"realm_access": map[string]any{
				"roles": []string{"writer"},
				"other": "not forwarded",
			},
			"department": "not-forwarded",
		},
	})

	identity, err := verifier.VerifyToken(context.Background(), token)

	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"groups": []any{"/engineering"},
		"realm_access": map[string]any{
			"roles": []any{"writer"},
		},
	}, identity.Claims)
}

func TestVerifierRejectsMalformedToken(t *testing.T) {
	now := fixedTime()
	issuer := newTestIssuer(t)
	verifier := issuer.verifier(t, authkitoidc.WithClock(func() time.Time {
		return now
	}))

	tests := []struct {
		name  string
		token string
	}{
		{name: "missing"},
		{name: "non JWT bearer token", token: "ak_token_secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := verifier.VerifyToken(context.Background(), tt.token)

			require.ErrorIs(t, err, authkit.ErrUnauthenticated)
			assert.Empty(t, identity)
		})
	}
}

func TestVerifierRejectsInvalidTokens(t *testing.T) {
	now := fixedTime()
	issuer := newTestIssuer(t)
	otherIssuer := newTestIssuer(t)
	verifier := issuer.verifier(t, authkitoidc.WithClock(func() time.Time {
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
			identity, err := verifier.VerifyToken(context.Background(), tt.token)

			require.ErrorIs(t, err, authkit.ErrUnauthenticated)
			assert.Empty(t, identity)
		})
	}
}

func TestVerifierAcceptsJWKsMarkedForVerification(t *testing.T) {
	now := fixedTime()
	issuer := newTestIssuerWithPublicKey(t, func(t *testing.T, key jwk.Key) {
		t.Helper()
		require.NoError(t, key.Set(jwk.KeyUsageKey, jwk.ForSignature))
		require.NoError(t, key.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpVerify}))
	})
	verifier := issuer.verifier(t, authkitoidc.WithClock(func() time.Time {
		return now
	}))
	token := issuer.sign(t, tokenRequest{
		subject:   testSubject,
		audiences: []string{testAudience},
		expiresAt: now.Add(time.Hour),
	})

	identity, err := verifier.VerifyToken(context.Background(), token)

	require.NoError(t, err)
	assert.Equal(t, testSubject, identity.Subject)
}

func TestVerifierRejectsJWKsNotUsableForVerification(t *testing.T) {
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
			verifier := issuer.verifier(t, authkitoidc.WithClock(func() time.Time {
				return now
			}))
			token := issuer.sign(t, tokenRequest{
				subject:   testSubject,
				audiences: []string{testAudience},
				expiresAt: now.Add(time.Hour),
			})

			identity, err := verifier.VerifyToken(context.Background(), token)

			require.Error(t, err)
			assert.Empty(t, identity)
		})
	}
}

func TestVerifierReturnsOperationalErrorsForProviderAndJWKSSourceFailures(t *testing.T) {
	now := fixedTime()
	issuer := newTestIssuer(t)
	sourceErr := errors.New("source unavailable")
	sourceFailingVerifier, err := authkitoidc.NewVerifier(
		failingProviderSource{err: sourceErr},
		authkitoidc.WithClock(func() time.Time {
			return now
		}),
	)
	require.NoError(t, err)
	jwksFailingVerifier := newVerifier(
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

	identity, err := sourceFailingVerifier.VerifyToken(context.Background(), token)
	require.ErrorIs(t, err, sourceErr)
	require.NotErrorIs(t, err, authkit.ErrUnauthenticated)
	assert.Empty(t, identity)

	identity, err = jwksFailingVerifier.VerifyToken(context.Background(), token)
	require.Error(t, err)
	require.NotErrorIs(t, err, authkit.ErrUnauthenticated)
	assert.Empty(t, identity)
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

func (i *testIssuer) verifier(t *testing.T, opts ...authkitoidc.Option) *authkitoidc.Verifier {
	t.Helper()

	opts = append([]authkitoidc.Option{authkitoidc.WithHTTPClient(i.server.Client())}, opts...)

	return newVerifier(t, i.provider(), opts...)
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

func newVerifier(
	t *testing.T,
	provider authkitoidc.Provider,
	opts ...authkitoidc.Option,
) *authkitoidc.Verifier {
	t.Helper()

	source, err := authkitoidc.NewStaticProviderSource(provider)
	require.NoError(t, err)
	verifier, err := authkitoidc.NewVerifier(source, opts...)
	require.NoError(t, err)

	return verifier
}

func fixedTime() time.Time {
	return time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
}
