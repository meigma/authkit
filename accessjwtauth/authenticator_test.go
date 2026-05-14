package accessjwtauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	"github.com/meigma/authkit/accessjwtauth"
	"github.com/meigma/authkit/store/memory"
)

const (
	testIssuer      = "https://auth.example.test"
	testAudience    = "notes-api"
	testKeyID       = "key-1"
	testPrincipalID = "principal_1"
	testTokenID     = "token-123"
)

func TestNewAuthenticatorValidatesDependencies(t *testing.T) {
	_, verifier := newIssuerAndVerifier(t)
	store := memory.NewStore()

	tests := []struct {
		name            string
		verifier        *accessjwt.Verifier
		principalFinder authkit.PrincipalFinder
	}{
		{
			name:            "missing verifier",
			principalFinder: store,
		},
		{
			name:     "missing principal finder",
			verifier: verifier,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authenticator, err := accessjwtauth.NewAuthenticator(tt.verifier, tt.principalFinder)

			require.Error(t, err)
			assert.Nil(t, authenticator)
		})
	}
}

func TestAuthenticatorAuthenticatesAccessJWT(t *testing.T) {
	issuer, verifier := newIssuerAndVerifier(t)
	store := memory.NewStore()
	principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindService,
		DisplayName: "notes service",
	})
	require.NoError(t, err)
	authenticator, err := accessjwtauth.NewAuthenticator(verifier, store)
	require.NoError(t, err)
	issued, err := issuer.IssueToken(context.Background(), accessjwt.IssueRequest{
		PrincipalID: principal.ID,
	})
	require.NoError(t, err)
	req := requestWithBearer(issued.Plaintext)

	authentication, err := authenticator.AuthenticatePrincipal(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, accessjwtauth.Name, authenticator.Name())
	require.NotNil(t, authentication)
	assert.Equal(t, principal, authentication.Principal)
}

func TestAuthenticatorRejectsInvalidRequests(t *testing.T) {
	privateKey, publicKey := newRSAKeyPair(t)
	issuer := newIssuer(t, privateKey, fixedTime(), nil)
	verifier := newVerifier(t, publicKey)
	store := memory.NewStore()
	principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindService,
		DisplayName: "notes service",
	})
	require.NoError(t, err)
	valid, err := issuer.IssueToken(context.Background(), accessjwt.IssueRequest{
		PrincipalID: principal.ID,
	})
	require.NoError(t, err)
	expiredIssuer := newIssuer(t, privateKey, fixedTime().Add(-2*time.Hour), nil)
	expired, err := expiredIssuer.IssueToken(context.Background(), accessjwt.IssueRequest{
		PrincipalID: principal.ID,
	})
	require.NoError(t, err)
	wrongIssuer := newIssuer(t, privateKey, fixedTime(), func(opts *accessjwt.IssuerOptions) {
		opts.Issuer = "https://other.example.test"
	})
	wrongIssuerToken, err := wrongIssuer.IssueToken(context.Background(), accessjwt.IssueRequest{
		PrincipalID: principal.ID,
	})
	require.NoError(t, err)
	wrongAudience := newIssuer(t, privateKey, fixedTime(), func(opts *accessjwt.IssuerOptions) {
		opts.Audience = "other-api"
	})
	wrongAudienceToken, err := wrongAudience.IssueToken(context.Background(), accessjwt.IssueRequest{
		PrincipalID: principal.ID,
	})
	require.NoError(t, err)
	missingPrincipal, err := issuer.IssueToken(context.Background(), accessjwt.IssueRequest{
		PrincipalID: "missing",
	})
	require.NoError(t, err)
	authenticator, err := accessjwtauth.NewAuthenticator(verifier, store)
	require.NoError(t, err)

	tests := []struct {
		name string
		req  *http.Request
	}{
		{name: "missing bearer", req: httptest.NewRequest(http.MethodGet, "/", nil)},
		{name: "malformed bearer", req: requestWithAuthorization("Basic " + valid.Plaintext)},
		{name: "invalid JWT", req: requestWithBearer("not-a-jwt")},
		{name: "expired JWT", req: requestWithBearer(expired.Plaintext)},
		{name: "wrong issuer", req: requestWithBearer(wrongIssuerToken.Plaintext)},
		{name: "wrong audience", req: requestWithBearer(wrongAudienceToken.Plaintext)},
		{name: "missing principal", req: requestWithBearer(missingPrincipal.Plaintext)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authentication, err := authenticator.AuthenticatePrincipal(context.Background(), tt.req)

			require.ErrorIs(t, err, authkit.ErrUnauthenticated)
			assert.Nil(t, authentication)
		})
	}
}

func newIssuerAndVerifier(t *testing.T) (*accessjwt.Issuer, *accessjwt.Verifier) {
	t.Helper()

	privateKey, publicKey := newRSAKeyPair(t)
	return newIssuer(t, privateKey, fixedTime(), nil), newVerifier(t, publicKey)
}

func newIssuer(
	t *testing.T,
	privateKey jwk.Key,
	now time.Time,
	mutate func(*accessjwt.IssuerOptions),
) *accessjwt.Issuer {
	t.Helper()

	issuerOpts := accessjwt.IssuerOptions{
		Issuer:     testIssuer,
		Audience:   testAudience,
		TTL:        time.Hour,
		SigningKey: privateKey,
		Clock: func() time.Time {
			return now
		},
		TokenID: func() (string, error) {
			return testTokenID, nil
		},
	}
	if mutate != nil {
		mutate(&issuerOpts)
	}
	issuer, err := accessjwt.NewIssuer(issuerOpts)
	require.NoError(t, err)

	return issuer
}

func newVerifier(t *testing.T, publicKey jwk.Key) *accessjwt.Verifier {
	t.Helper()

	keySet := jwk.NewSet()
	require.NoError(t, keySet.AddKey(publicKey))
	verifier, err := accessjwt.NewVerifier(accessjwt.VerifierOptions{
		Issuer:   testIssuer,
		Audience: testAudience,
		KeySet:   keySet,
		Clock:    fixedTime,
	})
	require.NoError(t, err)

	return verifier
}

func newRSAKeyPair(t *testing.T) (jwk.Key, jwk.Key) {
	t.Helper()

	rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privateKey, err := jwk.Import(rawKey)
	require.NoError(t, err)
	require.NoError(t, privateKey.Set(jwk.KeyIDKey, testKeyID))
	require.NoError(t, privateKey.Set(jwk.AlgorithmKey, jwa.RS256()))
	publicKey, err := jwk.PublicKeyOf(privateKey)
	require.NoError(t, err)

	return privateKey, publicKey
}

func requestWithBearer(token string) *http.Request {
	return requestWithAuthorization("Bearer " + token)
}

func requestWithAuthorization(header string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", header)

	return req
}

func fixedTime() time.Time {
	return time.Date(2026, time.May, 13, 22, 0, 0, 0, time.UTC)
}
