package accessjwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/roleauth"
	"github.com/meigma/authkit/store/memory"
)

const (
	testIssuer      = "https://auth.example.test"
	testAudience    = "notes-api"
	testPrincipalID = "principal_1"
	testTokenID     = "token-123"
	testAction      = "note:read"
	testRoleID      = "reader"
	testKeyID       = "key-1"
	rsaKeyBits      = 2048
)

func TestIssuerRejectsInvalidOptions(t *testing.T) {
	privateKey, _ := newRSAKeyPair(t)

	tests := []struct {
		name string
		opts IssuerOptions
	}{
		{
			name: "missing issuer",
			opts: issuerOptions(privateKey, func(opts *IssuerOptions) {
				opts.Issuer = ""
			}),
		},
		{
			name: "missing audience",
			opts: issuerOptions(privateKey, func(opts *IssuerOptions) {
				opts.Audience = ""
			}),
		},
		{
			name: "missing signing key",
			opts: issuerOptions(privateKey, func(opts *IssuerOptions) {
				opts.SigningKey = nil
			}),
		},
		{
			name: "non-positive TTL",
			opts: issuerOptions(privateKey, func(opts *IssuerOptions) {
				opts.TTL = 0
			}),
		},
		{
			name: "signing key without kid",
			opts: issuerOptions(newRSAKey(t, "", DefaultAlgorithm), nil),
		},
		{
			name: "none algorithm",
			opts: issuerOptions(privateKey, func(opts *IssuerOptions) {
				opts.Algorithm = jwa.NoSignature().String()
			}),
		},
		{
			name: "symmetric algorithm",
			opts: issuerOptions(privateKey, func(opts *IssuerOptions) {
				opts.Algorithm = jwa.HS256().String()
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer, err := NewIssuer(tt.opts)

			require.Error(t, err)
			assert.Nil(t, issuer)
		})
	}
}

func TestVerifierRejectsInvalidOptions(t *testing.T) {
	_, publicKey := newRSAKeyPair(t)
	keySet := newKeySet(t, publicKey)

	tests := []struct {
		name string
		opts VerifierOptions
	}{
		{
			name: "missing issuer",
			opts: verifierOptions(keySet, func(opts *VerifierOptions) {
				opts.Issuer = ""
			}),
		},
		{
			name: "missing audience",
			opts: verifierOptions(keySet, func(opts *VerifierOptions) {
				opts.Audience = ""
			}),
		},
		{
			name: "missing key set",
			opts: verifierOptions(keySet, func(opts *VerifierOptions) {
				opts.KeySet = nil
			}),
		},
		{
			name: "negative skew",
			opts: verifierOptions(keySet, func(opts *VerifierOptions) {
				opts.AcceptableSkew = -time.Second
			}),
		},
		{
			name: "empty algorithm entry",
			opts: verifierOptions(keySet, func(opts *VerifierOptions) {
				opts.AllowedAlgorithms = []string{""}
			}),
		},
		{
			name: "unsupported algorithm",
			opts: verifierOptions(keySet, func(opts *VerifierOptions) {
				opts.AllowedAlgorithms = []string{"unsupported"}
			}),
		},
		{
			name: "symmetric algorithm",
			opts: verifierOptions(keySet, func(opts *VerifierOptions) {
				opts.AllowedAlgorithms = []string{jwa.HS256().String()}
			}),
		},
		{
			name: "key without kid",
			opts: verifierOptions(newKeySet(t, newRSAKey(t, "", DefaultAlgorithm)), nil),
		},
		{
			name: "key without algorithm",
			opts: verifierOptions(newKeySet(t, newRSAKey(t, testKeyID, "")), nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := NewVerifier(tt.opts)

			require.Error(t, err)
			assert.Nil(t, verifier)
		})
	}
}

func TestIssueAndVerifyToken(t *testing.T) {
	issuer, verifier, keySet := newIssuerAndVerifier(t)

	issued, err := issuer.IssueToken(context.Background(), IssueRequest{
		PrincipalID: testPrincipalID,
	})
	require.NoError(t, err)

	assert.Equal(t, testTokenID, issued.ID)
	assert.Equal(t, testPrincipalID, issued.PrincipalID)
	assert.Equal(t, fixedTime(), issued.IssuedAt)
	assert.Equal(t, fixedTime().Add(time.Hour), issued.ExpiresAt)
	assert.NotEmpty(t, issued.Plaintext)
	assertProtectedHeader(t, issued.Plaintext, TokenType, DefaultAlgorithm, testKeyID)
	assertNoAuthorizationClaims(t, issued.Plaintext, keySet)

	verified, err := verifier.VerifyToken(context.Background(), issued.Plaintext)
	require.NoError(t, err)

	assert.Equal(t, testTokenID, verified.ID)
	assert.Equal(t, testPrincipalID, verified.PrincipalID)
	assert.Equal(t, testIssuer, verified.Issuer)
	assert.Equal(t, testAudience, verified.Audience)
	assert.Equal(t, fixedTime(), verified.IssuedAt)
	assert.Equal(t, fixedTime().Add(time.Hour), verified.ExpiresAt)
}

func TestIssueTokenRejectsInvalidRequest(t *testing.T) {
	issuer, _, _ := newIssuerAndVerifier(t)

	issued, err := issuer.IssueToken(context.Background(), IssueRequest{})

	require.Error(t, err)
	assert.Empty(t, issued)
}

func TestIssueTokenRejectsEmptyGeneratedTokenID(t *testing.T) {
	privateKey, _ := newRSAKeyPair(t)
	issuer, err := NewIssuer(issuerOptions(privateKey, func(opts *IssuerOptions) {
		opts.TokenID = func() (string, error) {
			return "", nil
		}
	}))
	require.NoError(t, err)

	issued, err := issuer.IssueToken(context.Background(), IssueRequest{
		PrincipalID: testPrincipalID,
	})

	require.Error(t, err)
	assert.Empty(t, issued)
}

func TestVerifyTokenRejectsInvalidTokens(t *testing.T) {
	_, verifier, _ := newIssuerAndVerifier(t)
	wrongIssuer := issueTokenWithOptions(t, func(opts *IssuerOptions) {
		opts.Issuer = "https://other.example.test"
	})
	wrongAudience := issueTokenWithOptions(t, func(opts *IssuerOptions) {
		opts.Audience = "other-api"
	})
	expired := issueTokenWithClock(t, fixedTime().Add(-2*time.Hour))

	tests := []struct {
		name  string
		token string
	}{
		{name: "malformed token", token: "not-a-jwt"},
		{name: "wrong signature", token: issueWithWrongSignature(t)},
		{name: "wrong kid", token: issueWithWrongKeyID(t)},
		{name: "wrong issuer", token: wrongIssuer},
		{name: "wrong audience", token: wrongAudience},
		{name: "expired token", token: expired},
		{name: "missing subject", token: signToken(t, nil, TokenType, DefaultAlgorithm, testKeyID)},
		{name: "wrong typ", token: signToken(t, baseClaims(), "JWT", DefaultAlgorithm, testKeyID)},
		{name: "missing typ", token: signTokenWithoutType(t, baseClaims())},
		{name: "none algorithm", token: unsignedToken(t, baseClaims())},
		{name: "algorithm confusion", token: hmacSignedToken(t, baseClaims())},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verified, err := verifier.VerifyToken(context.Background(), tt.token)

			require.Error(t, err)
			require.ErrorIs(t, err, authkit.ErrUnauthenticated)
			assert.Empty(t, verified)
		})
	}
}

func TestVerifiedTokenUsesStorageBackedAuthorization(t *testing.T) {
	issuer, verifier, _ := newIssuerAndVerifier(t)
	store := memory.NewStore()
	principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindService,
		DisplayName: "publisher",
	})
	require.NoError(t, err)
	_, err = store.CreateRole(context.Background(), authkit.CreateRoleRequest{
		ID:          testRoleID,
		DisplayName: "Reader",
	})
	require.NoError(t, err)
	require.NoError(t, store.GrantRoleAction(context.Background(), authkit.GrantRoleActionRequest{
		RoleID: testRoleID,
		Action: testAction,
	}))
	require.NoError(t, store.AssignPrincipalRole(context.Background(), authkit.AssignPrincipalRoleRequest{
		PrincipalID: principal.ID,
		RoleID:      testRoleID,
	}))

	issued, err := issuer.IssueToken(context.Background(), IssueRequest{
		PrincipalID: principal.ID,
	})
	require.NoError(t, err)
	verified, err := verifier.VerifyToken(context.Background(), issued.Plaintext)
	require.NoError(t, err)
	loaded, err := store.FindPrincipal(context.Background(), verified.PrincipalID)
	require.NoError(t, err)

	authorizer, err := roleauth.NewAuthorizer(store)
	require.NoError(t, err)
	decision, err := authorizer.Can(context.Background(), authkit.AuthorizationCheck{
		Principal: loaded,
		Action:    testAction,
		Resource:  authkit.Resource{Type: "note", ID: "note-1"},
	})

	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func newIssuerAndVerifier(t *testing.T) (*Issuer, *Verifier, jwk.Set) {
	t.Helper()

	privateKey, publicKey := newRSAKeyPair(t)
	keySet := newKeySet(t, publicKey)
	issuer, err := NewIssuer(issuerOptions(privateKey, nil))
	require.NoError(t, err)
	verifier, err := NewVerifier(verifierOptions(keySet, nil))
	require.NoError(t, err)

	return issuer, verifier, keySet
}

func issuerOptions(signingKey jwk.Key, mutate func(*IssuerOptions)) IssuerOptions {
	opts := IssuerOptions{
		Issuer:     testIssuer,
		Audience:   testAudience,
		TTL:        time.Hour,
		SigningKey: signingKey,
		Clock:      fixedTime,
		TokenID: func() (string, error) {
			return testTokenID, nil
		},
	}
	if mutate != nil {
		mutate(&opts)
	}

	return opts
}

func verifierOptions(keySet jwk.Set, mutate func(*VerifierOptions)) VerifierOptions {
	opts := VerifierOptions{
		Issuer:   testIssuer,
		Audience: testAudience,
		KeySet:   keySet,
		Clock:    fixedTime,
	}
	if mutate != nil {
		mutate(&opts)
	}

	return opts
}

func issueToken(t *testing.T, issuer *Issuer) IssuedToken {
	t.Helper()

	issued, err := issuer.IssueToken(context.Background(), IssueRequest{
		PrincipalID: testPrincipalID,
	})
	require.NoError(t, err)

	return issued
}

func issueTokenWithOptions(t *testing.T, mutate func(*IssuerOptions)) string {
	t.Helper()

	privateKey, _ := newRSAKeyPair(t)
	issuer, err := NewIssuer(issuerOptions(privateKey, mutate))
	require.NoError(t, err)

	return issueToken(t, issuer).Plaintext
}

func issueTokenWithClock(t *testing.T, now time.Time) string {
	t.Helper()

	return issueTokenWithOptions(t, func(opts *IssuerOptions) {
		opts.Clock = func() time.Time {
			return now
		}
	})
}

func issueWithWrongSignature(t *testing.T) string {
	t.Helper()

	privateKey, _ := newRSAKeyPair(t)
	issuer, err := NewIssuer(issuerOptions(privateKey, nil))
	require.NoError(t, err)

	return issueToken(t, issuer).Plaintext
}

func issueWithWrongKeyID(t *testing.T) string {
	t.Helper()

	return issueTokenWithOptions(t, func(opts *IssuerOptions) {
		opts.SigningKey = newRSAKey(t, "other-key", DefaultAlgorithm)
	})
}

func signToken(
	t *testing.T,
	claims map[string]any,
	tokenType string,
	algorithmName string,
	keyID string,
) string {
	t.Helper()

	key := newRSAKey(t, keyID, algorithmName)
	algorithm, err := signatureAlgorithm(algorithmName)
	require.NoError(t, err)
	token := jwt.New()
	for name, value := range claims {
		require.NoError(t, token.Set(name, value))
	}
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, tokenType))
	signed, err := jwt.Sign(token, jwt.WithKey(algorithm, key, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)

	return string(signed)
}

func signTokenWithoutType(t *testing.T, claims map[string]any) string {
	t.Helper()

	token := jwt.New()
	for name, value := range claims {
		require.NoError(t, token.Set(name, value))
	}
	payload, err := json.Marshal(token)
	require.NoError(t, err)

	key := newRSAKey(t, testKeyID, DefaultAlgorithm)
	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), key))
	require.NoError(t, err)

	return string(signed)
}

func unsignedToken(t *testing.T, claims map[string]any) string {
	t.Helper()

	header := map[string]any{
		jws.AlgorithmKey: jwa.NoSignature().String(),
		jws.TypeKey:      TokenType,
	}
	headerBytes, err := json.Marshal(header)
	require.NoError(t, err)
	payloadBytes, err := json.Marshal(claims)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payloadBytes) + "."
}

func hmacSignedToken(t *testing.T, claims map[string]any) string {
	t.Helper()

	key, err := jwk.Import([]byte("secret"))
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, testKeyID))
	token := jwt.New()
	for name, value := range claims {
		require.NoError(t, token.Set(name, value))
	}
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, TokenType))
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)

	return string(signed)
}

func baseClaims() map[string]any {
	now := fixedTime()

	return map[string]any{
		jwt.IssuerKey:     testIssuer,
		jwt.SubjectKey:    testPrincipalID,
		jwt.AudienceKey:   []string{testAudience},
		jwt.IssuedAtKey:   now,
		jwt.ExpirationKey: now.Add(time.Hour),
		jwt.JwtIDKey:      testTokenID,
	}
}

func assertProtectedHeader(t *testing.T, plaintext string, tokenType string, algorithm string, keyID string) {
	t.Helper()

	message, err := jws.Parse([]byte(plaintext), jws.WithCompact())
	require.NoError(t, err)
	require.Len(t, message.Signatures(), 1)
	headers := message.Signatures()[0].ProtectedHeaders()
	require.NotNil(t, headers)

	gotType, ok := headers.Type()
	require.True(t, ok)
	assert.Equal(t, tokenType, gotType)
	gotAlgorithm, ok := headers.Algorithm()
	require.True(t, ok)
	assert.Equal(t, algorithm, gotAlgorithm.String())
	gotKeyID, ok := headers.KeyID()
	require.True(t, ok)
	assert.Equal(t, keyID, gotKeyID)
}

func assertNoAuthorizationClaims(t *testing.T, plaintext string, keySet jwk.Set) {
	t.Helper()

	token, err := jwt.Parse(
		[]byte(plaintext),
		jwt.WithKeySet(keySet),
		jwt.WithIssuer(testIssuer),
		jwt.WithAudience(testAudience),
		jwt.WithClock(jwt.ClockFunc(fixedTime)),
	)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		jwt.AudienceKey,
		jwt.ExpirationKey,
		jwt.IssuedAtKey,
		jwt.IssuerKey,
		jwt.JwtIDKey,
		jwt.SubjectKey,
	}, token.Keys())
	assert.False(t, token.Has("roles"))
	assert.False(t, token.Has("permissions"))
	assert.False(t, token.Has("actions"))
}

func newRSAKeyPair(t *testing.T) (jwk.Key, jwk.Key) {
	t.Helper()

	privateKey := newRSAKey(t, testKeyID, DefaultAlgorithm)
	publicKey, err := jwk.PublicKeyOf(privateKey)
	require.NoError(t, err)

	return privateKey, publicKey
}

func newRSAKey(t *testing.T, keyID string, algorithm string) jwk.Key {
	t.Helper()

	rawKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	require.NoError(t, err)
	key, err := jwk.Import(rawKey)
	require.NoError(t, err)
	if keyID != "" {
		require.NoError(t, key.Set(jwk.KeyIDKey, keyID))
	}
	if algorithm != "" {
		require.NoError(t, key.Set(jwk.AlgorithmKey, algorithm))
	}

	return key
}

func newKeySet(t *testing.T, key jwk.Key) jwk.Set {
	t.Helper()

	keySet := jwk.NewSet()
	require.NoError(t, keySet.AddKey(key))

	return keySet
}

func fixedTime() time.Time {
	return time.Date(2026, time.May, 13, 21, 0, 0, 0, time.UTC)
}
