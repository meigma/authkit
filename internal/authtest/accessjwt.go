package authtest

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit/accessjwt"
)

const (
	testRSAKeyBits = 2048

	// AccessJWTIssuer is the default test issuer for authkit access JWTs.
	AccessJWTIssuer = "https://auth.example.test"

	// AccessJWTAudience is the default test audience for authkit access JWTs.
	AccessJWTAudience = "notes-api"

	// AccessJWTKeyID is the default test signing key ID for authkit access JWTs.
	AccessJWTKeyID = "test-key"
)

// FixedTime returns the shared stable clock value used by authkit test helpers.
func FixedTime() time.Time {
	return time.Date(2026, time.May, 13, 22, 0, 0, 0, time.UTC)
}

// AccessJWTOption configures NewAccessJWTIssuerAndVerifier.
type AccessJWTOption func(*accessJWTConfig)

type accessJWTConfig struct {
	issuer   string
	audience string
	keyID    string
	clock    func() time.Time
	tokenID  func() (string, error)
}

// WithAccessJWTTokenID sets a deterministic access JWT ID generator.
func WithAccessJWTTokenID(tokenID func() (string, error)) AccessJWTOption {
	return func(cfg *accessJWTConfig) {
		cfg.tokenID = tokenID
	}
}

// NewAccessJWTIssuerAndVerifier constructs a matching test access JWT issuer and verifier.
func NewAccessJWTIssuerAndVerifier(
	t testing.TB,
	opts ...AccessJWTOption,
) (*accessjwt.Issuer, *accessjwt.Verifier) {
	t.Helper()

	cfg := accessJWTConfig{
		issuer:   AccessJWTIssuer,
		audience: AccessJWTAudience,
		keyID:    AccessJWTKeyID,
		clock:    FixedTime,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	rawKey, err := rsa.GenerateKey(rand.Reader, testRSAKeyBits)
	require.NoError(t, err)
	signingKey, err := jwk.Import(rawKey)
	require.NoError(t, err)
	require.NoError(t, signingKey.Set(jwk.KeyIDKey, cfg.keyID))
	require.NoError(t, signingKey.Set(jwk.AlgorithmKey, jwa.RS256()))
	publicKey, err := jwk.PublicKeyOf(signingKey)
	require.NoError(t, err)
	keySet := jwk.NewSet()
	require.NoError(t, keySet.AddKey(publicKey))

	issuer, err := accessjwt.NewIssuer(accessjwt.IssuerOptions{
		Issuer:     cfg.issuer,
		Audience:   cfg.audience,
		TTL:        time.Hour,
		SigningKey: signingKey,
		Clock:      cfg.clock,
		TokenID:    cfg.tokenID,
	})
	require.NoError(t, err)
	verifier, err := accessjwt.NewVerifier(accessjwt.VerifierOptions{
		Issuer:   cfg.issuer,
		Audience: cfg.audience,
		KeySet:   keySet,
		Clock:    cfg.clock,
	})
	require.NoError(t, err)

	return issuer, verifier
}
