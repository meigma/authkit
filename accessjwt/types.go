package accessjwt

import (
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

const (
	// DefaultAlgorithm is the signing algorithm used when an options struct omits one.
	DefaultAlgorithm = "RS256"

	// TokenType is the protected JWS typ header used for access JWTs.
	TokenType = "at+jwt"
)

// TokenIDFunc generates a unique token ID for an issued access JWT.
type TokenIDFunc func() (string, error)

// IssueRequest describes a request to issue an access JWT.
type IssueRequest struct {
	// PrincipalID identifies the principal authenticated by the token.
	PrincipalID string
}

// IssuedToken describes an access JWT immediately after issuance.
type IssuedToken struct {
	// ID is the token's jti claim.
	ID string

	// Plaintext is the signed compact JWT returned to the caller.
	Plaintext string

	// PrincipalID is the principal authenticated by the token.
	PrincipalID string

	// IssuedAt is the token's iat claim.
	IssuedAt time.Time

	// ExpiresAt is the token's exp claim.
	ExpiresAt time.Time
}

// VerifiedToken describes a successfully verified access JWT.
type VerifiedToken struct {
	// ID is the token's jti claim.
	ID string

	// PrincipalID is the principal authenticated by the token.
	PrincipalID string

	// Issuer is the verified iss claim.
	Issuer string

	// Audience is the configured audience that matched the aud claim.
	Audience string

	// IssuedAt is the token's iat claim.
	IssuedAt time.Time

	// ExpiresAt is the token's exp claim.
	ExpiresAt time.Time
}

// IssuerOptions configures an Issuer.
type IssuerOptions struct {
	// Issuer is the exact iss claim written to issued tokens.
	Issuer string

	// Audience is the aud claim written to issued tokens.
	Audience string

	// TTL is the lifetime of issued tokens.
	TTL time.Duration

	// SigningKey is the private JWK used to sign tokens. It must carry a non-empty kid.
	SigningKey jwk.Key

	// Algorithm is the JWS signing algorithm. Empty selects DefaultAlgorithm.
	Algorithm string

	// Clock returns the current time. Nil selects time.Now.
	Clock func() time.Time

	// TokenID generates jti values. Nil selects a cryptographically random generator.
	TokenID TokenIDFunc
}

// VerifierOptions configures a Verifier.
type VerifierOptions struct {
	// Issuer is the exact iss claim accepted by the verifier.
	Issuer string

	// Audience is the aud claim value accepted by the verifier.
	Audience string

	// KeySet contains public verification keys. Each key must carry a kid and allowed alg.
	KeySet jwk.Set

	// AllowedAlgorithms limits accepted JWS signing algorithms. Empty selects DefaultAlgorithm.
	AllowedAlgorithms []string

	// AcceptableSkew is the allowed difference for exp, iat, and nbf validation.
	AcceptableSkew time.Duration

	// Clock returns the current time. Nil selects time.Now.
	Clock func() time.Time
}
