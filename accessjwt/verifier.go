package accessjwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/meigma/authkit"
)

// Verifier verifies authkit access JWTs.
type Verifier struct {
	issuer            string
	audience          string
	keySet            jwk.Set
	allowedAlgorithms map[string]jwa.SignatureAlgorithm
	acceptableSkew    time.Duration
	clock             func() time.Time
}

// NewVerifier constructs a Verifier from opts.
func NewVerifier(opts VerifierOptions) (*Verifier, error) {
	if err := validateRequiredString("issuer", opts.Issuer); err != nil {
		return nil, err
	}
	if err := validateRequiredString("audience", opts.Audience); err != nil {
		return nil, err
	}
	if opts.KeySet == nil || opts.KeySet.Len() == 0 {
		return nil, errors.New("accessjwt: key set is required")
	}
	if opts.AcceptableSkew < 0 {
		return nil, errors.New("accessjwt: acceptable skew must not be negative")
	}

	algorithmMap, err := signatureAlgorithms(opts.AllowedAlgorithms)
	if err != nil {
		return nil, err
	}
	if validationErr := validateKeySet(opts.KeySet, algorithmMap); validationErr != nil {
		return nil, validationErr
	}

	keySet, err := opts.KeySet.Clone()
	if err != nil {
		return nil, fmt.Errorf("accessjwt: clone key set: %w", err)
	}

	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}

	return &Verifier{
		issuer:            opts.Issuer,
		audience:          opts.Audience,
		keySet:            keySet,
		allowedAlgorithms: algorithmMap,
		acceptableSkew:    opts.AcceptableSkew,
		clock:             clock,
	}, nil
}

// VerifyToken verifies plaintext and returns its principal token metadata.
func (v *Verifier) VerifyToken(ctx context.Context, plaintext string) (VerifiedToken, error) {
	if err := ctx.Err(); err != nil {
		return VerifiedToken{}, err
	}
	if plaintext == "" {
		return VerifiedToken{}, unauthenticated("token is required")
	}

	if err := v.validateProtectedHeaders([]byte(plaintext)); err != nil {
		return VerifiedToken{}, unauthenticated(err.Error())
	}

	token, err := jwt.Parse(
		[]byte(plaintext),
		jwt.WithKeySet(v.keySet),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithRequiredClaim(jwt.SubjectKey),
		jwt.WithRequiredClaim(jwt.JwtIDKey),
		jwt.WithRequiredClaim(jwt.IssuedAtKey),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
		jwt.WithClock(jwt.ClockFunc(v.clock)),
		jwt.WithAcceptableSkew(v.acceptableSkew),
	)
	if err != nil {
		return VerifiedToken{}, unauthenticated("JWT verification failed")
	}

	verified, err := v.verifiedToken(token)
	if err != nil {
		return VerifiedToken{}, unauthenticated(err.Error())
	}

	return verified, nil
}

func (v *Verifier) validateProtectedHeaders(raw []byte) error {
	message, err := jws.Parse(raw, jws.WithCompact())
	if err != nil {
		return errors.New("malformed JWT")
	}

	signatures := message.Signatures()
	if len(signatures) != 1 {
		return errors.New("JWT must have exactly one signature")
	}

	headers := signatures[0].ProtectedHeaders()
	if headers == nil {
		return errors.New("JWT protected header is required")
	}
	tokenType, ok := headers.Type()
	if !ok || tokenType != TokenType {
		return errors.New("JWT type must be at+jwt")
	}
	keyID, ok := headers.KeyID()
	if !ok || keyID == "" {
		return errors.New("JWT key ID is required")
	}
	algorithm, ok := headers.Algorithm()
	if !ok {
		return errors.New("JWT algorithm is required")
	}
	if _, ok := v.allowedAlgorithms[algorithm.String()]; !ok {
		return errors.New("JWT algorithm is not allowed")
	}

	return nil
}

func (v *Verifier) verifiedToken(token jwt.Token) (VerifiedToken, error) {
	principalID, ok := token.Subject()
	if !ok || principalID == "" {
		return VerifiedToken{}, errors.New("subject claim is required")
	}
	tokenID, ok := token.JwtID()
	if !ok || tokenID == "" {
		return VerifiedToken{}, errors.New("JWT ID claim is required")
	}
	issuer, ok := token.Issuer()
	if !ok || issuer == "" {
		return VerifiedToken{}, errors.New("issuer claim is required")
	}
	issuedAt, ok := token.IssuedAt()
	if !ok || issuedAt.IsZero() {
		return VerifiedToken{}, errors.New("issued-at claim is required")
	}
	expiresAt, ok := token.Expiration()
	if !ok || expiresAt.IsZero() {
		return VerifiedToken{}, errors.New("expiration claim is required")
	}

	return VerifiedToken{
		ID:          tokenID,
		PrincipalID: principalID,
		Issuer:      issuer,
		Audience:    v.audience,
		IssuedAt:    issuedAt,
		ExpiresAt:   expiresAt,
	}, nil
}

func unauthenticated(reason string) error {
	return fmt.Errorf("%w: %s", authkit.ErrUnauthenticated, reason)
}
