package accessjwt

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Issuer issues signed authkit access JWTs.
type Issuer struct {
	issuer     string
	audience   string
	ttl        time.Duration
	signingKey jwk.Key
	algorithm  jwa.SignatureAlgorithm
	clock      func() time.Time
	tokenID    TokenIDFunc
}

// NewIssuer constructs an Issuer from opts.
func NewIssuer(opts IssuerOptions) (*Issuer, error) {
	if err := validateRequiredString("issuer", opts.Issuer); err != nil {
		return nil, err
	}
	if err := validateRequiredString("audience", opts.Audience); err != nil {
		return nil, err
	}
	if opts.TTL <= 0 {
		return nil, errors.New("accessjwt: TTL must be positive")
	}
	if opts.SigningKey == nil {
		return nil, errors.New("accessjwt: signing key is required")
	}
	if err := validateKeyID("signing key", opts.SigningKey); err != nil {
		return nil, err
	}

	algorithm, err := signatureAlgorithm(defaultString(opts.Algorithm, DefaultAlgorithm))
	if err != nil {
		return nil, err
	}
	if err := validateOptionalKeyAlgorithm("signing key", opts.SigningKey, algorithm); err != nil {
		return nil, err
	}

	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	tokenID := opts.TokenID
	if tokenID == nil {
		tokenID = randomTokenID
	}

	return &Issuer{
		issuer:     opts.Issuer,
		audience:   opts.Audience,
		ttl:        opts.TTL,
		signingKey: opts.SigningKey,
		algorithm:  algorithm,
		clock:      clock,
		tokenID:    tokenID,
	}, nil
}

// IssueToken issues a signed compact access JWT for req.PrincipalID.
func (i *Issuer) IssueToken(ctx context.Context, req IssueRequest) (IssuedToken, error) {
	if err := ctx.Err(); err != nil {
		return IssuedToken{}, err
	}
	if err := validateRequiredString("principal ID", req.PrincipalID); err != nil {
		return IssuedToken{}, err
	}

	tokenID, tokenIDErr := i.tokenID()
	if tokenIDErr != nil {
		return IssuedToken{}, fmt.Errorf("accessjwt: generate token ID: %w", tokenIDErr)
	}
	if validationErr := validateRequiredString("token ID", tokenID); validationErr != nil {
		return IssuedToken{}, validationErr
	}

	issuedAt := i.clock()
	expiresAt := issuedAt.Add(i.ttl)
	token, err := jwt.NewBuilder().
		Issuer(i.issuer).
		Subject(req.PrincipalID).
		Audience([]string{i.audience}).
		IssuedAt(issuedAt).
		Expiration(expiresAt).
		JwtID(tokenID).
		Build()
	if err != nil {
		return IssuedToken{}, fmt.Errorf("accessjwt: build token: %w", err)
	}

	headers := jws.NewHeaders()
	if headerErr := headers.Set(jws.TypeKey, TokenType); headerErr != nil {
		return IssuedToken{}, fmt.Errorf("accessjwt: set token type: %w", headerErr)
	}

	signed, err := jwt.Sign(
		token,
		jwt.WithKey(i.algorithm, i.signingKey, jws.WithProtectedHeaders(headers)),
	)
	if err != nil {
		return IssuedToken{}, fmt.Errorf("accessjwt: sign token: %w", err)
	}

	return IssuedToken{
		ID:          tokenID,
		Plaintext:   string(signed),
		PrincipalID: req.PrincipalID,
		IssuedAt:    issuedAt,
		ExpiresAt:   expiresAt,
	}, nil
}

func validateRequiredString(name string, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("accessjwt: %s is required", name)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("accessjwt: %s must not contain surrounding whitespace", name)
	}

	return nil
}

func defaultString(value string, fallback string) string {
	if value == "" {
		return fallback
	}

	return value
}

func randomTokenID() (string, error) {
	return rand.Text(), nil
}
