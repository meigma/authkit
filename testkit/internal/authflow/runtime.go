package authflow

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/accessjwt"
	"github.com/meigma/authkit/apikey"
	"github.com/meigma/authkit/compose"
	"github.com/meigma/authkit/exchange"
	"github.com/meigma/authkit/httpauth"
)

const (
	// CookieName is the temporary app-owned cookie carrying authkit access JWTs.
	CookieName = "authkit_testkit_access"

	// LoginPath is the HTML login page used when browser authentication fails.
	LoginPath = "/login"

	// SeedAPITokenTTL is the lifetime of the development bootstrap API token.
	SeedAPITokenTTL = 24 * time.Hour

	// AccessTokenTTL is the lifetime of access JWTs issued by testkit.
	AccessTokenTTL = 15 * time.Minute

	accessJWTIssuer        = "https://testkit.local/authkit"
	accessJWTAudience      = "testkit"
	accessJWTKeyID         = "testkit-dev-access-key"
	bootstrapPrincipalName = "Testkit author"
	bootstrapAPITokenName  = "testkit bootstrap token"
	rsaKeyBits             = 2048
	accessCookiePath       = "/"
	accessCookieMaxAge     = int(AccessTokenTTL / time.Second)
	clearedAccessCookieAge = -1
)

// Store is the authkit storage surface testkit needs for API-token exchange.
type Store interface {
	authkit.PrincipalCreator
	authkit.PrincipalFinder
	authkit.PrincipalLister
	apikey.TokenStore
}

// Runtime contains the authkit components used by testkit HTTP handlers.
type Runtime struct {
	// Middleware authenticates requests carrying authkit access JWTs.
	Middleware *httpauth.Middleware

	// Exchanger exchanges opaque API tokens for authkit access JWTs.
	Exchanger *exchange.APITokenExchanger

	// Principal is the bootstrap principal that owns the startup API token.
	Principal authkit.Principal

	// SeedAPIToken is the plaintext startup API token shown once on stdout.
	SeedAPIToken string

	// SeedAPITokenExpiresAt is when SeedAPIToken stops being accepted for exchange.
	SeedAPITokenExpiresAt time.Time
}

type options struct {
	clock func() time.Time
}

// Option configures Runtime construction.
type Option func(*options)

// WithClock configures the clock used for token timestamps.
func WithClock(clock func() time.Time) Option {
	return func(opts *options) {
		if clock != nil {
			opts.clock = clock
		}
	}
}

// NewRuntime constructs the authkit API-token exchange runtime for testkit.
func NewRuntime(ctx context.Context, store Store, opts ...Option) (*Runtime, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("authflow: store is required")
	}

	cfg := options{
		clock: time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.clock == nil {
		cfg.clock = time.Now
	}

	principal, err := bootstrapPrincipal(ctx, store)
	if err != nil {
		return nil, err
	}
	apiTokens, err := apikey.NewService(store, apikey.WithClock(cfg.clock))
	if err != nil {
		return nil, fmt.Errorf("authflow: create API-token service: %w", err)
	}
	seedToken, err := apiTokens.IssueToken(ctx, apikey.IssueRequest{
		PrincipalID: principal.ID,
		Name:        bootstrapAPITokenName,
		ExpiresAt:   cfg.clock().Add(SeedAPITokenTTL),
	})
	if err != nil {
		return nil, fmt.Errorf("authflow: issue seed API token: %w", err)
	}

	accessIssuer, accessVerifier, err := newAccessJWTIssuerAndVerifier(cfg.clock)
	if err != nil {
		return nil, err
	}
	exchanger, err := exchange.NewAPITokenExchanger(exchange.APITokenOptions{
		APITokens:    apiTokens,
		Principals:   store,
		AccessTokens: accessIssuer,
	})
	if err != nil {
		return nil, fmt.Errorf("authflow: create API-token exchanger: %w", err)
	}
	composed, err := compose.NewHTTP(compose.HTTPOptions{
		PrincipalAuthenticators: []compose.PrincipalAuthenticatorSpec{
			compose.AccessJWT(accessVerifier, store),
		},
		Authorizer: allowAuthorizer{},
		MiddlewareOptions: []httpauth.Option{
			httpauth.WithErrorRenderer(renderAuthError),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("authflow: compose HTTP auth: %w", err)
	}

	return &Runtime{
		Middleware:            composed.Middleware,
		Exchanger:             exchanger,
		Principal:             principal,
		SeedAPIToken:          seedToken.Plaintext,
		SeedAPITokenExpiresAt: seedToken.ExpiresAt,
	}, nil
}

// ExchangeAPIToken exchanges plaintext for an authkit access JWT.
func (r *Runtime) ExchangeAPIToken(
	ctx context.Context,
	plaintext string,
) (exchange.APITokenResult, error) {
	if r == nil || r.Exchanger == nil {
		return exchange.APITokenResult{}, errors.New("authflow: runtime exchanger is required")
	}

	return r.Exchanger.Exchange(ctx, exchange.APITokenRequest{
		Plaintext: plaintext,
	})
}

// Authenticate authenticates requests carrying authkit access JWTs.
func (r *Runtime) Authenticate(next http.Handler) http.Handler {
	return r.Middleware.Authenticate(next)
}

// SetAccessCookie writes the temporary testkit access JWT cookie.
func SetAccessCookie(w http.ResponseWriter, token accessjwt.IssuedToken) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token.Plaintext,
		Path:     accessCookiePath,
		Expires:  token.ExpiresAt,
		MaxAge:   accessCookieMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearAccessCookie clears the temporary testkit access JWT cookie.
func ClearAccessCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     accessCookiePath,
		MaxAge:   clearedAccessCookieAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func bootstrapPrincipal(ctx context.Context, store Store) (authkit.Principal, error) {
	principals, err := store.ListPrincipals(ctx)
	if err != nil {
		return authkit.Principal{}, fmt.Errorf("authflow: list principals: %w", err)
	}
	for _, principal := range principals {
		if principal.Kind == authkit.PrincipalKindUser && principal.DisplayName == bootstrapPrincipalName {
			return principal, nil
		}
	}

	principal, err := store.CreatePrincipal(ctx, authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindUser,
		DisplayName: bootstrapPrincipalName,
		Attributes: map[string]any{
			"testkit": true,
		},
	})
	if err != nil {
		return authkit.Principal{}, fmt.Errorf("authflow: create bootstrap principal: %w", err)
	}

	return principal, nil
}

func newAccessJWTIssuerAndVerifier(
	clock func() time.Time,
) (*accessjwt.Issuer, *accessjwt.Verifier, error) {
	rawKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("authflow: generate access JWT key: %w", err)
	}
	signingKey, err := jwk.Import(rawKey)
	if err != nil {
		return nil, nil, fmt.Errorf("authflow: import access JWT key: %w", err)
	}
	if setErr := signingKey.Set(jwk.KeyIDKey, accessJWTKeyID); setErr != nil {
		return nil, nil, fmt.Errorf("authflow: set access JWT key ID: %w", setErr)
	}
	if setErr := signingKey.Set(jwk.AlgorithmKey, jwa.RS256()); setErr != nil {
		return nil, nil, fmt.Errorf("authflow: set access JWT key algorithm: %w", setErr)
	}
	publicKey, err := jwk.PublicKeyOf(signingKey)
	if err != nil {
		return nil, nil, fmt.Errorf("authflow: derive access JWT public key: %w", err)
	}
	keySet := jwk.NewSet()
	if addErr := keySet.AddKey(publicKey); addErr != nil {
		return nil, nil, fmt.Errorf("authflow: build access JWT key set: %w", addErr)
	}

	issuer, err := accessjwt.NewIssuer(accessjwt.IssuerOptions{
		Issuer:     accessJWTIssuer,
		Audience:   accessJWTAudience,
		TTL:        AccessTokenTTL,
		SigningKey: signingKey,
		Clock:      clock,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("authflow: create access JWT issuer: %w", err)
	}
	verifier, err := accessjwt.NewVerifier(accessjwt.VerifierOptions{
		Issuer:   accessJWTIssuer,
		Audience: accessJWTAudience,
		KeySet:   keySet,
		Clock:    clock,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("authflow: create access JWT verifier: %w", err)
	}

	return issuer, verifier, nil
}

func renderAuthError(w http.ResponseWriter, req *http.Request, err error) {
	if errors.Is(err, authkit.ErrUnauthenticated) || errors.Is(err, authkit.ErrUnresolvedIdentity) {
		ClearAccessCookie(w)
		http.Redirect(w, req, LoginPath, http.StatusSeeOther)

		return
	}

	status := http.StatusInternalServerError
	if errors.Is(err, authkit.ErrUnauthorized) {
		status = http.StatusForbidden
	}
	http.Error(w, http.StatusText(status), status)
}

type allowAuthorizer struct{}

func (allowAuthorizer) Can(ctx context.Context, _ authkit.AuthorizationCheck) (authkit.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authkit.Decision{}, err
	}

	return authkit.Decision{Allowed: true}, nil
}
