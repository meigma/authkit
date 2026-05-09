package oidc

import (
	"net/http"
	"time"

	"github.com/meigma/authkit"
)

const (
	defaultHTTPTimeout    = 5 * time.Second
	defaultKeySetCacheTTL = 5 * time.Minute
)

type options struct {
	httpClient      *http.Client
	clock           func() time.Time
	acceptableSkew  time.Duration
	forwardedClaims []authkit.ClaimPath
	keySetCacheTTL  time.Duration
}

// Option configures an Authenticator.
type Option func(*options)

func defaultOptions() options {
	return options{
		httpClient:     &http.Client{Timeout: defaultHTTPTimeout},
		clock:          time.Now,
		keySetCacheTTL: defaultKeySetCacheTTL,
	}
}

// WithHTTPClient sets the HTTP client used to fetch JWKS documents.
func WithHTTPClient(client *http.Client) Option {
	return func(opts *options) {
		if client != nil {
			opts.httpClient = client
		}
	}
}

// WithClock sets the clock used for JWT time validation.
func WithClock(clock func() time.Time) Option {
	return func(opts *options) {
		if clock != nil {
			opts.clock = clock
		}
	}
}

// WithAcceptableSkew permits exp, nbf, and iat claims to vary by skew.
func WithAcceptableSkew(skew time.Duration) Option {
	return func(opts *options) {
		if skew >= 0 {
			opts.acceptableSkew = skew
		}
	}
}

// WithForwardedClaims selects verified JWT claims copied into authkit.Identity.Claims.
func WithForwardedClaims(claims ...string) Option {
	return func(opts *options) {
		opts.forwardedClaims = make([]authkit.ClaimPath, 0, len(claims))
		for _, claim := range claims {
			opts.forwardedClaims = append(opts.forwardedClaims, authkit.ClaimPath{claim})
		}
	}
}

// WithForwardedClaimPaths selects verified nested JWT claims copied into authkit.Identity.Claims.
func WithForwardedClaimPaths(paths ...authkit.ClaimPath) Option {
	return func(opts *options) {
		opts.forwardedClaims = cloneClaimPaths(paths)
	}
}

// WithKeySetCacheTTL sets how long fetched JWKS documents may be reused.
func WithKeySetCacheTTL(ttl time.Duration) Option {
	return func(opts *options) {
		if ttl >= 0 {
			opts.keySetCacheTTL = ttl
		}
	}
}
