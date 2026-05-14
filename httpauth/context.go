package httpauth

import (
	"context"

	"github.com/meigma/authkit"
)

type authenticationContextKey struct{}

// AuthenticationFromContext returns the request authentication stored in ctx.
func AuthenticationFromContext(ctx context.Context) (authkit.Authentication, bool) {
	if ctx == nil {
		return authkit.Authentication{}, false
	}

	authentication, ok := ctx.Value(authenticationContextKey{}).(authkit.Authentication)

	return authentication, ok
}

// IdentityFromContext returns the authenticated identity stored in ctx.
func IdentityFromContext(ctx context.Context) (authkit.Identity, bool) {
	authentication, ok := AuthenticationFromContext(ctx)
	if !ok {
		return authkit.Identity{}, false
	}
	if authentication.Identity.Provider == "" &&
		authentication.Identity.Subject == "" &&
		authentication.Identity.CredentialID == "" &&
		len(authentication.Identity.Claims) == 0 {
		return authkit.Identity{}, false
	}

	return authentication.Identity, true
}

// PrincipalFromContext returns the resolved principal stored in ctx.
func PrincipalFromContext(ctx context.Context) (authkit.Principal, bool) {
	authentication, ok := AuthenticationFromContext(ctx)
	if !ok {
		return authkit.Principal{}, false
	}

	return authentication.Principal, true
}

func contextWithAuthentication(
	ctx context.Context,
	authentication authkit.Authentication,
) context.Context {
	return context.WithValue(ctx, authenticationContextKey{}, authentication)
}
