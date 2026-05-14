package authkit

import (
	"context"
	"net/http"
)

// PrincipalAuthentication describes a request credential that authenticated directly to a principal.
type PrincipalAuthentication struct {
	// Principal is the internal principal authenticated by the request credential.
	Principal Principal
}

// PrincipalAuthenticator verifies credentials from an HTTP request and returns an internal principal.
type PrincipalAuthenticator interface {
	// Name returns a stable name for the authenticator.
	Name() string

	// AuthenticatePrincipal verifies the request credential and returns its principal.
	AuthenticatePrincipal(ctx context.Context, r *http.Request) (*PrincipalAuthentication, error)
}

// PrincipalResolver maps authenticated external identities to internal principals.
type PrincipalResolver interface {
	// ResolveIdentity returns the principal linked to identity.
	ResolveIdentity(ctx context.Context, identity Identity) (*Principal, error)
}

// Authorizer decides whether an authorization check is allowed.
type Authorizer interface {
	// Can returns the authorization decision for check.
	Can(ctx context.Context, check AuthorizationCheck) (Decision, error)
}
