package authkit

import (
	"context"
	"net/http"
)

// Authenticator verifies credentials from an HTTP request and returns an external identity.
type Authenticator interface {
	// Name returns a stable name for the authenticator.
	Name() string

	// Authenticate verifies the request credential and returns its external identity.
	Authenticate(ctx context.Context, r *http.Request) (*Identity, error)
}

// PrincipalResolver maps authenticated external identities to internal principals.
type PrincipalResolver interface {
	// ResolveIdentity returns the principal linked to identity.
	ResolveIdentity(ctx context.Context, identity Identity) (*Principal, error)
}

// Authorizer decides whether a principal may perform an action on a resource.
type Authorizer interface {
	// Can returns the authorization decision for principal, action, and resource.
	Can(ctx context.Context, principal Principal, action string, resource Resource) (Decision, error)
}
