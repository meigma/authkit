package roleauth

import (
	"context"
	"errors"
	"slices"

	"github.com/meigma/authkit"
)

const deniedReason = "action not granted"

// Authorizer authorizes checks from effective principal actions.
type Authorizer struct {
	resolver authkit.PrincipalActionResolver
}

// NewAuthorizer constructs an Authorizer around resolver.
func NewAuthorizer(resolver authkit.PrincipalActionResolver) (*Authorizer, error) {
	if resolver == nil {
		return nil, errors.New("roleauth: principal action resolver is required")
	}

	return &Authorizer{
		resolver: resolver,
	}, nil
}

// Can returns whether check.Principal has check.Action through local role grants.
func (a *Authorizer) Can(ctx context.Context, check authkit.AuthorizationCheck) (authkit.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authkit.Decision{}, err
	}
	if check.Principal.ID == "" {
		return authkit.Decision{}, errors.New("roleauth: principal ID is required")
	}
	if check.Action == "" {
		return authkit.Decision{}, errors.New("roleauth: action is required")
	}

	actions, err := a.resolver.ResolvePrincipalActions(ctx, check.Principal.ID)
	if err != nil {
		return authkit.Decision{}, err
	}
	if err := ctx.Err(); err != nil {
		return authkit.Decision{}, err
	}

	if slices.Contains(actions, check.Action) {
		return authkit.Decision{Allowed: true}, nil
	}

	return authkit.Decision{
		Allowed: false,
		Reason:  deniedReason,
	}, nil
}
