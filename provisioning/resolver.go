package provisioning

import (
	"context"
	"errors"
	"fmt"

	"github.com/meigma/authkit"
)

// PrincipalFactory decides whether identity may be provisioned and builds its principal request.
type PrincipalFactory func(
	ctx context.Context,
	identity authkit.Identity,
) (authkit.CreatePrincipalRequest, bool, error)

// ResolverOptions configures a Resolver.
type ResolverOptions struct {
	// Resolver resolves identities that have already been linked.
	Resolver authkit.PrincipalResolver

	// Provisioner atomically creates and links principals for allowed identities.
	Provisioner authkit.IdentityProvisioner

	// Factory maps unresolved identities to principal creation requests.
	Factory PrincipalFactory
}

// Resolver resolves linked identities and provisions allowed unresolved identities.
type Resolver struct {
	resolver    authkit.PrincipalResolver
	provisioner authkit.IdentityProvisioner
	factory     PrincipalFactory
}

// NewResolver constructs an auto-provisioning principal resolver.
func NewResolver(opts ResolverOptions) (*Resolver, error) {
	if opts.Resolver == nil {
		return nil, errors.New("provisioning: resolver is required")
	}
	if opts.Provisioner == nil {
		return nil, errors.New("provisioning: provisioner is required")
	}
	if opts.Factory == nil {
		return nil, errors.New("provisioning: principal factory is required")
	}

	return &Resolver{
		resolver:    opts.Resolver,
		provisioner: opts.Provisioner,
		factory:     opts.Factory,
	}, nil
}

// ResolveIdentity resolves identity or provisions it when the factory allows creation.
func (r *Resolver) ResolveIdentity(
	ctx context.Context,
	identity authkit.Identity,
) (*authkit.Principal, error) {
	principal, err := r.resolver.ResolveIdentity(ctx, identity)
	if err == nil {
		return principal, nil
	}
	if !errors.Is(err, authkit.ErrUnresolvedIdentity) {
		return nil, err
	}

	req, ok, factoryErr := r.factory(ctx, identity)
	if factoryErr != nil {
		return nil, fmt.Errorf("provisioning: build principal request: %w", factoryErr)
	}
	if !ok {
		return nil, err
	}

	result, provisionErr := r.provisioner.ProvisionIdentity(ctx, authkit.ProvisionIdentityRequest{
		Identity:  identity,
		Principal: req,
	})
	if provisionErr != nil {
		return nil, fmt.Errorf("provisioning: provision identity: %w", provisionErr)
	}

	return &result.Principal, nil
}
