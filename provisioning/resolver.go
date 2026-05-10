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

	// RuleSource lists provisioning rules used for initial role assignment.
	RuleSource authkit.ProvisioningRuleLister
}

// Resolver resolves linked identities and provisions allowed unresolved identities.
type Resolver struct {
	resolver    authkit.PrincipalResolver
	provisioner authkit.IdentityProvisioner
	factory     PrincipalFactory
	ruleSource  authkit.ProvisioningRuleLister
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
		ruleSource:  opts.RuleSource,
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

	roleIDs, err := r.initialRoleIDs(ctx, identity)
	if err != nil {
		return nil, err
	}

	result, provisionErr := r.provisioner.ProvisionIdentity(ctx, authkit.ProvisionIdentityRequest{
		Identity:       identity,
		Principal:      req,
		InitialRoleIDs: roleIDs,
	})
	if provisionErr != nil {
		return nil, fmt.Errorf("provisioning: provision identity: %w", provisionErr)
	}

	return &result.Principal, nil
}

func (r *Resolver) initialRoleIDs(ctx context.Context, identity authkit.Identity) ([]string, error) {
	if r.ruleSource == nil {
		return nil, nil
	}

	rules, err := r.ruleSource.ListProvisioningRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("provisioning: list provisioning rules: %w", err)
	}

	return matchRules(ctx, identity, rules), nil
}

// MatchRules returns local role IDs assigned by provisioning rules for identity.
func MatchRules(identity authkit.Identity, rules []authkit.ProvisioningRule) []string {
	return matchRules(context.Background(), identity, rules)
}

func matchRules(ctx context.Context, identity authkit.Identity, rules []authkit.ProvisioningRule) []string {
	if len(rules) == 0 {
		return nil
	}

	var roleIDs []string
	seen := map[string]struct{}{}
	for _, rule := range rules {
		if !rule.Enabled || rule.Provider != identity.Provider {
			continue
		}
		if !conditionMatches(ctx, identity, rule.Condition) {
			continue
		}

		for _, roleID := range rule.AssignRoleIDs {
			if roleID == "" {
				continue
			}
			if _, ok := seen[roleID]; ok {
				continue
			}

			seen[roleID] = struct{}{}
			roleIDs = append(roleIDs, roleID)
		}
	}

	return roleIDs
}
