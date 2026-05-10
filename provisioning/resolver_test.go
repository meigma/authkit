package provisioning_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/provisioning"
)

var errUnresolved = fmt.Errorf("%w: not linked", authkit.ErrUnresolvedIdentity)

func TestResolverSatisfiesPrincipalResolver(t *testing.T) {
	var _ authkit.PrincipalResolver = (*provisioning.Resolver)(nil)

	resolver, err := provisioning.NewResolver(provisioning.ResolverOptions{
		Resolver:    &fakeResolver{},
		Provisioner: &fakeProvisioner{},
		Factory:     allowFactory,
	})

	require.NoError(t, err)
	assert.NotNil(t, resolver)
}

func TestNewResolverValidatesOptions(t *testing.T) {
	tests := []struct {
		name string
		opts provisioning.ResolverOptions
	}{
		{
			name: "missing resolver",
			opts: provisioning.ResolverOptions{
				Provisioner: &fakeProvisioner{},
				Factory:     allowFactory,
			},
		},
		{
			name: "missing provisioner",
			opts: provisioning.ResolverOptions{
				Resolver: &fakeResolver{},
				Factory:  allowFactory,
			},
		},
		{
			name: "missing factory",
			opts: provisioning.ResolverOptions{
				Resolver:    &fakeResolver{},
				Provisioner: &fakeProvisioner{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver, err := provisioning.NewResolver(tt.opts)

			require.Error(t, err)
			assert.Nil(t, resolver)
		})
	}
}

func TestResolverReturnsExistingPrincipalWithoutProvisioning(t *testing.T) {
	existing := testPrincipal()
	inner := &fakeResolver{principal: &existing}
	provisioner := &fakeProvisioner{}
	factoryCalls := 0
	resolver := newResolver(t, inner, provisioner, func(
		context.Context,
		authkit.Identity,
	) (authkit.CreatePrincipalRequest, bool, error) {
		factoryCalls++

		return testPrincipalRequest(), true, nil
	})

	principal, err := resolver.ResolveIdentity(context.Background(), testIdentity())

	require.NoError(t, err)
	require.NotNil(t, principal)
	assert.Equal(t, existing, *principal)
	assert.Equal(t, []authkit.Identity{testIdentity()}, inner.identities)
	assert.Equal(t, 0, factoryCalls)
	assert.Empty(t, provisioner.requests)
}

func TestResolverProvisionsAllowedUnresolvedIdentity(t *testing.T) {
	inner := &fakeResolver{err: errUnresolved}
	provisioner := &fakeProvisioner{
		result: authkit.ProvisionIdentityResult{
			Principal: testPrincipal(),
			Link: authkit.ExternalIdentity{
				Provider:    testIdentity().Provider,
				Subject:     testIdentity().Subject,
				PrincipalID: testPrincipal().ID,
			},
			Created: true,
		},
	}
	factoryIdentities := []authkit.Identity{}
	resolver := newResolver(t, inner, provisioner, func(
		_ context.Context,
		identity authkit.Identity,
	) (authkit.CreatePrincipalRequest, bool, error) {
		factoryIdentities = append(factoryIdentities, identity)

		return testPrincipalRequest(), true, nil
	})

	principal, err := resolver.ResolveIdentity(context.Background(), testIdentity())

	require.NoError(t, err)
	require.NotNil(t, principal)
	assert.Equal(t, testPrincipal(), *principal)
	assert.Equal(t, []authkit.Identity{testIdentity()}, factoryIdentities)
	assert.Equal(t, []authkit.ProvisionIdentityRequest{{
		Identity:  testIdentity(),
		Principal: testPrincipalRequest(),
	}}, provisioner.requests)
}

func TestResolverAssignsInitialRolesFromProvisioningRules(t *testing.T) {
	inner := &fakeResolver{err: errUnresolved}
	provisioner := &fakeProvisioner{
		result: authkit.ProvisionIdentityResult{
			Principal: testPrincipal(),
			Link: authkit.ExternalIdentity{
				Provider:    testIdentity().Provider,
				Subject:     testIdentity().Subject,
				PrincipalID: testPrincipal().ID,
			},
			Created: true,
		},
	}
	resolver, err := provisioning.NewResolver(provisioning.ResolverOptions{
		Resolver:    inner,
		Provisioner: provisioner,
		Factory:     allowFactory,
		RuleSource: &fakeRuleSource{
			rules: []authkit.ProvisioningRule{
				{
					ID:            "engineering-readers",
					Provider:      testIdentity().Provider,
					Condition:     `hasAny(claims.groups, ["/engineering"])`,
					AssignRoleIDs: []string{"reader"},
					Enabled:       true,
				},
			},
		},
	})
	require.NoError(t, err)

	principal, err := resolver.ResolveIdentity(context.Background(), testIdentity())

	require.NoError(t, err)
	require.NotNil(t, principal)
	assert.Equal(t, []authkit.ProvisionIdentityRequest{{
		Identity:       testIdentity(),
		Principal:      testPrincipalRequest(),
		InitialRoleIDs: []string{"reader"},
	}}, provisioner.requests)
}

func TestResolverPreservesUnresolvedIdentityWhenFactoryDenies(t *testing.T) {
	provisioner := &fakeProvisioner{}
	resolver := newResolver(t, &fakeResolver{err: errUnresolved}, provisioner, func(
		context.Context,
		authkit.Identity,
	) (authkit.CreatePrincipalRequest, bool, error) {
		return authkit.CreatePrincipalRequest{}, false, nil
	})

	principal, err := resolver.ResolveIdentity(context.Background(), testIdentity())

	require.ErrorIs(t, err, authkit.ErrUnresolvedIdentity)
	assert.Nil(t, principal)
	assert.Empty(t, provisioner.requests)
}

func TestResolverReturnsRuleSourceError(t *testing.T) {
	ruleErr := errors.New("rules unavailable")
	provisioner := &fakeProvisioner{}
	resolver, err := provisioning.NewResolver(provisioning.ResolverOptions{
		Resolver:    &fakeResolver{err: errUnresolved},
		Provisioner: provisioner,
		Factory:     allowFactory,
		RuleSource:  &fakeRuleSource{err: ruleErr},
	})
	require.NoError(t, err)

	principal, err := resolver.ResolveIdentity(context.Background(), testIdentity())

	require.ErrorIs(t, err, ruleErr)
	assert.Nil(t, principal)
	assert.Empty(t, provisioner.requests)
}

func TestResolverReturnsFactoryError(t *testing.T) {
	factoryErr := errors.New("claim mapping failed")
	provisioner := &fakeProvisioner{}
	resolver := newResolver(t, &fakeResolver{err: errUnresolved}, provisioner, func(
		context.Context,
		authkit.Identity,
	) (authkit.CreatePrincipalRequest, bool, error) {
		return authkit.CreatePrincipalRequest{}, false, factoryErr
	})

	principal, err := resolver.ResolveIdentity(context.Background(), testIdentity())

	require.ErrorIs(t, err, factoryErr)
	assert.Nil(t, principal)
	assert.Empty(t, provisioner.requests)
}

func TestResolverReturnsProvisionerError(t *testing.T) {
	provisionErr := errors.New("store failed")
	provisioner := &fakeProvisioner{err: provisionErr}
	resolver := newResolver(t, &fakeResolver{err: errUnresolved}, provisioner, allowFactory)

	principal, err := resolver.ResolveIdentity(context.Background(), testIdentity())

	require.ErrorIs(t, err, provisionErr)
	assert.Nil(t, principal)
	assert.Equal(t, []authkit.ProvisionIdentityRequest{{
		Identity:  testIdentity(),
		Principal: testPrincipalRequest(),
	}}, provisioner.requests)
}

func TestResolverDoesNotProvisionUnexpectedResolverErrors(t *testing.T) {
	resolverErr := errors.New("database unavailable")
	provisioner := &fakeProvisioner{}
	resolver := newResolver(t, &fakeResolver{err: resolverErr}, provisioner, allowFactory)

	principal, err := resolver.ResolveIdentity(context.Background(), testIdentity())

	require.ErrorIs(t, err, resolverErr)
	assert.Nil(t, principal)
	assert.Empty(t, provisioner.requests)
}

func TestMatchRules(t *testing.T) {
	identity := authkit.Identity{
		Provider:     "https://token.actions.githubusercontent.com",
		Subject:      "repo:meigma/imgsrv:ref:refs/heads/main",
		CredentialID: "jwt:abc123",
		Claims: map[string]any{
			"repository_id": "123456789",
			"workflow_ref":  "meigma/imgsrv/.github/workflows/publish.yml@refs/heads/main",
			"scope":         "openid content.write",
			"groups":        []any{"publishers", "operators"},
		},
	}
	rules := []authkit.ProvisioningRule{
		{
			ID:            "disabled",
			Provider:      identity.Provider,
			Condition:     "true",
			AssignRoleIDs: []string{"disabled"},
		},
		{
			ID:            "provider-mismatch",
			Provider:      "https://other.example",
			Condition:     "true",
			AssignRoleIDs: []string{"other"},
			Enabled:       true,
		},
		{
			ID:            "missing-claim",
			Provider:      identity.Provider,
			Condition:     `claims.department == "engineering"`,
			AssignRoleIDs: []string{"department"},
			Enabled:       true,
		},
		{
			ID:            "eval-error",
			Provider:      identity.Provider,
			Condition:     `claims.missing.startsWith("repo:")`,
			AssignRoleIDs: []string{"eval-error"},
			Enabled:       true,
		},
		{
			ID:       "github-main-publisher",
			Provider: identity.Provider,
			Condition: `identity.subject == "repo:meigma/imgsrv:ref:refs/heads/main" &&
				claims.repository_id == "123456789" &&
				claims.workflow_ref == "meigma/imgsrv/.github/workflows/publish.yml@refs/heads/main"`,
			AssignRoleIDs: []string{"content-writer"},
			Enabled:       true,
		},
		{
			ID:            "scope-match",
			Provider:      identity.Provider,
			Condition:     `hasToken(claims.scope, "content.write")`,
			AssignRoleIDs: []string{"scope-writer", "content-writer"},
			Enabled:       true,
		},
		{
			ID:            "group-match",
			Provider:      identity.Provider,
			Condition:     `hasAny(claims.groups, ["publishers"])`,
			AssignRoleIDs: []string{"group-writer"},
			Enabled:       true,
		},
	}

	roleIDs := provisioning.MatchRules(identity, rules)

	assert.Equal(t, []string{"content-writer", "scope-writer", "group-writer"}, roleIDs)
}

func TestValidateConditionRejectsInvalidExpressions(t *testing.T) {
	tests := []struct {
		name      string
		condition string
	}{
		{name: "syntax error", condition: "claims.scope =="},
		{name: "type error", condition: "identity.subject"},
		{name: "empty", condition: ""},
		{name: "too large", condition: strings.Repeat("a", provisioning.MaxConditionBytes+1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, provisioning.ValidateCondition(tt.condition))
		})
	}
}

func newResolver(
	t *testing.T,
	inner authkit.PrincipalResolver,
	provisioner authkit.IdentityProvisioner,
	factory provisioning.PrincipalFactory,
) *provisioning.Resolver {
	t.Helper()

	resolver, err := provisioning.NewResolver(provisioning.ResolverOptions{
		Resolver:    inner,
		Provisioner: provisioner,
		Factory:     factory,
	})
	require.NoError(t, err)

	return resolver
}

func allowFactory(context.Context, authkit.Identity) (authkit.CreatePrincipalRequest, bool, error) {
	return testPrincipalRequest(), true, nil
}

func testIdentity() authkit.Identity {
	return authkit.Identity{
		Provider: "https://issuer.example",
		Subject:  "user-123",
		Claims: map[string]any{
			"email": "ada@example.test",
			"groups": []any{
				"/engineering",
			},
		},
	}
}

func testPrincipalRequest() authkit.CreatePrincipalRequest {
	return authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindUser,
		DisplayName: "Ada Lovelace",
		Attributes: map[string]any{
			"email": "ada@example.test",
		},
	}
}

func testPrincipal() authkit.Principal {
	return authkit.Principal{
		ID:          "principal_1",
		Kind:        authkit.PrincipalKindUser,
		DisplayName: "Ada Lovelace",
		Attributes: map[string]any{
			"email": "ada@example.test",
		},
	}
}

type fakeResolver struct {
	identities []authkit.Identity
	principal  *authkit.Principal
	err        error
}

func (r *fakeResolver) ResolveIdentity(
	_ context.Context,
	identity authkit.Identity,
) (*authkit.Principal, error) {
	r.identities = append(r.identities, identity)
	if r.err != nil {
		return nil, r.err
	}

	return r.principal, nil
}

type fakeProvisioner struct {
	requests []authkit.ProvisionIdentityRequest
	result   authkit.ProvisionIdentityResult
	err      error
}

func (p *fakeProvisioner) ProvisionIdentity(
	_ context.Context,
	req authkit.ProvisionIdentityRequest,
) (authkit.ProvisionIdentityResult, error) {
	p.requests = append(p.requests, req)
	if p.err != nil {
		return authkit.ProvisionIdentityResult{}, p.err
	}

	return p.result, nil
}

type fakeRuleSource struct {
	rules []authkit.ProvisioningRule
	err   error
}

func (s *fakeRuleSource) ListProvisioningRules(context.Context) ([]authkit.ProvisioningRule, error) {
	if s.err != nil {
		return nil, s.err
	}

	return s.rules, nil
}
