package provisioning_test

import (
	"context"
	"errors"
	"fmt"
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
