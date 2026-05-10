package postgres

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/apikey"
	"github.com/meigma/authkit/oidc"
)

func TestStoreSatisfiesAuthkitContracts(_ *testing.T) {
	var _ authkit.PrincipalCreator = (*Store)(nil)
	var _ authkit.RoleCreator = (*Store)(nil)
	var _ authkit.RoleActionGranter = (*Store)(nil)
	var _ authkit.PrincipalRoleAssigner = (*Store)(nil)
	var _ authkit.PrincipalActionResolver = (*Store)(nil)
	var _ authkit.IdentityLinker = (*Store)(nil)
	var _ authkit.IdentityProvisioner = (*Store)(nil)
	var _ authkit.PrincipalResolver = (*Store)(nil)
	var _ authkit.ProvisioningRuleCreator = (*Store)(nil)
	var _ authkit.ProvisioningRuleUpdater = (*Store)(nil)
	var _ authkit.ProvisioningRuleDeleter = (*Store)(nil)
	var _ authkit.ProvisioningRuleFinder = (*Store)(nil)
	var _ authkit.ProvisioningRuleLister = (*Store)(nil)
	var _ apikey.TokenStore = (*Store)(nil)
	var _ oidc.ProviderSource = (*Store)(nil)
	var _ oidc.ProviderTrustStore = (*Store)(nil)
}

func TestNewStoreValidatesPool(t *testing.T) {
	store, err := NewStore(nil)

	require.Error(t, err)
	assert.Nil(t, store)
}

func TestMigrateValidatesPool(t *testing.T) {
	err := Migrate(context.Background(), nil)

	require.Error(t, err)
}
