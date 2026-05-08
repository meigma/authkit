package postgres

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/apikey"
)

func TestStoreSatisfiesAuthkitContracts(_ *testing.T) {
	var _ authkit.PrincipalCreator = (*Store)(nil)
	var _ authkit.IdentityLinker = (*Store)(nil)
	var _ authkit.PrincipalResolver = (*Store)(nil)
	var _ apikey.TokenStore = (*Store)(nil)
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
