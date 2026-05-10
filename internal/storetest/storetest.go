package storetest

import (
	"context"
	"crypto/sha256"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/apikey"
	"github.com/meigma/authkit/oidc"
)

const (
	concurrentProvisionAttempts = 8
	testAction                  = "notes:read"
	testProvider                = "oidc"
	testProvisioningRuleID      = "engineering-readers"
	testRoleID                  = "notes-reader"
	testSubject                 = "user-123"
	testDisplayName             = "Ada Lovelace"
)

// Store is the complete storage surface exercised by Run.
type Store interface {
	authkit.PrincipalCreator
	authkit.PrincipalFinder
	authkit.PrincipalLister
	authkit.RoleCreator
	authkit.RoleActionGranter
	authkit.PrincipalRoleAssigner
	authkit.PrincipalRoleUnassigner
	authkit.PrincipalRoleAssignmentLister
	authkit.PrincipalActionResolver
	authkit.ProvisioningRuleCreator
	authkit.ProvisioningRuleUpdater
	authkit.ProvisioningRuleDeleter
	authkit.ProvisioningRuleFinder
	authkit.ProvisioningRuleLister
	authkit.IdentityLinker
	authkit.IdentityProvisioner
	authkit.PrincipalResolver
	apikey.TokenStore
	apikey.TokenMetadataLister
	oidc.ProviderTrustStore
}

// Run runs the shared storage behavior suite against newStore.
//
//nolint:funlen,gocognit // Keeping one top-level suite makes cross-store coverage easy to audit.
func Run(t *testing.T, newStore func(t *testing.T) Store) {
	t.Helper()

	t.Run("create principal", func(t *testing.T) {
		store := newStore(t)

		tests := []struct {
			name string
			kind authkit.PrincipalKind
		}{
			{name: "creates user principal", kind: authkit.PrincipalKindUser},
			{name: "creates service principal", kind: authkit.PrincipalKindService},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
					Kind:        tt.kind,
					DisplayName: testDisplayName,
				})

				require.NoError(t, err)
				assert.NotEmpty(t, principal.ID)
				assert.Contains(t, principal.ID, "principal_")
				assert.Equal(t, tt.kind, principal.Kind)
				assert.Equal(t, testDisplayName, principal.DisplayName)
				assert.Nil(t, principal.Attributes)
			})
		}
	})

	t.Run("create principal rejects invalid kind", func(t *testing.T) {
		store := newStore(t)

		principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
			Kind:        authkit.PrincipalKind("team"),
			DisplayName: testDisplayName,
		})

		require.Error(t, err)
		assert.Empty(t, principal)
	})

	t.Run("find and list principals", func(t *testing.T) {
		store := newStore(t)
		first, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
			Kind:        authkit.PrincipalKindUser,
			DisplayName: testDisplayName,
			Attributes: map[string]any{
				"team": "platform",
			},
		})
		require.NoError(t, err)
		second, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
			Kind:        authkit.PrincipalKindService,
			DisplayName: "Deploy service",
		})
		require.NoError(t, err)

		found, err := store.FindPrincipal(context.Background(), first.ID)
		require.NoError(t, err)
		assert.Equal(t, first, found)

		first.Attributes["team"] = "changed"
		found.Attributes["team"] = "changed from found"

		foundAgain, err := store.FindPrincipal(context.Background(), first.ID)
		require.NoError(t, err)
		assert.Equal(t, "platform", foundAgain.Attributes["team"])

		principals, err := store.ListPrincipals(context.Background())
		require.NoError(t, err)
		want := []authkit.Principal{foundAgain, second}
		sort.Slice(want, func(i, j int) bool {
			return want[i].ID < want[j].ID
		})
		assert.Equal(t, want, principals)

		principals[0].Attributes["team"] = "changed from list"
		foundAfterListMutation, err := store.FindPrincipal(context.Background(), first.ID)
		require.NoError(t, err)
		assert.Equal(t, "platform", foundAfterListMutation.Attributes["team"])
	})

	t.Run("find principal missing behavior", func(t *testing.T) {
		store := newStore(t)

		found, err := store.FindPrincipal(context.Background(), "missing")

		require.ErrorIs(t, err, authkit.ErrPrincipalNotFound)
		assert.Empty(t, found)
	})

	t.Run("create role", func(t *testing.T) {
		store := newStore(t)
		req := roleRequest()

		role, err := store.CreateRole(context.Background(), req)

		require.NoError(t, err)
		assert.Equal(t, authkit.Role(req), role)
	})

	t.Run("create role validates request", func(t *testing.T) {
		store := newStore(t)

		role, err := store.CreateRole(context.Background(), authkit.CreateRoleRequest{})

		require.Error(t, err)
		assert.Empty(t, role)
	})

	t.Run("create role rejects duplicate ID", func(t *testing.T) {
		store := newStore(t)
		_, err := store.CreateRole(context.Background(), roleRequest())
		require.NoError(t, err)

		role, err := store.CreateRole(context.Background(), roleRequest())

		require.Error(t, err)
		assert.Empty(t, role)
	})

	t.Run("grant role action is idempotent", func(t *testing.T) {
		store := newStore(t)
		principal := createPrincipal(t, store)
		createRole(t, store, testRoleID)

		req := authkit.GrantRoleActionRequest{
			RoleID: testRoleID,
			Action: testAction,
		}
		require.NoError(t, store.GrantRoleAction(context.Background(), req))
		require.NoError(t, store.GrantRoleAction(context.Background(), req))
		require.NoError(t, store.AssignPrincipalRole(context.Background(), authkit.AssignPrincipalRoleRequest{
			PrincipalID: principal.ID,
			RoleID:      testRoleID,
		}))

		actions, err := store.ResolvePrincipalActions(context.Background(), principal.ID)

		require.NoError(t, err)
		assert.Equal(t, []string{testAction}, actions)
	})

	t.Run("grant role action validates request", func(t *testing.T) {
		store := newStore(t)
		createRole(t, store, testRoleID)

		tests := []struct {
			name string
			req  authkit.GrantRoleActionRequest
		}{
			{
				name: "missing role ID",
				req: authkit.GrantRoleActionRequest{
					Action: testAction,
				},
			},
			{
				name: "missing action",
				req: authkit.GrantRoleActionRequest{
					RoleID: testRoleID,
				},
			},
			{
				name: "missing role",
				req: authkit.GrantRoleActionRequest{
					RoleID: "missing",
					Action: testAction,
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				require.Error(t, store.GrantRoleAction(context.Background(), tt.req))
			})
		}
	})

	t.Run("assign principal role is idempotent", func(t *testing.T) {
		store := newStore(t)
		principal := createPrincipal(t, store)
		createRole(t, store, testRoleID)
		require.NoError(t, store.GrantRoleAction(context.Background(), authkit.GrantRoleActionRequest{
			RoleID: testRoleID,
			Action: testAction,
		}))

		req := authkit.AssignPrincipalRoleRequest{
			PrincipalID: principal.ID,
			RoleID:      testRoleID,
		}
		require.NoError(t, store.AssignPrincipalRole(context.Background(), req))
		require.NoError(t, store.AssignPrincipalRole(context.Background(), req))

		actions, err := store.ResolvePrincipalActions(context.Background(), principal.ID)

		require.NoError(t, err)
		assert.Equal(t, []string{testAction}, actions)
	})

	t.Run("list and unassign principal roles", func(t *testing.T) {
		store := newStore(t)
		principal := createPrincipal(t, store)
		createRole(t, store, "writers")
		createRole(t, store, "readers")
		for _, assignment := range []authkit.AssignPrincipalRoleRequest{
			{PrincipalID: principal.ID, RoleID: "writers"},
			{PrincipalID: principal.ID, RoleID: "readers"},
		} {
			require.NoError(t, store.AssignPrincipalRole(context.Background(), assignment))
		}

		assignments, err := store.ListPrincipalRoleAssignments(context.Background(), principal.ID)
		require.NoError(t, err)
		assert.Equal(t, []authkit.PrincipalRoleAssignment{
			{PrincipalID: principal.ID, RoleID: "readers"},
			{PrincipalID: principal.ID, RoleID: "writers"},
		}, assignments)

		require.NoError(t, store.UnassignPrincipalRole(context.Background(), authkit.UnassignPrincipalRoleRequest{
			PrincipalID: principal.ID,
			RoleID:      "writers",
		}))
		require.NoError(t, store.UnassignPrincipalRole(context.Background(), authkit.UnassignPrincipalRoleRequest{
			PrincipalID: principal.ID,
			RoleID:      "writers",
		}))

		assignments, err = store.ListPrincipalRoleAssignments(context.Background(), principal.ID)
		require.NoError(t, err)
		assert.Equal(t, []authkit.PrincipalRoleAssignment{
			{PrincipalID: principal.ID, RoleID: "readers"},
		}, assignments)
	})

	t.Run("assign principal role validates request", func(t *testing.T) {
		store := newStore(t)
		principal := createPrincipal(t, store)
		createRole(t, store, testRoleID)

		tests := []struct {
			name string
			req  authkit.AssignPrincipalRoleRequest
		}{
			{
				name: "missing principal ID",
				req: authkit.AssignPrincipalRoleRequest{
					RoleID: testRoleID,
				},
			},
			{
				name: "missing role ID",
				req: authkit.AssignPrincipalRoleRequest{
					PrincipalID: principal.ID,
				},
			},
			{
				name: "missing principal",
				req: authkit.AssignPrincipalRoleRequest{
					PrincipalID: "missing",
					RoleID:      testRoleID,
				},
			},
			{
				name: "missing role",
				req: authkit.AssignPrincipalRoleRequest{
					PrincipalID: principal.ID,
					RoleID:      "missing",
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				require.Error(t, store.AssignPrincipalRole(context.Background(), tt.req))
			})
		}
	})

	t.Run("unassign and list principal roles validate request", func(t *testing.T) {
		store := newStore(t)
		principal := createPrincipal(t, store)
		createRole(t, store, testRoleID)

		tests := []struct {
			name string
			req  authkit.UnassignPrincipalRoleRequest
		}{
			{
				name: "missing principal ID",
				req: authkit.UnassignPrincipalRoleRequest{
					RoleID: testRoleID,
				},
			},
			{
				name: "missing role ID",
				req: authkit.UnassignPrincipalRoleRequest{
					PrincipalID: principal.ID,
				},
			},
			{
				name: "missing principal",
				req: authkit.UnassignPrincipalRoleRequest{
					PrincipalID: "missing",
					RoleID:      testRoleID,
				},
			},
			{
				name: "missing role",
				req: authkit.UnassignPrincipalRoleRequest{
					PrincipalID: principal.ID,
					RoleID:      "missing",
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				require.Error(t, store.UnassignPrincipalRole(context.Background(), tt.req))
			})
		}

		assignments, err := store.ListPrincipalRoleAssignments(context.Background(), "missing")
		require.ErrorIs(t, err, authkit.ErrPrincipalNotFound)
		assert.Nil(t, assignments)
	})

	t.Run("resolve principal actions returns distinct sorted actions", func(t *testing.T) {
		store := newStore(t)
		principal := createPrincipal(t, store)
		createRole(t, store, "writers")
		createRole(t, store, "readers")
		for _, grant := range []authkit.GrantRoleActionRequest{
			{RoleID: "writers", Action: "notes:write"},
			{RoleID: "writers", Action: testAction},
			{RoleID: "readers", Action: testAction},
		} {
			require.NoError(t, store.GrantRoleAction(context.Background(), grant))
		}
		for _, assignment := range []authkit.AssignPrincipalRoleRequest{
			{PrincipalID: principal.ID, RoleID: "writers"},
			{PrincipalID: principal.ID, RoleID: "readers"},
		} {
			require.NoError(t, store.AssignPrincipalRole(context.Background(), assignment))
		}

		actions, err := store.ResolvePrincipalActions(context.Background(), principal.ID)

		require.NoError(t, err)
		assert.Equal(t, []string{testAction, "notes:write"}, actions)
	})

	t.Run("resolve principal actions validates request", func(t *testing.T) {
		store := newStore(t)

		actions, err := store.ResolvePrincipalActions(context.Background(), "")
		require.Error(t, err)
		assert.Nil(t, actions)

		actions, err = store.ResolvePrincipalActions(context.Background(), "missing")
		require.Error(t, err)
		assert.Nil(t, actions)
	})

	t.Run("provisioning rules", func(t *testing.T) {
		store := newStore(t)
		createRole(t, store, testRoleID)
		trustProvider(t, store, providerFixture())
		req := provisioningRuleRequest()

		rule, err := store.CreateProvisioningRule(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, authkit.ProvisioningRule(req), rule)

		req.AssignRoleIDs[0] = "changed"
		rule.AssignRoleIDs[0] = "changed-from-returned"

		found, err := store.FindProvisioningRule(context.Background(), testProvisioningRuleID)
		require.NoError(t, err)
		assert.Equal(t, `hasAny(claims.groups, ["/engineering"])`, found.Condition)
		assert.Equal(t, []string{testRoleID}, found.AssignRoleIDs)

		listed, err := store.ListProvisioningRules(context.Background())
		require.NoError(t, err)
		assert.Equal(t, []authkit.ProvisioningRule{found}, listed)

		found.Condition = "false"
		listed[0].AssignRoleIDs[0] = "changed-from-list"
		foundAgain, err := store.FindProvisioningRule(context.Background(), testProvisioningRuleID)
		require.NoError(t, err)
		assert.Equal(t, `hasAny(claims.groups, ["/engineering"])`, foundAgain.Condition)
		assert.Equal(t, []string{testRoleID}, foundAgain.AssignRoleIDs)
	})

	t.Run("provisioning rules can be updated and deleted", func(t *testing.T) {
		store := newStore(t)
		createRole(t, store, testRoleID)
		createRole(t, store, "notes-writer")
		trustProvider(t, store, providerFixture())
		_, err := store.CreateProvisioningRule(context.Background(), provisioningRuleRequest())
		require.NoError(t, err)

		updated := authkit.UpdateProvisioningRuleRequest{
			ID:            testProvisioningRuleID,
			DisplayName:   "Platform writers",
			Provider:      providerFixture().Issuer,
			Condition:     `hasAny(claims.realm_access.roles, ["writer"])`,
			AssignRoleIDs: []string{"notes-writer"},
			Enabled:       false,
		}
		rule, err := store.UpdateProvisioningRule(context.Background(), updated)
		require.NoError(t, err)
		assert.Equal(t, authkit.ProvisioningRule(updated), rule)

		require.NoError(t, store.DeleteProvisioningRule(context.Background(), testProvisioningRuleID))
		_, err = store.FindProvisioningRule(context.Background(), testProvisioningRuleID)
		require.ErrorIs(t, err, authkit.ErrProvisioningRuleNotFound)
		require.ErrorIs(
			t,
			store.DeleteProvisioningRule(context.Background(), testProvisioningRuleID),
			authkit.ErrProvisioningRuleNotFound,
		)

		_, err = store.UpdateProvisioningRule(context.Background(), authkit.UpdateProvisioningRuleRequest{
			ID:            testProvisioningRuleID,
			Provider:      "https://untrusted.example",
			Condition:     `claims.missing == "missing"`,
			AssignRoleIDs: []string{"missing"},
			Enabled:       true,
		})
		require.ErrorIs(t, err, authkit.ErrProvisioningRuleNotFound)
	})

	t.Run("provisioning rules validate configuration", func(t *testing.T) {
		store := newStore(t)
		createRole(t, store, testRoleID)
		trustProvider(t, store, providerFixture())

		tests := []struct {
			name string
			req  authkit.CreateProvisioningRuleRequest
		}{
			{
				name: "missing ID",
				req: func() authkit.CreateProvisioningRuleRequest {
					req := provisioningRuleRequest()
					req.ID = ""

					return req
				}(),
			},
			{
				name: "untrusted provider",
				req: func() authkit.CreateProvisioningRuleRequest {
					req := provisioningRuleRequest()
					req.Provider = "https://untrusted.example"

					return req
				}(),
			},
			{
				name: "missing condition",
				req: func() authkit.CreateProvisioningRuleRequest {
					req := provisioningRuleRequest()
					req.Condition = ""

					return req
				}(),
			},
			{
				name: "syntax error",
				req: func() authkit.CreateProvisioningRuleRequest {
					req := provisioningRuleRequest()
					req.Condition = "claims.groups =="

					return req
				}(),
			},
			{
				name: "non-bool condition",
				req: func() authkit.CreateProvisioningRuleRequest {
					req := provisioningRuleRequest()
					req.Condition = "identity.subject"

					return req
				}(),
			},
			{
				name: "missing role",
				req: func() authkit.CreateProvisioningRuleRequest {
					req := provisioningRuleRequest()
					req.AssignRoleIDs = []string{"missing"}

					return req
				}(),
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				rule, err := store.CreateProvisioningRule(context.Background(), tt.req)

				require.Error(t, err)
				assert.Empty(t, rule)
			})
		}
	})

	t.Run("principal attributes are copied", func(t *testing.T) {
		store := newStore(t)
		attrs := map[string]any{
			"role": "operator",
		}

		principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
			Kind:        authkit.PrincipalKindUser,
			DisplayName: testDisplayName,
			Attributes:  attrs,
		})
		require.NoError(t, err)

		attrs["role"] = "changed before resolve"
		principal.Attributes["role"] = "changed from returned principal"

		_, err = store.LinkIdentity(context.Background(), authkit.LinkIdentityRequest{
			Provider:    testProvider,
			Subject:     testSubject,
			PrincipalID: principal.ID,
		})
		require.NoError(t, err)

		resolved, err := store.ResolveIdentity(context.Background(), authkit.Identity{
			Provider: testProvider,
			Subject:  testSubject,
		})
		require.NoError(t, err)
		require.NotNil(t, resolved)
		assert.Equal(t, "operator", resolved.Attributes["role"])

		resolved.Attributes["role"] = "changed from resolved principal"
		resolvedAgain, err := store.ResolveIdentity(context.Background(), authkit.Identity{
			Provider: testProvider,
			Subject:  testSubject,
		})
		require.NoError(t, err)
		require.NotNil(t, resolvedAgain)
		assert.Equal(t, "operator", resolvedAgain.Attributes["role"])
	})

	t.Run("link identity", func(t *testing.T) {
		store := newStore(t)
		first := createPrincipal(t, store)
		second := createPrincipal(t, store)

		link, err := store.LinkIdentity(context.Background(), authkit.LinkIdentityRequest{
			Provider:    testProvider,
			Subject:     testSubject,
			PrincipalID: first.ID,
		})
		require.NoError(t, err)
		assert.Equal(t, authkit.ExternalIdentity{
			Provider:    testProvider,
			Subject:     testSubject,
			PrincipalID: first.ID,
		}, link)

		relinked, err := store.LinkIdentity(context.Background(), authkit.LinkIdentityRequest{
			Provider:    testProvider,
			Subject:     testSubject,
			PrincipalID: first.ID,
		})
		require.NoError(t, err)
		assert.Equal(t, link, relinked)

		conflicted, err := store.LinkIdentity(context.Background(), authkit.LinkIdentityRequest{
			Provider:    testProvider,
			Subject:     testSubject,
			PrincipalID: second.ID,
		})
		require.Error(t, err)
		assert.Empty(t, conflicted)
	})

	t.Run("link identity validates request", func(t *testing.T) {
		store := newStore(t)
		principal := createPrincipal(t, store)

		tests := []struct {
			name string
			req  authkit.LinkIdentityRequest
		}{
			{
				name: "missing provider",
				req: authkit.LinkIdentityRequest{
					Subject:     testSubject,
					PrincipalID: principal.ID,
				},
			},
			{
				name: "missing subject",
				req: authkit.LinkIdentityRequest{
					Provider:    testProvider,
					PrincipalID: principal.ID,
				},
			},
			{
				name: "missing principal ID",
				req: authkit.LinkIdentityRequest{
					Provider: testProvider,
					Subject:  testSubject,
				},
			},
			{
				name: "missing principal",
				req: authkit.LinkIdentityRequest{
					Provider:    testProvider,
					Subject:     testSubject,
					PrincipalID: "missing",
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				link, err := store.LinkIdentity(context.Background(), tt.req)

				require.Error(t, err)
				assert.Empty(t, link)
			})
		}
	})

	t.Run("resolve identity", func(t *testing.T) {
		store := newStore(t)
		principal := createPrincipal(t, store)

		_, err := store.LinkIdentity(context.Background(), authkit.LinkIdentityRequest{
			Provider:    testProvider,
			Subject:     testSubject,
			PrincipalID: principal.ID,
		})
		require.NoError(t, err)

		resolved, err := store.ResolveIdentity(context.Background(), authkit.Identity{
			Provider:     testProvider,
			Subject:      testSubject,
			CredentialID: "id-123",
			Claims: map[string]any{
				"ignored": true,
			},
		})

		require.NoError(t, err)
		require.NotNil(t, resolved)
		assert.Equal(t, principal, *resolved)
	})

	t.Run("resolve identity returns unresolved identity", func(t *testing.T) {
		store := newStore(t)

		tests := []struct {
			name     string
			identity authkit.Identity
		}{
			{
				name: "missing provider",
				identity: authkit.Identity{
					Subject: testSubject,
				},
			},
			{
				name: "missing subject",
				identity: authkit.Identity{
					Provider: testProvider,
				},
			},
			{
				name: "unlinked identity",
				identity: authkit.Identity{
					Provider: testProvider,
					Subject:  testSubject,
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				resolved, err := store.ResolveIdentity(context.Background(), tt.identity)

				require.ErrorIs(t, err, authkit.ErrUnresolvedIdentity)
				assert.Nil(t, resolved)
			})
		}
	})

	t.Run("provision identity creates principal and link", func(t *testing.T) {
		store := newStore(t)
		req := provisionRequest()
		wantAttributes := map[string]any{
			"email": "ada@example.test",
		}

		result, err := store.ProvisionIdentity(context.Background(), req)
		require.NoError(t, err)
		assert.True(t, result.Created)
		assert.NotEmpty(t, result.Principal.ID)
		assert.Equal(t, authkit.PrincipalKindUser, result.Principal.Kind)
		assert.Equal(t, testDisplayName, result.Principal.DisplayName)
		assert.Equal(t, wantAttributes, result.Principal.Attributes)
		assert.Equal(t, authkit.ExternalIdentity{
			Provider:    testProvider,
			Subject:     testSubject,
			PrincipalID: result.Principal.ID,
		}, result.Link)

		req.Principal.Attributes["email"] = "changed before resolve"
		result.Principal.Attributes["email"] = "changed from returned principal"

		resolved, err := store.ResolveIdentity(context.Background(), req.Identity)
		require.NoError(t, err)
		require.NotNil(t, resolved)
		assert.Equal(t, wantAttributes, resolved.Attributes)
		assert.Equal(t, result.Principal.ID, resolved.ID)
	})

	t.Run("provision identity assigns initial roles", func(t *testing.T) {
		store := newStore(t)
		createRole(t, store, testRoleID)
		require.NoError(t, store.GrantRoleAction(context.Background(), authkit.GrantRoleActionRequest{
			RoleID: testRoleID,
			Action: testAction,
		}))
		req := provisionRequest()
		req.InitialRoleIDs = []string{testRoleID}

		result, err := store.ProvisionIdentity(context.Background(), req)
		require.NoError(t, err)
		require.True(t, result.Created)

		actions, err := store.ResolvePrincipalActions(context.Background(), result.Principal.ID)
		require.NoError(t, err)
		assert.Equal(t, []string{testAction}, actions)
	})

	t.Run("provision identity fails when initial role is missing", func(t *testing.T) {
		store := newStore(t)
		req := provisionRequest()
		req.InitialRoleIDs = []string{"missing"}

		result, err := store.ProvisionIdentity(context.Background(), req)
		require.Error(t, err)
		assert.Empty(t, result)

		resolved, err := store.ResolveIdentity(context.Background(), req.Identity)
		require.ErrorIs(t, err, authkit.ErrUnresolvedIdentity)
		assert.Nil(t, resolved)
	})

	t.Run("provision identity does not assign roles to existing links", func(t *testing.T) {
		store := newStore(t)
		first, err := store.ProvisionIdentity(context.Background(), provisionRequest())
		require.NoError(t, err)
		require.True(t, first.Created)
		createRole(t, store, testRoleID)
		require.NoError(t, store.GrantRoleAction(context.Background(), authkit.GrantRoleActionRequest{
			RoleID: testRoleID,
			Action: testAction,
		}))
		req := provisionRequest()
		req.InitialRoleIDs = []string{testRoleID}

		second, err := store.ProvisionIdentity(context.Background(), req)
		require.NoError(t, err)
		assert.False(t, second.Created)

		actions, err := store.ResolvePrincipalActions(context.Background(), first.Principal.ID)
		require.NoError(t, err)
		assert.Nil(t, actions)
	})

	t.Run("provision identity returns existing link without updating principal", func(t *testing.T) {
		store := newStore(t)
		first, err := store.ProvisionIdentity(context.Background(), provisionRequest())
		require.NoError(t, err)
		require.True(t, first.Created)

		secondReq := provisionRequest()
		secondReq.Principal.DisplayName = "Changed Name"
		secondReq.Principal.Attributes = map[string]any{
			"email": "changed@example.test",
		}
		second, err := store.ProvisionIdentity(context.Background(), secondReq)

		require.NoError(t, err)
		assert.False(t, second.Created)
		assert.Equal(t, first.Link, second.Link)
		assert.Equal(t, first.Principal, second.Principal)
		assert.Equal(t, testDisplayName, second.Principal.DisplayName)
		assert.Equal(t, "ada@example.test", second.Principal.Attributes["email"])
	})

	t.Run("provision identity validates request", func(t *testing.T) {
		store := newStore(t)

		tests := []struct {
			name      string
			req       authkit.ProvisionIdentityRequest
			assertErr func(t *testing.T, err error)
		}{
			{
				name: "missing provider",
				req: authkit.ProvisionIdentityRequest{
					Identity: authkit.Identity{Subject: testSubject},
					Principal: authkit.CreatePrincipalRequest{
						Kind: authkit.PrincipalKindUser,
					},
				},
				assertErr: func(t *testing.T, err error) {
					require.ErrorIs(t, err, authkit.ErrUnresolvedIdentity)
				},
			},
			{
				name: "missing subject",
				req: authkit.ProvisionIdentityRequest{
					Identity: authkit.Identity{Provider: testProvider},
					Principal: authkit.CreatePrincipalRequest{
						Kind: authkit.PrincipalKindUser,
					},
				},
				assertErr: func(t *testing.T, err error) {
					require.ErrorIs(t, err, authkit.ErrUnresolvedIdentity)
				},
			},
			{
				name: "invalid principal kind",
				req: authkit.ProvisionIdentityRequest{
					Identity: authkit.Identity{
						Provider: testProvider,
						Subject:  testSubject,
					},
					Principal: authkit.CreatePrincipalRequest{
						Kind: authkit.PrincipalKind("team"),
					},
				},
				assertErr: func(t *testing.T, err error) {
					require.Error(t, err)
					require.NotErrorIs(t, err, authkit.ErrUnresolvedIdentity)
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result, err := store.ProvisionIdentity(context.Background(), tt.req)

				tt.assertErr(t, err)
				assert.Empty(t, result)
			})
		}
	})

	t.Run("provision identity is idempotent under concurrency", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()
		start := make(chan struct{})
		results := make(chan authkit.ProvisionIdentityResult, concurrentProvisionAttempts)
		errs := make(chan error, concurrentProvisionAttempts)
		var wg sync.WaitGroup

		for range cap(results) {
			wg.Go(func() {
				<-start
				result, err := store.ProvisionIdentity(ctx, provisionRequest())
				if err != nil {
					errs <- err

					return
				}
				results <- result
			})
		}

		close(start)
		wg.Wait()
		close(results)
		close(errs)

		for err := range errs {
			require.NoError(t, err)
		}

		created := 0
		principalID := ""
		for result := range results {
			if result.Created {
				created++
			}
			if principalID == "" {
				principalID = result.Principal.ID
			}
			assert.Equal(t, principalID, result.Principal.ID)
			assert.Equal(t, principalID, result.Link.PrincipalID)
		}
		assert.Equal(t, 1, created)

		resolved, err := store.ResolveIdentity(ctx, provisionRequest().Identity)
		require.NoError(t, err)
		require.NotNil(t, resolved)
		assert.Equal(t, principalID, resolved.ID)
	})

	t.Run("trusted providers", func(t *testing.T) {
		store := newStore(t)
		provider := providerFixture()
		want := providerFixture()

		trusted, err := store.TrustProvider(context.Background(), provider)
		require.NoError(t, err)
		assert.Equal(t, want, trusted)

		provider.Audiences[0] = "changed before find"
		provider.ForwardedClaims[0][0] = "changed-before-find"
		trusted.Audiences[0] = "changed from returned provider"
		trusted.SupportedSigningAlgorithms[0] = "ES256"
		trusted.ForwardedClaims[0][0] = "changed-from-returned-provider"

		found, err := store.FindProvider(context.Background(), want.Issuer)
		require.NoError(t, err)
		assert.Equal(t, want, found)

		found.Audiences[0] = "changed from found provider"
		found.SupportedSigningAlgorithms[0] = "ES256"
		found.ForwardedClaims[0][0] = "changed-from-found-provider"
		foundAgain, err := store.FindProvider(context.Background(), want.Issuer)
		require.NoError(t, err)
		assert.Equal(t, want, foundAgain)
	})

	t.Run("trusted providers can be updated", func(t *testing.T) {
		store := newStore(t)
		provider := providerFixture()
		_, err := store.TrustProvider(context.Background(), provider)
		require.NoError(t, err)

		updated := oidc.Provider{
			Issuer:                     provider.Issuer,
			Audiences:                  []string{"updated-api"},
			JWKSURL:                    "https://issuer.example/updated-jwks.json",
			SupportedSigningAlgorithms: []string{"RS512"},
			ForwardedClaims:            []authkit.ClaimPath{{"email"}},
		}
		trusted, err := store.TrustProvider(context.Background(), updated)
		require.NoError(t, err)
		assert.Equal(t, updated, trusted)

		found, err := store.FindProvider(context.Background(), provider.Issuer)
		require.NoError(t, err)
		assert.Equal(t, updated, found)
	})

	t.Run("trusted providers missing behavior", func(t *testing.T) {
		store := newStore(t)

		found, err := store.FindProvider(context.Background(), "https://issuer.example")

		require.ErrorIs(t, err, oidc.ErrProviderNotFound)
		assert.Empty(t, found)
	})

	t.Run("trusted providers reject invalid configuration", func(t *testing.T) {
		store := newStore(t)
		invalid := providerFixture()
		invalid.Audiences = nil

		trusted, err := store.TrustProvider(context.Background(), invalid)
		require.Error(t, err)
		assert.Empty(t, trusted)

		found, err := store.FindProvider(context.Background(), invalid.Issuer)
		require.ErrorIs(t, err, oidc.ErrProviderNotFound)
		assert.Empty(t, found)
	})

	t.Run("returns context error", func(t *testing.T) {
		store := newStore(t)
		principal := createPrincipal(t, store)
		_, err := store.LinkIdentity(context.Background(), authkit.LinkIdentityRequest{
			Provider:    testProvider,
			Subject:     testSubject,
			PrincipalID: principal.ID,
		})
		require.NoError(t, err)
		token := tokenFixture(fixedStoreTime(), principal.ID)
		require.NoError(t, store.CreateToken(context.Background(), token))

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		tests := []struct {
			name string
			run  func() error
		}{
			{
				name: "create principal",
				run: func() error {
					_, runErr := store.CreatePrincipal(ctx, authkit.CreatePrincipalRequest{
						Kind: authkit.PrincipalKindUser,
					})

					return runErr
				},
			},
			{
				name: "find principal",
				run: func() error {
					_, runErr := store.FindPrincipal(ctx, principal.ID)

					return runErr
				},
			},
			{
				name: "list principals",
				run: func() error {
					_, runErr := store.ListPrincipals(ctx)

					return runErr
				},
			},
			{
				name: "unassign principal role",
				run: func() error {
					return store.UnassignPrincipalRole(ctx, authkit.UnassignPrincipalRoleRequest{
						PrincipalID: principal.ID,
						RoleID:      testRoleID,
					})
				},
			},
			{
				name: "list principal role assignments",
				run: func() error {
					_, runErr := store.ListPrincipalRoleAssignments(ctx, principal.ID)

					return runErr
				},
			},
			{
				name: "link identity",
				run: func() error {
					_, runErr := store.LinkIdentity(ctx, authkit.LinkIdentityRequest{
						Provider:    "api-token",
						Subject:     "token-123",
						PrincipalID: principal.ID,
					})

					return runErr
				},
			},
			{
				name: "resolve identity",
				run: func() error {
					_, runErr := store.ResolveIdentity(ctx, authkit.Identity{
						Provider: testProvider,
						Subject:  testSubject,
					})

					return runErr
				},
			},
			{
				name: "provision identity",
				run: func() error {
					_, runErr := store.ProvisionIdentity(ctx, provisionRequest())

					return runErr
				},
			},
			{
				name: "create token",
				run: func() error {
					return store.CreateToken(ctx, tokenFixture(fixedStoreTime(), principal.ID))
				},
			},
			{
				name: "find token",
				run: func() error {
					_, runErr := store.FindToken(ctx, token.ID)

					return runErr
				},
			},
			{
				name: "list principal token metadata",
				run: func() error {
					_, runErr := store.ListPrincipalTokenMetadata(ctx, principal.ID)

					return runErr
				},
			},
			{
				name: "update token last used",
				run: func() error {
					return store.UpdateTokenLastUsed(ctx, token.ID, fixedStoreTime())
				},
			},
			{
				name: "revoke token",
				run: func() error {
					return store.RevokeToken(ctx, token.ID, fixedStoreTime())
				},
			},
			{
				name: "trust provider",
				run: func() error {
					_, runErr := store.TrustProvider(ctx, providerFixture())

					return runErr
				},
			},
			{
				name: "create provisioning rule",
				run: func() error {
					_, runErr := store.CreateProvisioningRule(ctx, provisioningRuleRequest())

					return runErr
				},
			},
			{
				name: "update provisioning rule",
				run: func() error {
					_, runErr := store.UpdateProvisioningRule(ctx, authkit.UpdateProvisioningRuleRequest{
						ID: testProvisioningRuleID,
					})

					return runErr
				},
			},
			{
				name: "delete provisioning rule",
				run: func() error {
					return store.DeleteProvisioningRule(ctx, testProvisioningRuleID)
				},
			},
			{
				name: "find provisioning rule",
				run: func() error {
					_, runErr := store.FindProvisioningRule(ctx, testProvisioningRuleID)

					return runErr
				},
			},
			{
				name: "list provisioning rules",
				run: func() error {
					_, runErr := store.ListProvisioningRules(ctx)

					return runErr
				},
			},
			{
				name: "find provider",
				run: func() error {
					_, runErr := store.FindProvider(ctx, "https://issuer.example")

					return runErr
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				require.ErrorIs(t, tt.run(), context.Canceled)
			})
		}
	})

	t.Run("token storage", func(t *testing.T) {
		store := newStore(t)
		principal := createPrincipal(t, store)
		now := fixedStoreTime()
		usedAt := now.Add(time.Hour)
		wantUsedAt := usedAt
		token := tokenFixture(now, principal.ID)
		token.LastUsedAt = &usedAt

		require.NoError(t, store.CreateToken(context.Background(), token))
		*token.LastUsedAt = now.Add(time.Minute)

		found, err := store.FindToken(context.Background(), token.ID)
		require.NoError(t, err)
		require.NotNil(t, found.LastUsedAt)
		assert.Equal(t, wantUsedAt, *found.LastUsedAt)
		assert.Equal(t, token.SecretHash, found.SecretHash)

		*found.LastUsedAt = now.Add(time.Minute)
		foundAgain, err := store.FindToken(context.Background(), token.ID)
		require.NoError(t, err)
		require.NotNil(t, foundAgain.LastUsedAt)
		assert.Equal(t, wantUsedAt, *foundAgain.LastUsedAt)
	})

	t.Run("token last used and revocation", func(t *testing.T) {
		store := newStore(t)
		principal := createPrincipal(t, store)
		now := fixedStoreTime()
		token := createToken(t, store, now, principal.ID)
		usedAt := now.Add(time.Hour)
		revokedAt := now.Add(time.Hour + time.Minute)

		require.NoError(t, store.UpdateTokenLastUsed(context.Background(), token.ID, usedAt))
		require.NoError(t, store.RevokeToken(context.Background(), token.ID, revokedAt))

		found, err := store.FindToken(context.Background(), token.ID)
		require.NoError(t, err)
		require.NotNil(t, found.LastUsedAt)
		require.NotNil(t, found.RevokedAt)
		assert.Equal(t, usedAt, *found.LastUsedAt)
		assert.Equal(t, revokedAt, *found.RevokedAt)

		*found.LastUsedAt = now
		*found.RevokedAt = now
		foundAgain, err := store.FindToken(context.Background(), token.ID)
		require.NoError(t, err)
		require.NotNil(t, foundAgain.LastUsedAt)
		require.NotNil(t, foundAgain.RevokedAt)
		assert.Equal(t, usedAt, *foundAgain.LastUsedAt)
		assert.Equal(t, revokedAt, *foundAgain.RevokedAt)
	})

	t.Run("list principal token metadata", func(t *testing.T) {
		store := newStore(t)
		first := createPrincipal(t, store)
		second := createPrincipal(t, store)
		now := fixedStoreTime()
		firstToken := createToken(t, store, now, first.ID)
		secondToken := tokenFixture(now, first.ID)
		secondToken.ID = "token_2"
		secondToken.Name = "second token"
		require.NoError(t, store.CreateToken(context.Background(), secondToken))
		otherToken := tokenFixture(now, second.ID)
		otherToken.ID = "token_3"
		require.NoError(t, store.CreateToken(context.Background(), otherToken))
		usedAt := now.Add(time.Hour)
		revokedAt := now.Add(2 * time.Hour)
		require.NoError(t, store.UpdateTokenLastUsed(context.Background(), secondToken.ID, usedAt))
		require.NoError(t, store.RevokeToken(context.Background(), secondToken.ID, revokedAt))

		tokens, err := store.ListPrincipalTokenMetadata(context.Background(), first.ID)
		require.NoError(t, err)
		require.Len(t, tokens, 2)
		assert.Equal(t, apikey.TokenMetadata{
			ID:          firstToken.ID,
			PrincipalID: first.ID,
			Name:        firstToken.Name,
			ExpiresAt:   firstToken.ExpiresAt,
		}, tokens[0])
		assert.Equal(t, secondToken.ID, tokens[1].ID)
		assert.Equal(t, first.ID, tokens[1].PrincipalID)
		assert.Equal(t, secondToken.Name, tokens[1].Name)
		assert.Equal(t, secondToken.ExpiresAt, tokens[1].ExpiresAt)
		require.NotNil(t, tokens[1].LastUsedAt)
		require.NotNil(t, tokens[1].RevokedAt)
		assert.Equal(t, usedAt, *tokens[1].LastUsedAt)
		assert.Equal(t, revokedAt, *tokens[1].RevokedAt)

		*tokens[1].LastUsedAt = now
		*tokens[1].RevokedAt = now
		listedAgain, err := store.ListPrincipalTokenMetadata(context.Background(), first.ID)
		require.NoError(t, err)
		require.Len(t, listedAgain, 2)
		require.NotNil(t, listedAgain[1].LastUsedAt)
		require.NotNil(t, listedAgain[1].RevokedAt)
		assert.Equal(t, usedAt, *listedAgain[1].LastUsedAt)
		assert.Equal(t, revokedAt, *listedAgain[1].RevokedAt)
	})

	t.Run("token missing behavior", func(t *testing.T) {
		store := newStore(t)
		now := fixedStoreTime()

		found, err := store.FindToken(context.Background(), "missing")
		require.ErrorIs(t, err, apikey.ErrTokenNotFound)
		assert.Empty(t, found)

		require.ErrorIs(
			t,
			store.UpdateTokenLastUsed(context.Background(), "missing", now),
			apikey.ErrTokenNotFound,
		)
		require.ErrorIs(t, store.RevokeToken(context.Background(), "missing", now), apikey.ErrTokenNotFound)

		tokens, err := store.ListPrincipalTokenMetadata(context.Background(), "missing")
		require.ErrorIs(t, err, authkit.ErrPrincipalNotFound)
		assert.Nil(t, tokens)
	})

	t.Run("api token service integration", func(t *testing.T) {
		now := fixedStoreTime()
		store := newStore(t)
		service, err := apikey.NewService(store, apikey.WithClock(func() time.Time {
			return now
		}))
		require.NoError(t, err)
		principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
			Kind:        authkit.PrincipalKindService,
			DisplayName: "deploy service",
		})
		require.NoError(t, err)
		issued, err := service.IssueToken(context.Background(), apikey.IssueRequest{
			PrincipalID: principal.ID,
			Name:        "deploy token",
			ExpiresAt:   now.Add(time.Hour),
		})
		require.NoError(t, err)
		_, err = store.LinkIdentity(context.Background(), issued.IdentityLink)
		require.NoError(t, err)

		identity, err := service.VerifyToken(context.Background(), issued.Plaintext)
		require.NoError(t, err)
		require.NotNil(t, identity)
		resolved, err := store.ResolveIdentity(context.Background(), *identity)

		require.NoError(t, err)
		require.NotNil(t, resolved)
		assert.Equal(t, principal, *resolved)
	})
}

func createPrincipal(t *testing.T, store Store) authkit.Principal {
	t.Helper()

	principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindUser,
		DisplayName: testDisplayName,
		Attributes: map[string]any{
			"role": "operator",
		},
	})
	require.NoError(t, err)

	return principal
}

func createRole(t *testing.T, store Store, roleID string) authkit.Role {
	t.Helper()

	role, err := store.CreateRole(context.Background(), authkit.CreateRoleRequest{
		ID:          roleID,
		DisplayName: "Notes reader",
		Description: "Can read notes.",
	})
	require.NoError(t, err)

	return role
}

func trustProvider(t *testing.T, store Store, provider oidc.Provider) oidc.Provider {
	t.Helper()

	trusted, err := store.TrustProvider(context.Background(), provider)
	require.NoError(t, err)

	return trusted
}

func roleRequest() authkit.CreateRoleRequest {
	return authkit.CreateRoleRequest{
		ID:          testRoleID,
		DisplayName: "Notes reader",
		Description: "Can read notes.",
	}
}

func providerFixture() oidc.Provider {
	return oidc.Provider{
		Issuer:                     "https://issuer.example",
		Audiences:                  []string{"notes-api"},
		JWKSURL:                    "https://issuer.example/.well-known/jwks.json",
		SupportedSigningAlgorithms: []string{"RS256"},
		ForwardedClaims: []authkit.ClaimPath{
			{"groups"},
			{"realm_access", "roles"},
		},
	}
}

func provisioningRuleRequest() authkit.CreateProvisioningRuleRequest {
	return authkit.CreateProvisioningRuleRequest{
		ID:            testProvisioningRuleID,
		DisplayName:   "Engineering readers",
		Provider:      providerFixture().Issuer,
		Condition:     `hasAny(claims.groups, ["/engineering"])`,
		AssignRoleIDs: []string{testRoleID},
		Enabled:       true,
	}
}

func provisionRequest() authkit.ProvisionIdentityRequest {
	return authkit.ProvisionIdentityRequest{
		Identity: authkit.Identity{
			Provider: testProvider,
			Subject:  testSubject,
		},
		Principal: authkit.CreatePrincipalRequest{
			Kind:        authkit.PrincipalKindUser,
			DisplayName: testDisplayName,
			Attributes: map[string]any{
				"email": "ada@example.test",
			},
		},
	}
}

func createToken(t *testing.T, store Store, now time.Time, principalID string) apikey.StoredToken {
	t.Helper()

	token := tokenFixture(now, principalID)
	require.NoError(t, store.CreateToken(context.Background(), token))

	return token
}

func tokenFixture(now time.Time, principalID string) apikey.StoredToken {
	return apikey.StoredToken{
		ID:          "token_1",
		PrincipalID: principalID,
		Name:        "deploy",
		SecretHash:  sha256.Sum256([]byte("secret")),
		ExpiresAt:   now.Add(time.Hour),
	}
}

func fixedStoreTime() time.Time {
	return time.Date(2026, time.May, 7, 18, 0, 0, 0, time.UTC)
}
