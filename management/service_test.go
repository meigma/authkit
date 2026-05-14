package management_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/apikey"
	"github.com/meigma/authkit/management"
	"github.com/meigma/authkit/store/memory"
)

const (
	testPrincipalID   = "principal_1"
	testTokenID       = "token_1"
	testTokenName     = "deploy token"
	testTokenSecret   = "ak_token_1_secret"
	testProvider      = "oidc"
	testSubject       = "user-123"
	testPrincipalName = "deploy service"
)

func TestNewServiceAllowsSparseOptions(t *testing.T) {
	tests := []struct {
		name string
		opts management.Options
	}{
		{
			name: "no collaborators",
		},
		{
			name: "missing principal creator",
			opts: management.Options{
				IdentityLinker: newFakeIdentityLinker(),
				APITokens:      newFakeAPITokens(),
			},
		},
		{
			name: "missing identity linker",
			opts: management.Options{
				PrincipalCreator: newFakePrincipalCreator(),
				APITokens:        newFakeAPITokens(),
			},
		},
		{
			name: "missing API tokens",
			opts: management.Options{
				PrincipalCreator: newFakePrincipalCreator(),
				IdentityLinker:   newFakeIdentityLinker(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := management.NewService(tt.opts)

			assert.NotNil(t, service)
		})
	}
}

func TestServiceCoreMethodsRequirePorts(t *testing.T) {
	service := management.NewService(management.Options{})

	tests := []struct {
		name string
		run  func() error
		want string
	}{
		{
			name: "create principal",
			run: func() error {
				_, err := service.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
					Kind: authkit.PrincipalKindService,
				})

				return err
			},
			want: "management: principal creator is required",
		},
		{
			name: "link identity",
			run: func() error {
				_, err := service.LinkIdentity(context.Background(), authkit.LinkIdentityRequest{
					Provider:    testProvider,
					Subject:     testSubject,
					PrincipalID: testPrincipalID,
				})

				return err
			},
			want: "management: identity linker is required",
		},
		{
			name: "find principal",
			run: func() error {
				_, err := service.FindPrincipal(context.Background(), testPrincipalID)

				return err
			},
			want: "management: principal finder is required",
		},
		{
			name: "list principals",
			run: func() error {
				_, err := service.ListPrincipals(context.Background())

				return err
			},
			want: "management: principal lister is required",
		},
		{
			name: "issue API token missing API token service",
			run: func() error {
				_, err := service.IssueAPIToken(context.Background(), management.IssueAPITokenRequest{
					PrincipalID: testPrincipalID,
					ExpiresAt:   fixedTime().Add(time.Hour),
				})

				return err
			},
			want: "management: API tokens service is required",
		},
		{
			name: "revoke API token",
			run: func() error {
				return service.RevokeAPIToken(context.Background(), testTokenID)
			},
			want: "management: API tokens service is required",
		},
		{
			name: "list API token metadata",
			run: func() error {
				_, err := service.ListPrincipalAPITokenMetadata(context.Background(), testPrincipalID)

				return err
			},
			want: "management: API token metadata lister is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()

			require.Error(t, err)
			assert.EqualError(t, err, tt.want)
		})
	}
}

func TestServiceIssueAPITokenRequiresPrincipalFinderBeforeIssuing(t *testing.T) {
	apiTokens := newFakeAPITokens()
	service := management.NewService(management.Options{
		APITokens: apiTokens,
	})

	issued, err := service.IssueAPIToken(context.Background(), management.IssueAPITokenRequest{
		PrincipalID: testPrincipalID,
		ExpiresAt:   fixedTime().Add(time.Hour),
	})

	require.EqualError(t, err, "management: principal finder is required")
	assert.Empty(t, issued)
	assert.Empty(t, apiTokens.issueRequests)
}

func TestServiceCreatePrincipal(t *testing.T) {
	creator := newFakePrincipalCreator()
	creator.principal = authkit.Principal{
		ID:          testPrincipalID,
		Kind:        authkit.PrincipalKindService,
		DisplayName: testPrincipalName,
	}
	service := newService(t, creator, newFakeIdentityLinker(), newFakeAPITokens())
	req := authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindService,
		DisplayName: testPrincipalName,
	}

	principal, err := service.CreatePrincipal(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, creator.principal, principal)
	assert.Equal(t, []authkit.CreatePrincipalRequest{req}, creator.requests)
}

func TestServiceFindAndListPrincipals(t *testing.T) {
	principals := newFakePrincipalCreator()
	principals.principal = authkit.Principal{
		ID:          testPrincipalID,
		Kind:        authkit.PrincipalKindService,
		DisplayName: testPrincipalName,
	}
	principals.principals = []authkit.Principal{principals.principal}
	service := management.NewService(management.Options{
		PrincipalFinder: principals,
		PrincipalLister: principals,
	})

	found, err := service.FindPrincipal(context.Background(), testPrincipalID)
	require.NoError(t, err)
	assert.Equal(t, principals.principal, found)
	assert.Equal(t, []string{testPrincipalID}, principals.findIDs)

	listed, err := service.ListPrincipals(context.Background())
	require.NoError(t, err)
	assert.Equal(t, principals.principals, listed)
	assert.Equal(t, 1, principals.listCalls)
}

func TestNewServiceDoesNotRequireRolePorts(t *testing.T) {
	service := management.NewService(management.Options{
		PrincipalCreator: newFakePrincipalCreator(),
		IdentityLinker:   newFakeIdentityLinker(),
		APITokens:        newFakeAPITokens(),
	})
	assert.NotNil(t, service)
}

func TestNewServiceDoesNotRequireProvisioningRulePorts(t *testing.T) {
	service := management.NewService(management.Options{
		PrincipalCreator: newFakePrincipalCreator(),
		IdentityLinker:   newFakeIdentityLinker(),
		APITokens:        newFakeAPITokens(),
	})
	assert.NotNil(t, service)
}

func TestServiceCreateRole(t *testing.T) {
	roles := newFakeRoleStore()
	roles.role = authkit.Role{
		ID:          "notes-reader",
		DisplayName: "Notes reader",
		Description: "Can read notes.",
	}
	service := newServiceWithRoles(t, newFakePrincipalCreator(), roles, newFakeIdentityLinker(), newFakeAPITokens())
	req := authkit.CreateRoleRequest{
		ID:          roles.role.ID,
		DisplayName: roles.role.DisplayName,
		Description: roles.role.Description,
	}

	role, err := service.CreateRole(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, roles.role, role)
	assert.Equal(t, []authkit.CreateRoleRequest{req}, roles.createRequests)
}

func TestServiceGrantRoleAction(t *testing.T) {
	roles := newFakeRoleStore()
	service := newServiceWithRoles(t, newFakePrincipalCreator(), roles, newFakeIdentityLinker(), newFakeAPITokens())
	req := authkit.GrantRoleActionRequest{
		RoleID: "notes-reader",
		Action: "notes:read",
	}

	err := service.GrantRoleAction(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, []authkit.GrantRoleActionRequest{req}, roles.grantRequests)
}

func TestServiceAssignPrincipalRole(t *testing.T) {
	roles := newFakeRoleStore()
	service := newServiceWithRoles(t, newFakePrincipalCreator(), roles, newFakeIdentityLinker(), newFakeAPITokens())
	req := authkit.AssignPrincipalRoleRequest{
		PrincipalID: testPrincipalID,
		RoleID:      "notes-reader",
	}

	err := service.AssignPrincipalRole(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, []authkit.AssignPrincipalRoleRequest{req}, roles.assignRequests)
}

func TestServiceUnassignPrincipalRole(t *testing.T) {
	roles := newFakeRoleStore()
	service := newServiceWithRoles(t, newFakePrincipalCreator(), roles, newFakeIdentityLinker(), newFakeAPITokens())
	req := authkit.UnassignPrincipalRoleRequest{
		PrincipalID: testPrincipalID,
		RoleID:      "notes-reader",
	}

	err := service.UnassignPrincipalRole(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, []authkit.UnassignPrincipalRoleRequest{req}, roles.unassignRequests)
}

func TestServiceListPrincipalRoleAssignments(t *testing.T) {
	roles := newFakeRoleStore()
	roles.assignments = []authkit.PrincipalRoleAssignment{
		{PrincipalID: testPrincipalID, RoleID: "notes-reader"},
	}
	service := newServiceWithRoles(t, newFakePrincipalCreator(), roles, newFakeIdentityLinker(), newFakeAPITokens())

	assignments, err := service.ListPrincipalRoleAssignments(context.Background(), testPrincipalID)

	require.NoError(t, err)
	assert.Equal(t, roles.assignments, assignments)
	assert.Equal(t, []string{testPrincipalID}, roles.listPrincipalIDs)
}

func TestServiceWrapsRoleErrors(t *testing.T) {
	roleErr := errors.New("role failed")

	tests := []struct {
		name string
		run  func(*management.Service) error
	}{
		{
			name: "create role",
			run: func(service *management.Service) error {
				_, err := service.CreateRole(context.Background(), authkit.CreateRoleRequest{ID: "notes-reader"})

				return err
			},
		},
		{
			name: "grant role action",
			run: func(service *management.Service) error {
				return service.GrantRoleAction(context.Background(), authkit.GrantRoleActionRequest{
					RoleID: "notes-reader",
					Action: "notes:read",
				})
			},
		},
		{
			name: "assign principal role",
			run: func(service *management.Service) error {
				return service.AssignPrincipalRole(context.Background(), authkit.AssignPrincipalRoleRequest{
					PrincipalID: testPrincipalID,
					RoleID:      "notes-reader",
				})
			},
		},
		{
			name: "unassign principal role",
			run: func(service *management.Service) error {
				return service.UnassignPrincipalRole(context.Background(), authkit.UnassignPrincipalRoleRequest{
					PrincipalID: testPrincipalID,
					RoleID:      "notes-reader",
				})
			},
		},
		{
			name: "list principal role assignments",
			run: func(service *management.Service) error {
				_, err := service.ListPrincipalRoleAssignments(context.Background(), testPrincipalID)

				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roles := newFakeRoleStore()
			roles.err = roleErr
			service := newServiceWithRoles(
				t,
				newFakePrincipalCreator(),
				roles,
				newFakeIdentityLinker(),
				newFakeAPITokens(),
			)

			require.ErrorIs(t, tt.run(service), roleErr)
		})
	}
}

func TestServiceRoleMethodsRequireRolePorts(t *testing.T) {
	service := management.NewService(management.Options{
		PrincipalCreator: newFakePrincipalCreator(),
		IdentityLinker:   newFakeIdentityLinker(),
		APITokens:        newFakeAPITokens(),
	})

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "create role",
			run: func() error {
				_, runErr := service.CreateRole(context.Background(), authkit.CreateRoleRequest{
					ID: "notes-reader",
				})

				return runErr
			},
		},
		{
			name: "grant role action",
			run: func() error {
				return service.GrantRoleAction(context.Background(), authkit.GrantRoleActionRequest{
					RoleID: "notes-reader",
					Action: "notes:read",
				})
			},
		},
		{
			name: "assign principal role",
			run: func() error {
				return service.AssignPrincipalRole(context.Background(), authkit.AssignPrincipalRoleRequest{
					PrincipalID: testPrincipalID,
					RoleID:      "notes-reader",
				})
			},
		},
		{
			name: "unassign principal role",
			run: func() error {
				return service.UnassignPrincipalRole(context.Background(), authkit.UnassignPrincipalRoleRequest{
					PrincipalID: testPrincipalID,
					RoleID:      "notes-reader",
				})
			},
		},
		{
			name: "list principal role assignments",
			run: func() error {
				_, runErr := service.ListPrincipalRoleAssignments(context.Background(), testPrincipalID)

				return runErr
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.run())
		})
	}
}

func TestServiceProvisioningRuleMethods(t *testing.T) {
	rules := newFakeProvisioningRuleStore()
	rules.rule = provisioningRule()
	service := newServiceWithProvisioningRules(
		t,
		newFakePrincipalCreator(),
		newFakeRoleStore(),
		rules,
		newFakeIdentityLinker(),
		newFakeAPITokens(),
	)
	createReq := authkit.CreateProvisioningRuleRequest{
		ID:            rules.rule.ID,
		DisplayName:   rules.rule.DisplayName,
		Provider:      rules.rule.Provider,
		Condition:     rules.rule.Condition,
		AssignRoleIDs: rules.rule.AssignRoleIDs,
		Enabled:       rules.rule.Enabled,
	}
	updateReq := authkit.UpdateProvisioningRuleRequest{
		ID:            rules.rule.ID,
		DisplayName:   "Updated",
		Provider:      rules.rule.Provider,
		Condition:     rules.rule.Condition,
		AssignRoleIDs: rules.rule.AssignRoleIDs,
		Enabled:       false,
	}

	created, err := service.CreateProvisioningRule(context.Background(), createReq)
	require.NoError(t, err)
	assert.Equal(t, rules.rule, created)
	assert.Equal(t, []authkit.CreateProvisioningRuleRequest{createReq}, rules.createRequests)

	updated, err := service.UpdateProvisioningRule(context.Background(), updateReq)
	require.NoError(t, err)
	assert.Equal(t, rules.rule, updated)
	assert.Equal(t, []authkit.UpdateProvisioningRuleRequest{updateReq}, rules.updateRequests)

	found, err := service.FindProvisioningRule(context.Background(), rules.rule.ID)
	require.NoError(t, err)
	assert.Equal(t, rules.rule, found)
	assert.Equal(t, []string{rules.rule.ID}, rules.findIDs)

	listed, err := service.ListProvisioningRules(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []authkit.ProvisioningRule{rules.rule}, listed)
	assert.Equal(t, 1, rules.listCalls)

	require.NoError(t, service.DeleteProvisioningRule(context.Background(), rules.rule.ID))
	assert.Equal(t, []string{rules.rule.ID}, rules.deleteIDs)
}

func TestServiceWrapsProvisioningRuleErrors(t *testing.T) {
	ruleErr := errors.New("rule failed")

	tests := []struct {
		name string
		run  func(*management.Service) error
	}{
		{
			name: "create",
			run: func(service *management.Service) error {
				_, err := service.CreateProvisioningRule(context.Background(), authkit.CreateProvisioningRuleRequest{
					ID: "engineering-readers",
				})

				return err
			},
		},
		{
			name: "update",
			run: func(service *management.Service) error {
				_, err := service.UpdateProvisioningRule(context.Background(), authkit.UpdateProvisioningRuleRequest{
					ID: "engineering-readers",
				})

				return err
			},
		},
		{
			name: "delete",
			run: func(service *management.Service) error {
				return service.DeleteProvisioningRule(context.Background(), "engineering-readers")
			},
		},
		{
			name: "find",
			run: func(service *management.Service) error {
				_, err := service.FindProvisioningRule(context.Background(), "engineering-readers")

				return err
			},
		},
		{
			name: "list",
			run: func(service *management.Service) error {
				_, err := service.ListProvisioningRules(context.Background())

				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := newFakeProvisioningRuleStore()
			rules.err = ruleErr
			service := newServiceWithProvisioningRules(
				t,
				newFakePrincipalCreator(),
				newFakeRoleStore(),
				rules,
				newFakeIdentityLinker(),
				newFakeAPITokens(),
			)

			require.ErrorIs(t, tt.run(service), ruleErr)
		})
	}
}

func TestServiceProvisioningRuleMethodsRequirePorts(t *testing.T) {
	service := management.NewService(management.Options{
		PrincipalCreator: newFakePrincipalCreator(),
		IdentityLinker:   newFakeIdentityLinker(),
		APITokens:        newFakeAPITokens(),
	})

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "create",
			run: func() error {
				_, runErr := service.CreateProvisioningRule(
					context.Background(),
					authkit.CreateProvisioningRuleRequest{},
				)

				return runErr
			},
		},
		{
			name: "update",
			run: func() error {
				_, runErr := service.UpdateProvisioningRule(
					context.Background(),
					authkit.UpdateProvisioningRuleRequest{},
				)

				return runErr
			},
		},
		{
			name: "delete",
			run: func() error {
				return service.DeleteProvisioningRule(context.Background(), "engineering-readers")
			},
		},
		{
			name: "find",
			run: func() error {
				_, runErr := service.FindProvisioningRule(context.Background(), "engineering-readers")

				return runErr
			},
		},
		{
			name: "list",
			run: func() error {
				_, runErr := service.ListProvisioningRules(context.Background())

				return runErr
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.run())
		})
	}
}

func TestServiceLinkIdentity(t *testing.T) {
	linker := newFakeIdentityLinker()
	linker.identity = authkit.ExternalIdentity{
		Provider:    testProvider,
		Subject:     testSubject,
		PrincipalID: testPrincipalID,
	}
	service := newService(t, newFakePrincipalCreator(), linker, newFakeAPITokens())
	req := authkit.LinkIdentityRequest(linker.identity)

	identity, err := service.LinkIdentity(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, linker.identity, identity)
	assert.Equal(t, []authkit.LinkIdentityRequest{req}, linker.requests)
}

func TestServiceIssueAPITokenIssuesForExistingPrincipal(t *testing.T) {
	now := fixedTime()
	expiresAt := now.Add(time.Hour)
	apiTokens := newFakeAPITokens()
	apiTokens.issued = apikey.IssuedToken{
		ID:        testTokenID,
		Plaintext: testTokenSecret,
		ExpiresAt: expiresAt,
	}
	principals := newFakePrincipalCreator()
	principals.principal = authkit.Principal{
		ID:          testPrincipalID,
		Kind:        authkit.PrincipalKindService,
		DisplayName: testPrincipalName,
	}
	service := newService(t, principals, newFakeIdentityLinker(), apiTokens)
	req := management.IssueAPITokenRequest{
		PrincipalID: testPrincipalID,
		Name:        testTokenName,
		ExpiresAt:   expiresAt,
	}

	issued, err := service.IssueAPIToken(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, []string{testPrincipalID}, principals.findIDs)
	assert.Equal(t, []apikey.IssueRequest{{
		PrincipalID: testPrincipalID,
		Name:        testTokenName,
		ExpiresAt:   expiresAt,
	}}, apiTokens.issueRequests)
	assert.Equal(t, management.IssuedAPIToken{
		ID:          testTokenID,
		PrincipalID: testPrincipalID,
		Plaintext:   testTokenSecret,
		ExpiresAt:   expiresAt,
	}, issued)
}

func TestServiceIssueAPITokenRejectsMissingPrincipal(t *testing.T) {
	principals := newFakePrincipalCreator()
	principals.err = authkit.ErrPrincipalNotFound
	apiTokens := newFakeAPITokens()
	service := newService(t, principals, newFakeIdentityLinker(), apiTokens)

	issued, err := service.IssueAPIToken(context.Background(), management.IssueAPITokenRequest{
		PrincipalID: testPrincipalID,
		ExpiresAt:   fixedTime().Add(time.Hour),
	})

	require.ErrorIs(t, err, authkit.ErrPrincipalNotFound)
	assert.Empty(t, issued)
	assert.Equal(t, []string{testPrincipalID}, principals.findIDs)
	assert.Empty(t, apiTokens.issueRequests)
}

func TestServiceIssueAPITokenReturnsIssueErrorWithoutLinkingIdentity(t *testing.T) {
	issueErr := errors.New("issue failed")
	apiTokens := newFakeAPITokens()
	apiTokens.issueErr = issueErr
	linker := newFakeIdentityLinker()
	principals := newFakePrincipalCreator()
	principals.principal = authkit.Principal{ID: testPrincipalID}
	service := newService(t, principals, linker, apiTokens)

	issued, err := service.IssueAPIToken(context.Background(), management.IssueAPITokenRequest{
		PrincipalID: testPrincipalID,
		ExpiresAt:   fixedTime().Add(time.Hour),
	})

	require.ErrorIs(t, err, issueErr)
	assert.Empty(t, issued)
	assert.Empty(t, linker.requests)
	assert.Empty(t, apiTokens.revokedIDs)
}

func TestServiceRevokeAPIToken(t *testing.T) {
	apiTokens := newFakeAPITokens()
	service := newService(t, newFakePrincipalCreator(), newFakeIdentityLinker(), apiTokens)

	err := service.RevokeAPIToken(context.Background(), testTokenID)

	require.NoError(t, err)
	assert.Equal(t, []string{testTokenID}, apiTokens.revokedIDs)
}

func TestServiceRevokeAPITokenReturnsError(t *testing.T) {
	revokeErr := errors.New("revoke failed")
	apiTokens := newFakeAPITokens()
	apiTokens.revokeErr = revokeErr
	service := newService(t, newFakePrincipalCreator(), newFakeIdentityLinker(), apiTokens)

	err := service.RevokeAPIToken(context.Background(), testTokenID)

	require.ErrorIs(t, err, revokeErr)
}

func TestServiceListPrincipalAPITokenMetadata(t *testing.T) {
	apiTokens := newFakeAPITokens()
	apiTokens.metadata = []apikey.TokenMetadata{{
		ID:          testTokenID,
		PrincipalID: testPrincipalID,
		Name:        testTokenName,
		ExpiresAt:   fixedTime().Add(time.Hour),
	}}
	service := management.NewService(management.Options{
		APITokenMetadataLister: apiTokens,
	})

	tokens, err := service.ListPrincipalAPITokenMetadata(context.Background(), testPrincipalID)

	require.NoError(t, err)
	assert.Equal(t, apiTokens.metadata, tokens)
	assert.Equal(t, []string{testPrincipalID}, apiTokens.metadataPrincipalIDs)
}

func TestServicePropagatesContextCancellation(t *testing.T) {
	now := fixedTime()
	store := memory.NewStore()
	tokenService, err := apikey.NewService(store, apikey.WithClock(func() time.Time {
		return now
	}))
	require.NoError(t, err)
	service := newManagementService(t, store, tokenService)
	principal, err := store.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
		Kind: authkit.PrincipalKindService,
	})
	require.NoError(t, err)
	token, err := tokenService.IssueToken(context.Background(), apikey.IssueRequest{
		PrincipalID: principal.ID,
		ExpiresAt:   now.Add(time.Hour),
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "create principal",
			run: func() error {
				_, runErr := service.CreatePrincipal(ctx, authkit.CreatePrincipalRequest{
					Kind: authkit.PrincipalKindService,
				})

				return runErr
			},
		},
		{
			name: "find principal",
			run: func() error {
				_, runErr := service.FindPrincipal(ctx, principal.ID)

				return runErr
			},
		},
		{
			name: "list principals",
			run: func() error {
				_, runErr := service.ListPrincipals(ctx)

				return runErr
			},
		},
		{
			name: "link identity",
			run: func() error {
				_, runErr := service.LinkIdentity(ctx, authkit.LinkIdentityRequest{
					Provider:    testProvider,
					Subject:     testSubject,
					PrincipalID: principal.ID,
				})

				return runErr
			},
		},
		{
			name: "create role",
			run: func() error {
				_, runErr := service.CreateRole(ctx, authkit.CreateRoleRequest{
					ID: "notes-reader",
				})

				return runErr
			},
		},
		{
			name: "grant role action",
			run: func() error {
				return service.GrantRoleAction(ctx, authkit.GrantRoleActionRequest{
					RoleID: "notes-reader",
					Action: "notes:read",
				})
			},
		},
		{
			name: "assign principal role",
			run: func() error {
				return service.AssignPrincipalRole(ctx, authkit.AssignPrincipalRoleRequest{
					PrincipalID: principal.ID,
					RoleID:      "notes-reader",
				})
			},
		},
		{
			name: "unassign principal role",
			run: func() error {
				return service.UnassignPrincipalRole(ctx, authkit.UnassignPrincipalRoleRequest{
					PrincipalID: principal.ID,
					RoleID:      "notes-reader",
				})
			},
		},
		{
			name: "list principal role assignments",
			run: func() error {
				_, runErr := service.ListPrincipalRoleAssignments(ctx, principal.ID)

				return runErr
			},
		},
		{
			name: "create provisioning rule",
			run: func() error {
				_, runErr := service.CreateProvisioningRule(ctx, authkit.CreateProvisioningRuleRequest{})

				return runErr
			},
		},
		{
			name: "update provisioning rule",
			run: func() error {
				_, runErr := service.UpdateProvisioningRule(ctx, authkit.UpdateProvisioningRuleRequest{})

				return runErr
			},
		},
		{
			name: "delete provisioning rule",
			run: func() error {
				return service.DeleteProvisioningRule(ctx, "engineering-readers")
			},
		},
		{
			name: "find provisioning rule",
			run: func() error {
				_, runErr := service.FindProvisioningRule(ctx, "engineering-readers")

				return runErr
			},
		},
		{
			name: "list provisioning rules",
			run: func() error {
				_, runErr := service.ListProvisioningRules(ctx)

				return runErr
			},
		},
		{
			name: "issue API token",
			run: func() error {
				_, runErr := service.IssueAPIToken(ctx, management.IssueAPITokenRequest{
					PrincipalID: principal.ID,
					ExpiresAt:   now.Add(time.Hour),
				})

				return runErr
			},
		},
		{
			name: "revoke API token",
			run: func() error {
				return service.RevokeAPIToken(ctx, token.ID)
			},
		},
		{
			name: "list API token metadata",
			run: func() error {
				_, runErr := service.ListPrincipalAPITokenMetadata(ctx, principal.ID)

				return runErr
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorIs(t, tt.run(), context.Canceled)
		})
	}
}

func TestServiceIssueAPITokenResolvesThroughMemoryStore(t *testing.T) {
	now := fixedTime()
	store := memory.NewStore()
	tokenService, err := apikey.NewService(store, apikey.WithClock(func() time.Time {
		return now
	}))
	require.NoError(t, err)
	service := newManagementService(t, store, tokenService)
	principal, err := service.CreatePrincipal(context.Background(), authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindService,
		DisplayName: testPrincipalName,
	})
	require.NoError(t, err)

	issued, err := service.IssueAPIToken(context.Background(), management.IssueAPITokenRequest{
		PrincipalID: principal.ID,
		Name:        testTokenName,
		ExpiresAt:   now.Add(time.Hour),
	})
	require.NoError(t, err)
	verified, err := tokenService.VerifyAPIToken(context.Background(), issued.Plaintext)
	require.NoError(t, err)
	assert.Equal(t, principal.ID, issued.PrincipalID)
	assert.Equal(t, apikey.VerifiedToken{
		ID:          issued.ID,
		PrincipalID: principal.ID,
		ExpiresAt:   issued.ExpiresAt,
	}, verified)
}

func newService(
	t *testing.T,
	principals principalStore,
	linker authkit.IdentityLinker,
	apiTokens management.APITokens,
) *management.Service {
	t.Helper()

	return newServiceWithRoles(t, principals, newFakeRoleStore(), linker, apiTokens)
}

func newServiceWithRoles(
	t *testing.T,
	principals principalStore,
	roles roleStore,
	linker authkit.IdentityLinker,
	apiTokens management.APITokens,
) *management.Service {
	t.Helper()

	service := management.NewService(management.Options{
		PrincipalCreator:              principals,
		PrincipalFinder:               principals,
		RoleCreator:                   roles,
		RoleActionGranter:             roles,
		PrincipalRoleAssigner:         roles,
		PrincipalRoleUnassigner:       roles,
		PrincipalRoleAssignmentLister: roles,
		IdentityLinker:                linker,
		APITokens:                     apiTokens,
	})

	return service
}

func newServiceWithProvisioningRules(
	t *testing.T,
	principals principalStore,
	roles roleStore,
	rules provisioningRuleStore,
	linker authkit.IdentityLinker,
	apiTokens management.APITokens,
) *management.Service {
	t.Helper()

	service := management.NewService(management.Options{
		PrincipalCreator:              principals,
		PrincipalFinder:               principals,
		RoleCreator:                   roles,
		RoleActionGranter:             roles,
		PrincipalRoleAssigner:         roles,
		PrincipalRoleUnassigner:       roles,
		PrincipalRoleAssignmentLister: roles,
		ProvisioningRuleCreator:       rules,
		ProvisioningRuleUpdater:       rules,
		ProvisioningRuleDeleter:       rules,
		ProvisioningRuleFinder:        rules,
		ProvisioningRuleLister:        rules,
		IdentityLinker:                linker,
		APITokens:                     apiTokens,
	})

	return service
}

func newManagementService(
	t *testing.T,
	store *memory.Store,
	tokenService *apikey.Service,
) *management.Service {
	t.Helper()

	return management.NewService(management.Options{
		PrincipalCreator:              store,
		PrincipalFinder:               store,
		PrincipalLister:               store,
		RoleCreator:                   store,
		RoleActionGranter:             store,
		PrincipalRoleAssigner:         store,
		PrincipalRoleUnassigner:       store,
		PrincipalRoleAssignmentLister: store,
		ProvisioningRuleCreator:       store,
		ProvisioningRuleUpdater:       store,
		ProvisioningRuleDeleter:       store,
		ProvisioningRuleFinder:        store,
		ProvisioningRuleLister:        store,
		IdentityLinker:                store,
		APITokens:                     tokenService,
		APITokenMetadataLister:        store,
	})
}

type roleStore interface {
	authkit.RoleCreator
	authkit.RoleActionGranter
	authkit.PrincipalRoleAssigner
	authkit.PrincipalRoleUnassigner
	authkit.PrincipalRoleAssignmentLister
}

type principalStore interface {
	authkit.PrincipalCreator
	authkit.PrincipalFinder
}

type provisioningRuleStore interface {
	authkit.ProvisioningRuleCreator
	authkit.ProvisioningRuleUpdater
	authkit.ProvisioningRuleDeleter
	authkit.ProvisioningRuleFinder
	authkit.ProvisioningRuleLister
}

func newFakePrincipalCreator() *fakePrincipalCreator {
	return &fakePrincipalCreator{}
}

func newFakeIdentityLinker() *fakeIdentityLinker {
	return &fakeIdentityLinker{}
}

func newFakeRoleStore() *fakeRoleStore {
	return &fakeRoleStore{}
}

func newFakeProvisioningRuleStore() *fakeProvisioningRuleStore {
	return &fakeProvisioningRuleStore{}
}

func newFakeAPITokens() *fakeAPITokens {
	return &fakeAPITokens{}
}

func fixedTime() time.Time {
	return time.Date(2026, time.May, 8, 12, 0, 0, 0, time.UTC)
}

func provisioningRule() authkit.ProvisioningRule {
	return authkit.ProvisioningRule{
		ID:            "engineering-readers",
		DisplayName:   "Engineering readers",
		Provider:      "https://issuer.example",
		Condition:     `hasAny(claims.groups, ["/engineering"])`,
		AssignRoleIDs: []string{"notes-reader"},
		Enabled:       true,
	}
}

type fakePrincipalCreator struct {
	requests   []authkit.CreatePrincipalRequest
	findIDs    []string
	listCalls  int
	principal  authkit.Principal
	principals []authkit.Principal
	err        error
}

func (f *fakePrincipalCreator) CreatePrincipal(
	_ context.Context,
	req authkit.CreatePrincipalRequest,
) (authkit.Principal, error) {
	f.requests = append(f.requests, req)
	if f.err != nil {
		return authkit.Principal{}, f.err
	}

	return f.principal, nil
}

func (f *fakePrincipalCreator) FindPrincipal(_ context.Context, id string) (authkit.Principal, error) {
	f.findIDs = append(f.findIDs, id)
	if f.err != nil {
		return authkit.Principal{}, f.err
	}

	return f.principal, nil
}

func (f *fakePrincipalCreator) ListPrincipals(_ context.Context) ([]authkit.Principal, error) {
	f.listCalls++
	if f.err != nil {
		return nil, f.err
	}

	return f.principals, nil
}

type fakeIdentityLinker struct {
	requests []authkit.LinkIdentityRequest
	identity authkit.ExternalIdentity
	err      error
}

func (f *fakeIdentityLinker) LinkIdentity(
	_ context.Context,
	req authkit.LinkIdentityRequest,
) (authkit.ExternalIdentity, error) {
	f.requests = append(f.requests, req)
	if f.err != nil {
		return authkit.ExternalIdentity{}, f.err
	}

	return f.identity, nil
}

type fakeRoleStore struct {
	createRequests   []authkit.CreateRoleRequest
	grantRequests    []authkit.GrantRoleActionRequest
	assignRequests   []authkit.AssignPrincipalRoleRequest
	unassignRequests []authkit.UnassignPrincipalRoleRequest
	listPrincipalIDs []string
	role             authkit.Role
	assignments      []authkit.PrincipalRoleAssignment
	err              error
}

func (f *fakeRoleStore) CreateRole(
	_ context.Context,
	req authkit.CreateRoleRequest,
) (authkit.Role, error) {
	f.createRequests = append(f.createRequests, req)
	if f.err != nil {
		return authkit.Role{}, f.err
	}

	return f.role, nil
}

func (f *fakeRoleStore) GrantRoleAction(
	_ context.Context,
	req authkit.GrantRoleActionRequest,
) error {
	f.grantRequests = append(f.grantRequests, req)
	if f.err != nil {
		return f.err
	}

	return nil
}

func (f *fakeRoleStore) AssignPrincipalRole(
	_ context.Context,
	req authkit.AssignPrincipalRoleRequest,
) error {
	f.assignRequests = append(f.assignRequests, req)
	if f.err != nil {
		return f.err
	}

	return nil
}

func (f *fakeRoleStore) UnassignPrincipalRole(
	_ context.Context,
	req authkit.UnassignPrincipalRoleRequest,
) error {
	f.unassignRequests = append(f.unassignRequests, req)
	if f.err != nil {
		return f.err
	}

	return nil
}

func (f *fakeRoleStore) ListPrincipalRoleAssignments(
	_ context.Context,
	principalID string,
) ([]authkit.PrincipalRoleAssignment, error) {
	f.listPrincipalIDs = append(f.listPrincipalIDs, principalID)
	if f.err != nil {
		return nil, f.err
	}

	return f.assignments, nil
}

type fakeProvisioningRuleStore struct {
	createRequests []authkit.CreateProvisioningRuleRequest
	updateRequests []authkit.UpdateProvisioningRuleRequest
	deleteIDs      []string
	findIDs        []string
	listCalls      int
	rule           authkit.ProvisioningRule
	err            error
}

func (f *fakeProvisioningRuleStore) CreateProvisioningRule(
	_ context.Context,
	req authkit.CreateProvisioningRuleRequest,
) (authkit.ProvisioningRule, error) {
	f.createRequests = append(f.createRequests, req)
	if f.err != nil {
		return authkit.ProvisioningRule{}, f.err
	}

	return f.rule, nil
}

func (f *fakeProvisioningRuleStore) UpdateProvisioningRule(
	_ context.Context,
	req authkit.UpdateProvisioningRuleRequest,
) (authkit.ProvisioningRule, error) {
	f.updateRequests = append(f.updateRequests, req)
	if f.err != nil {
		return authkit.ProvisioningRule{}, f.err
	}

	return f.rule, nil
}

func (f *fakeProvisioningRuleStore) DeleteProvisioningRule(_ context.Context, id string) error {
	f.deleteIDs = append(f.deleteIDs, id)
	if f.err != nil {
		return f.err
	}

	return nil
}

func (f *fakeProvisioningRuleStore) FindProvisioningRule(
	_ context.Context,
	id string,
) (authkit.ProvisioningRule, error) {
	f.findIDs = append(f.findIDs, id)
	if f.err != nil {
		return authkit.ProvisioningRule{}, f.err
	}

	return f.rule, nil
}

func (f *fakeProvisioningRuleStore) ListProvisioningRules(
	context.Context,
) ([]authkit.ProvisioningRule, error) {
	f.listCalls++
	if f.err != nil {
		return nil, f.err
	}

	return []authkit.ProvisioningRule{f.rule}, nil
}

type fakeAPITokens struct {
	issueRequests        []apikey.IssueRequest
	issued               apikey.IssuedToken
	issueErr             error
	revokedIDs           []string
	revokeErr            error
	metadataPrincipalIDs []string
	metadata             []apikey.TokenMetadata
	metadataErr          error
}

func (f *fakeAPITokens) IssueToken(
	_ context.Context,
	req apikey.IssueRequest,
) (apikey.IssuedToken, error) {
	f.issueRequests = append(f.issueRequests, req)
	if f.issueErr != nil {
		return apikey.IssuedToken{}, f.issueErr
	}

	return f.issued, nil
}

func (f *fakeAPITokens) RevokeToken(_ context.Context, tokenID string) error {
	f.revokedIDs = append(f.revokedIDs, tokenID)
	if f.revokeErr != nil {
		return f.revokeErr
	}

	return nil
}

func (f *fakeAPITokens) ListPrincipalTokenMetadata(
	_ context.Context,
	principalID string,
) ([]apikey.TokenMetadata, error) {
	f.metadataPrincipalIDs = append(f.metadataPrincipalIDs, principalID)
	if f.metadataErr != nil {
		return nil, f.metadataErr
	}

	return f.metadata, nil
}
