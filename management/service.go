package management

import (
	"context"
	"errors"
	"fmt"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/apikey"
)

// APITokens issues and revokes opaque API tokens.
type APITokens interface {
	// IssueToken issues an opaque API token for an existing principal.
	IssueToken(ctx context.Context, req apikey.IssueRequest) (apikey.IssuedToken, error)

	// RevokeToken revokes tokenID.
	RevokeToken(ctx context.Context, tokenID string) error
}

// Options configures a Service.
type Options struct {
	// PrincipalCreator creates internal principals.
	PrincipalCreator authkit.PrincipalCreator

	// PrincipalFinder finds internal principals.
	PrincipalFinder authkit.PrincipalFinder

	// PrincipalLister lists internal principals.
	PrincipalLister authkit.PrincipalLister

	// RoleCreator creates local roles.
	RoleCreator authkit.RoleCreator

	// RoleActionGranter grants authorization actions to roles.
	RoleActionGranter authkit.RoleActionGranter

	// PrincipalRoleAssigner assigns principals to roles.
	PrincipalRoleAssigner authkit.PrincipalRoleAssigner

	// PrincipalRoleUnassigner removes principals from roles.
	PrincipalRoleUnassigner authkit.PrincipalRoleUnassigner

	// PrincipalRoleAssignmentLister lists role assignments for principals.
	PrincipalRoleAssignmentLister authkit.PrincipalRoleAssignmentLister

	// ProvisioningRuleCreator creates provisioning rules.
	ProvisioningRuleCreator authkit.ProvisioningRuleCreator

	// ProvisioningRuleUpdater updates provisioning rules.
	ProvisioningRuleUpdater authkit.ProvisioningRuleUpdater

	// ProvisioningRuleDeleter deletes provisioning rules.
	ProvisioningRuleDeleter authkit.ProvisioningRuleDeleter

	// ProvisioningRuleFinder finds provisioning rules.
	ProvisioningRuleFinder authkit.ProvisioningRuleFinder

	// ProvisioningRuleLister lists provisioning rules.
	ProvisioningRuleLister authkit.ProvisioningRuleLister

	// IdentityLinker links external identities to internal principals.
	IdentityLinker authkit.IdentityLinker

	// APITokens issues and revokes API tokens.
	APITokens APITokens

	// APITokenMetadataLister lists API-token metadata.
	APITokenMetadataLister apikey.TokenMetadataLister
}

// Service composes common authkit management operations.
type Service struct {
	principalCreator        authkit.PrincipalCreator
	principalFinder         authkit.PrincipalFinder
	principalLister         authkit.PrincipalLister
	roleCreator             authkit.RoleCreator
	roleActionGranter       authkit.RoleActionGranter
	principalRoleAssigner   authkit.PrincipalRoleAssigner
	principalRoleUnassigner authkit.PrincipalRoleUnassigner
	roleAssignmentLister    authkit.PrincipalRoleAssignmentLister
	provisioningRuleCreator authkit.ProvisioningRuleCreator
	provisioningRuleUpdater authkit.ProvisioningRuleUpdater
	provisioningRuleDeleter authkit.ProvisioningRuleDeleter
	provisioningRuleFinder  authkit.ProvisioningRuleFinder
	provisioningRuleLister  authkit.ProvisioningRuleLister
	identityLinker          authkit.IdentityLinker
	apiTokens               APITokens
	apiTokenMetadataLister  apikey.TokenMetadataLister
}

// NewService constructs a management service from opts.
func NewService(opts Options) *Service {
	return &Service{
		principalCreator:        opts.PrincipalCreator,
		principalFinder:         opts.PrincipalFinder,
		principalLister:         opts.PrincipalLister,
		roleCreator:             opts.RoleCreator,
		roleActionGranter:       opts.RoleActionGranter,
		principalRoleAssigner:   opts.PrincipalRoleAssigner,
		principalRoleUnassigner: opts.PrincipalRoleUnassigner,
		roleAssignmentLister:    opts.PrincipalRoleAssignmentLister,
		provisioningRuleCreator: opts.ProvisioningRuleCreator,
		provisioningRuleUpdater: opts.ProvisioningRuleUpdater,
		provisioningRuleDeleter: opts.ProvisioningRuleDeleter,
		provisioningRuleFinder:  opts.ProvisioningRuleFinder,
		provisioningRuleLister:  opts.ProvisioningRuleLister,
		identityLinker:          opts.IdentityLinker,
		apiTokens:               opts.APITokens,
		apiTokenMetadataLister:  opts.APITokenMetadataLister,
	}
}

// CreatePrincipal creates an internal principal.
func (s *Service) CreatePrincipal(
	ctx context.Context,
	req authkit.CreatePrincipalRequest,
) (authkit.Principal, error) {
	if s.principalCreator == nil {
		return authkit.Principal{}, errors.New("management: principal creator is required")
	}

	principal, err := s.principalCreator.CreatePrincipal(ctx, req)
	if err != nil {
		return authkit.Principal{}, fmt.Errorf("management: create principal: %w", err)
	}

	return principal, nil
}

// FindPrincipal returns a principal by ID.
func (s *Service) FindPrincipal(ctx context.Context, id string) (authkit.Principal, error) {
	if s.principalFinder == nil {
		return authkit.Principal{}, errors.New("management: principal finder is required")
	}

	principal, err := s.principalFinder.FindPrincipal(ctx, id)
	if err != nil {
		return authkit.Principal{}, fmt.Errorf("management: find principal: %w", err)
	}

	return principal, nil
}

// ListPrincipals returns principals.
func (s *Service) ListPrincipals(ctx context.Context) ([]authkit.Principal, error) {
	if s.principalLister == nil {
		return nil, errors.New("management: principal lister is required")
	}

	principals, err := s.principalLister.ListPrincipals(ctx)
	if err != nil {
		return nil, fmt.Errorf("management: list principals: %w", err)
	}

	return principals, nil
}

// CreateRole creates a local role.
func (s *Service) CreateRole(
	ctx context.Context,
	req authkit.CreateRoleRequest,
) (authkit.Role, error) {
	if s.roleCreator == nil {
		return authkit.Role{}, errors.New("management: role creator is required")
	}

	role, err := s.roleCreator.CreateRole(ctx, req)
	if err != nil {
		return authkit.Role{}, fmt.Errorf("management: create role: %w", err)
	}

	return role, nil
}

// GrantRoleAction grants an authorization action to a local role.
func (s *Service) GrantRoleAction(ctx context.Context, req authkit.GrantRoleActionRequest) error {
	if s.roleActionGranter == nil {
		return errors.New("management: role action granter is required")
	}

	if err := s.roleActionGranter.GrantRoleAction(ctx, req); err != nil {
		return fmt.Errorf("management: grant role action: %w", err)
	}

	return nil
}

// AssignPrincipalRole assigns a principal to a local role.
func (s *Service) AssignPrincipalRole(ctx context.Context, req authkit.AssignPrincipalRoleRequest) error {
	if s.principalRoleAssigner == nil {
		return errors.New("management: principal role assigner is required")
	}

	if err := s.principalRoleAssigner.AssignPrincipalRole(ctx, req); err != nil {
		return fmt.Errorf("management: assign principal role: %w", err)
	}

	return nil
}

// UnassignPrincipalRole removes a principal from a local role.
func (s *Service) UnassignPrincipalRole(ctx context.Context, req authkit.UnassignPrincipalRoleRequest) error {
	if s.principalRoleUnassigner == nil {
		return errors.New("management: principal role unassigner is required")
	}

	if err := s.principalRoleUnassigner.UnassignPrincipalRole(ctx, req); err != nil {
		return fmt.Errorf("management: unassign principal role: %w", err)
	}

	return nil
}

// ListPrincipalRoleAssignments returns role assignments for a principal.
func (s *Service) ListPrincipalRoleAssignments(
	ctx context.Context,
	principalID string,
) ([]authkit.PrincipalRoleAssignment, error) {
	if s.roleAssignmentLister == nil {
		return nil, errors.New("management: principal role assignment lister is required")
	}

	assignments, err := s.roleAssignmentLister.ListPrincipalRoleAssignments(ctx, principalID)
	if err != nil {
		return nil, fmt.Errorf("management: list principal role assignments: %w", err)
	}

	return assignments, nil
}

// CreateProvisioningRule creates a provisioning rule.
func (s *Service) CreateProvisioningRule(
	ctx context.Context,
	req authkit.CreateProvisioningRuleRequest,
) (authkit.ProvisioningRule, error) {
	if s.provisioningRuleCreator == nil {
		return authkit.ProvisioningRule{}, errors.New("management: provisioning rule creator is required")
	}

	rule, err := s.provisioningRuleCreator.CreateProvisioningRule(ctx, req)
	if err != nil {
		return authkit.ProvisioningRule{}, fmt.Errorf("management: create provisioning rule: %w", err)
	}

	return rule, nil
}

// UpdateProvisioningRule updates a provisioning rule.
func (s *Service) UpdateProvisioningRule(
	ctx context.Context,
	req authkit.UpdateProvisioningRuleRequest,
) (authkit.ProvisioningRule, error) {
	if s.provisioningRuleUpdater == nil {
		return authkit.ProvisioningRule{}, errors.New("management: provisioning rule updater is required")
	}

	rule, err := s.provisioningRuleUpdater.UpdateProvisioningRule(ctx, req)
	if err != nil {
		return authkit.ProvisioningRule{}, fmt.Errorf("management: update provisioning rule: %w", err)
	}

	return rule, nil
}

// DeleteProvisioningRule deletes a provisioning rule.
func (s *Service) DeleteProvisioningRule(ctx context.Context, id string) error {
	if s.provisioningRuleDeleter == nil {
		return errors.New("management: provisioning rule deleter is required")
	}

	if err := s.provisioningRuleDeleter.DeleteProvisioningRule(ctx, id); err != nil {
		return fmt.Errorf("management: delete provisioning rule: %w", err)
	}

	return nil
}

// FindProvisioningRule returns a provisioning rule by ID.
func (s *Service) FindProvisioningRule(ctx context.Context, id string) (authkit.ProvisioningRule, error) {
	if s.provisioningRuleFinder == nil {
		return authkit.ProvisioningRule{}, errors.New("management: provisioning rule finder is required")
	}

	rule, err := s.provisioningRuleFinder.FindProvisioningRule(ctx, id)
	if err != nil {
		return authkit.ProvisioningRule{}, fmt.Errorf("management: find provisioning rule: %w", err)
	}

	return rule, nil
}

// ListProvisioningRules returns provisioning rules.
func (s *Service) ListProvisioningRules(ctx context.Context) ([]authkit.ProvisioningRule, error) {
	if s.provisioningRuleLister == nil {
		return nil, errors.New("management: provisioning rule lister is required")
	}

	rules, err := s.provisioningRuleLister.ListProvisioningRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("management: list provisioning rules: %w", err)
	}

	return rules, nil
}

// LinkIdentity links an external identity to an internal principal.
func (s *Service) LinkIdentity(
	ctx context.Context,
	req authkit.LinkIdentityRequest,
) (authkit.ExternalIdentity, error) {
	if s.identityLinker == nil {
		return authkit.ExternalIdentity{}, errors.New("management: identity linker is required")
	}

	identity, err := s.identityLinker.LinkIdentity(ctx, req)
	if err != nil {
		return authkit.ExternalIdentity{}, fmt.Errorf("management: link identity: %w", err)
	}

	return identity, nil
}

// IssueAPIToken issues an API token and links its API-token identity.
func (s *Service) IssueAPIToken(ctx context.Context, req IssueAPITokenRequest) (IssuedAPIToken, error) {
	if s.apiTokens == nil {
		return IssuedAPIToken{}, errors.New("management: API tokens service is required")
	}
	if s.identityLinker == nil {
		return IssuedAPIToken{}, errors.New("management: identity linker is required")
	}

	issued, err := s.apiTokens.IssueToken(ctx, apikey.IssueRequest{
		PrincipalID: req.PrincipalID,
		Name:        req.Name,
		ExpiresAt:   req.ExpiresAt,
	})
	if err != nil {
		return IssuedAPIToken{}, fmt.Errorf("management: issue API token: %w", err)
	}

	identity, err := s.identityLinker.LinkIdentity(ctx, issued.IdentityLink)
	if err != nil {
		_ = s.apiTokens.RevokeToken(ctx, issued.ID)

		return IssuedAPIToken{}, fmt.Errorf("management: link API token identity: %w", err)
	}

	return IssuedAPIToken{
		ID:        issued.ID,
		Plaintext: issued.Plaintext,
		ExpiresAt: issued.ExpiresAt,
		Identity:  identity,
	}, nil
}

// RevokeAPIToken revokes tokenID.
func (s *Service) RevokeAPIToken(ctx context.Context, tokenID string) error {
	if s.apiTokens == nil {
		return errors.New("management: API tokens service is required")
	}

	if err := s.apiTokens.RevokeToken(ctx, tokenID); err != nil {
		return fmt.Errorf("management: revoke API token: %w", err)
	}

	return nil
}

// ListPrincipalAPITokenMetadata returns API-token metadata for a principal.
func (s *Service) ListPrincipalAPITokenMetadata(
	ctx context.Context,
	principalID string,
) ([]apikey.TokenMetadata, error) {
	if s.apiTokenMetadataLister == nil {
		return nil, errors.New("management: API token metadata lister is required")
	}

	tokens, err := s.apiTokenMetadataLister.ListPrincipalTokenMetadata(ctx, principalID)
	if err != nil {
		return nil, fmt.Errorf("management: list principal API token metadata: %w", err)
	}

	return tokens, nil
}
