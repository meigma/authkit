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

	// RoleCreator creates local roles.
	RoleCreator authkit.RoleCreator

	// RoleActionGranter grants authorization actions to roles.
	RoleActionGranter authkit.RoleActionGranter

	// PrincipalRoleAssigner assigns principals to roles.
	PrincipalRoleAssigner authkit.PrincipalRoleAssigner

	// IdentityLinker links external identities to internal principals.
	IdentityLinker authkit.IdentityLinker

	// APITokens issues and revokes API tokens.
	APITokens APITokens
}

// Service composes common authkit management operations.
type Service struct {
	principalCreator      authkit.PrincipalCreator
	roleCreator           authkit.RoleCreator
	roleActionGranter     authkit.RoleActionGranter
	principalRoleAssigner authkit.PrincipalRoleAssigner
	identityLinker        authkit.IdentityLinker
	apiTokens             APITokens
}

// NewService constructs a management service from opts.
func NewService(opts Options) (*Service, error) {
	if opts.PrincipalCreator == nil {
		return nil, errors.New("management: principal creator is required")
	}
	if opts.IdentityLinker == nil {
		return nil, errors.New("management: identity linker is required")
	}
	if opts.APITokens == nil {
		return nil, errors.New("management: API tokens service is required")
	}

	return &Service{
		principalCreator:      opts.PrincipalCreator,
		roleCreator:           opts.RoleCreator,
		roleActionGranter:     opts.RoleActionGranter,
		principalRoleAssigner: opts.PrincipalRoleAssigner,
		identityLinker:        opts.IdentityLinker,
		apiTokens:             opts.APITokens,
	}, nil
}

// CreatePrincipal creates an internal principal.
func (s *Service) CreatePrincipal(
	ctx context.Context,
	req authkit.CreatePrincipalRequest,
) (authkit.Principal, error) {
	principal, err := s.principalCreator.CreatePrincipal(ctx, req)
	if err != nil {
		return authkit.Principal{}, fmt.Errorf("management: create principal: %w", err)
	}

	return principal, nil
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

// LinkIdentity links an external identity to an internal principal.
func (s *Service) LinkIdentity(
	ctx context.Context,
	req authkit.LinkIdentityRequest,
) (authkit.ExternalIdentity, error) {
	identity, err := s.identityLinker.LinkIdentity(ctx, req)
	if err != nil {
		return authkit.ExternalIdentity{}, fmt.Errorf("management: link identity: %w", err)
	}

	return identity, nil
}

// IssueAPIToken issues an API token and links its API-token identity.
func (s *Service) IssueAPIToken(ctx context.Context, req IssueAPITokenRequest) (IssuedAPIToken, error) {
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
	if err := s.apiTokens.RevokeToken(ctx, tokenID); err != nil {
		return fmt.Errorf("management: revoke API token: %w", err)
	}

	return nil
}
