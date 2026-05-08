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

	// IdentityLinker links external identities to internal principals.
	IdentityLinker authkit.IdentityLinker

	// APITokens issues and revokes API tokens.
	APITokens APITokens
}

// Service composes common authkit management operations.
type Service struct {
	principalCreator authkit.PrincipalCreator
	identityLinker   authkit.IdentityLinker
	apiTokens        APITokens
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
		principalCreator: opts.PrincipalCreator,
		identityLinker:   opts.IdentityLinker,
		apiTokens:        opts.APITokens,
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
