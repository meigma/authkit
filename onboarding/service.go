package onboarding

import (
	"context"
	"errors"
	"fmt"

	"github.com/meigma/authkit"
)

// Service composes explicit identity attachment and principal provisioning flows.
type Service struct {
	principalFinder     authkit.PrincipalFinder
	identityLinker      authkit.IdentityLinker
	identityProvisioner authkit.IdentityProvisioner
}

// NewService constructs an onboarding service from opts.
func NewService(opts Options) *Service {
	return &Service{
		principalFinder:     opts.PrincipalFinder,
		identityLinker:      opts.IdentityLinker,
		identityProvisioner: opts.IdentityProvisioner,
	}
}

// AttachIdentity links a verified identity to an existing principal.
func (s *Service) AttachIdentity(
	ctx context.Context,
	req AttachIdentityRequest,
) (AttachIdentityResult, error) {
	if s.principalFinder == nil {
		return AttachIdentityResult{}, errors.New("onboarding: principal finder is required")
	}
	if s.identityLinker == nil {
		return AttachIdentityResult{}, errors.New("onboarding: identity linker is required")
	}
	if err := validateIdentity(req.Identity); err != nil {
		return AttachIdentityResult{}, err
	}
	if req.PrincipalID == "" {
		return AttachIdentityResult{}, errors.New("onboarding: principal ID is required")
	}

	principal, err := s.principalFinder.FindPrincipal(ctx, req.PrincipalID)
	if err != nil {
		return AttachIdentityResult{}, fmt.Errorf("onboarding: find principal: %w", err)
	}

	link, err := s.identityLinker.LinkIdentity(ctx, authkit.LinkIdentityRequest{
		Provider:    req.Identity.Provider,
		Subject:     req.Identity.Subject,
		PrincipalID: req.PrincipalID,
	})
	if err != nil {
		return AttachIdentityResult{}, fmt.Errorf("onboarding: link identity: %w", err)
	}

	return AttachIdentityResult{
		Principal: principal,
		Link:      link,
	}, nil
}

// ProvisionPrincipal creates or resolves a principal for a verified identity.
func (s *Service) ProvisionPrincipal(
	ctx context.Context,
	req ProvisionPrincipalRequest,
) (ProvisionPrincipalResult, error) {
	if s.identityProvisioner == nil {
		return ProvisionPrincipalResult{}, errors.New("onboarding: identity provisioner is required")
	}
	if err := validateIdentity(req.Identity); err != nil {
		return ProvisionPrincipalResult{}, err
	}

	result, err := s.identityProvisioner.ProvisionIdentity(ctx, authkit.ProvisionIdentityRequest{
		Identity:       req.Identity,
		Principal:      req.Principal,
		InitialRoleIDs: req.InitialRoleIDs,
	})
	if err != nil {
		return ProvisionPrincipalResult{}, fmt.Errorf("onboarding: provision principal: %w", err)
	}

	return ProvisionPrincipalResult{
		Principal: result.Principal,
		Link:      result.Link,
		Created:   result.Created,
	}, nil
}

func validateIdentity(identity authkit.Identity) error {
	if identity.Provider == "" {
		return errors.New("onboarding: identity provider is required")
	}
	if identity.Subject == "" {
		return errors.New("onboarding: identity subject is required")
	}

	return nil
}
