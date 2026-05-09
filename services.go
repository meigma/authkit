package authkit

import "context"

// CreatePrincipalRequest describes a request to create an internal principal.
type CreatePrincipalRequest struct {
	// Kind classifies the principal being created.
	Kind PrincipalKind

	// DisplayName is a human-readable principal label.
	DisplayName string

	// Attributes contains optional application-owned principal metadata.
	Attributes map[string]any
}

// LinkIdentityRequest describes a request to link an external identity to a principal.
type LinkIdentityRequest struct {
	// Provider identifies the authority or credential class for the identity.
	Provider string

	// Subject is the provider-scoped subject to link.
	Subject string

	// PrincipalID identifies the internal principal to link.
	PrincipalID string
}

// ProvisionIdentityRequest describes a request to create and link a principal for an identity.
type ProvisionIdentityRequest struct {
	// Identity is the authenticated external identity to provision.
	Identity Identity

	// Principal describes the internal principal to create when Identity is not linked.
	Principal CreatePrincipalRequest
}

// ProvisionIdentityResult describes the outcome of provisioning an identity.
type ProvisionIdentityResult struct {
	// Principal is the internal principal linked to the identity.
	Principal Principal

	// Link is the external identity link for Principal.
	Link ExternalIdentity

	// Created reports whether this call created a new principal and identity link.
	Created bool
}

// PrincipalCreator creates internal principals.
type PrincipalCreator interface {
	// CreatePrincipal creates a principal from req.
	CreatePrincipal(ctx context.Context, req CreatePrincipalRequest) (Principal, error)
}

// IdentityLinker links external identities to internal principals.
type IdentityLinker interface {
	// LinkIdentity links an external identity to a principal.
	LinkIdentity(ctx context.Context, req LinkIdentityRequest) (ExternalIdentity, error)
}

// IdentityProvisioner atomically creates and links principals for external identities.
type IdentityProvisioner interface {
	// ProvisionIdentity creates and links a principal for req.Identity or returns the existing link.
	ProvisionIdentity(ctx context.Context, req ProvisionIdentityRequest) (ProvisionIdentityResult, error)
}
