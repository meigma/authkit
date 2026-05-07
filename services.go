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
