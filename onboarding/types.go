package onboarding

import "github.com/meigma/authkit"

// Options configures a Service.
type Options struct {
	// PrincipalFinder finds existing principals before identity attachment.
	PrincipalFinder authkit.PrincipalFinder

	// IdentityLinker links verified identities to existing principals.
	IdentityLinker authkit.IdentityLinker

	// IdentityProvisioner creates and links principals for verified identities.
	IdentityProvisioner authkit.IdentityProvisioner
}

// AttachIdentityRequest describes a request to attach a verified identity to an existing principal.
type AttachIdentityRequest struct {
	// Identity is the verified external identity to attach.
	Identity authkit.Identity

	// PrincipalID identifies the existing principal receiving the identity link.
	PrincipalID string
}

// AttachIdentityResult describes the outcome of attaching an identity to a principal.
type AttachIdentityResult struct {
	// Principal is the existing principal that received the identity link.
	Principal authkit.Principal

	// Link is the external identity link created or confirmed for Principal.
	Link authkit.ExternalIdentity
}

// ProvisionPrincipalRequest describes a request to provision a principal for a verified identity.
type ProvisionPrincipalRequest struct {
	// Identity is the verified external identity to provision.
	Identity authkit.Identity

	// Principal describes the internal principal to create when Identity is not linked.
	Principal authkit.CreatePrincipalRequest

	// InitialRoleIDs are local roles assigned only when a new principal is created.
	InitialRoleIDs []string
}

// ProvisionPrincipalResult describes the outcome of provisioning a principal for an identity.
type ProvisionPrincipalResult struct {
	// Principal is the internal principal linked to the identity.
	Principal authkit.Principal

	// Link is the external identity link for Principal.
	Link authkit.ExternalIdentity

	// Created reports whether this call created a new principal and identity link.
	Created bool
}
