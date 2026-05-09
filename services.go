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

// CreateRoleRequest describes a request to create an admin-managed local role.
type CreateRoleRequest struct {
	// ID is the stable application-owned role identifier.
	ID string

	// DisplayName is a human-readable role label.
	DisplayName string

	// Description optionally explains the role's intended use.
	Description string
}

// GrantRoleActionRequest describes a request to grant an action to a role.
type GrantRoleActionRequest struct {
	// RoleID identifies the role receiving the action grant.
	RoleID string

	// Action is the authorization action granted to the role.
	Action string
}

// AssignPrincipalRoleRequest describes a request to assign a principal to a role.
type AssignPrincipalRoleRequest struct {
	// PrincipalID identifies the principal receiving the role.
	PrincipalID string

	// RoleID identifies the assigned role.
	RoleID string
}

// CreateProvisioningRuleRequest describes a request to create a provisioning rule.
type CreateProvisioningRuleRequest struct {
	// ID is the stable application-owned provisioning rule identifier.
	ID string

	// DisplayName is a human-readable rule label.
	DisplayName string

	// Provider identifies the trusted identity provider this rule applies to.
	Provider string

	// ClaimPath identifies the forwarded identity claim inspected by this rule.
	ClaimPath ClaimPath

	// Values are exact claim values that satisfy this rule.
	Values []string

	// AssignRoleIDs are local role IDs assigned when this rule matches.
	AssignRoleIDs []string

	// Enabled controls whether this rule participates in runtime provisioning.
	Enabled bool
}

// UpdateProvisioningRuleRequest describes a request to replace a provisioning rule.
type UpdateProvisioningRuleRequest struct {
	// ID identifies the provisioning rule to update.
	ID string

	// DisplayName is a human-readable rule label.
	DisplayName string

	// Provider identifies the trusted identity provider this rule applies to.
	Provider string

	// ClaimPath identifies the forwarded identity claim inspected by this rule.
	ClaimPath ClaimPath

	// Values are exact claim values that satisfy this rule.
	Values []string

	// AssignRoleIDs are local role IDs assigned when this rule matches.
	AssignRoleIDs []string

	// Enabled controls whether this rule participates in runtime provisioning.
	Enabled bool
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

	// InitialRoleIDs are local roles assigned only when a new principal is created.
	InitialRoleIDs []string
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

// RoleCreator creates admin-managed local roles.
type RoleCreator interface {
	// CreateRole creates a local role from req.
	CreateRole(ctx context.Context, req CreateRoleRequest) (Role, error)
}

// RoleActionGranter grants authorization actions to roles.
type RoleActionGranter interface {
	// GrantRoleAction grants req.Action to req.RoleID.
	GrantRoleAction(ctx context.Context, req GrantRoleActionRequest) error
}

// PrincipalRoleAssigner assigns principals to roles.
type PrincipalRoleAssigner interface {
	// AssignPrincipalRole assigns req.PrincipalID to req.RoleID.
	AssignPrincipalRole(ctx context.Context, req AssignPrincipalRoleRequest) error
}

// PrincipalActionResolver resolves effective authorization actions for principals.
type PrincipalActionResolver interface {
	// ResolvePrincipalActions returns the distinct actions granted to principalID.
	ResolvePrincipalActions(ctx context.Context, principalID string) ([]string, error)
}

// ProvisioningRuleCreator creates admin-managed provisioning rules.
type ProvisioningRuleCreator interface {
	// CreateProvisioningRule creates a provisioning rule from req.
	CreateProvisioningRule(ctx context.Context, req CreateProvisioningRuleRequest) (ProvisioningRule, error)
}

// ProvisioningRuleUpdater updates admin-managed provisioning rules.
type ProvisioningRuleUpdater interface {
	// UpdateProvisioningRule replaces a provisioning rule from req.
	UpdateProvisioningRule(ctx context.Context, req UpdateProvisioningRuleRequest) (ProvisioningRule, error)
}

// ProvisioningRuleDeleter deletes admin-managed provisioning rules.
type ProvisioningRuleDeleter interface {
	// DeleteProvisioningRule deletes the provisioning rule identified by id.
	DeleteProvisioningRule(ctx context.Context, id string) error
}

// ProvisioningRuleFinder finds admin-managed provisioning rules.
type ProvisioningRuleFinder interface {
	// FindProvisioningRule returns the provisioning rule identified by id.
	FindProvisioningRule(ctx context.Context, id string) (ProvisioningRule, error)
}

// ProvisioningRuleLister lists admin-managed provisioning rules.
type ProvisioningRuleLister interface {
	// ListProvisioningRules returns all provisioning rules.
	ListProvisioningRules(ctx context.Context) ([]ProvisioningRule, error)
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
