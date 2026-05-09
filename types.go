package authkit

// Identity describes a credential identity after authentication succeeds.
type Identity struct {
	// Provider identifies the authority or credential class that produced the identity.
	Provider string

	// Subject is the provider-scoped subject for the authenticated actor.
	Subject string

	// CredentialID identifies the concrete credential when the authenticator exposes one.
	CredentialID string

	// Claims contains optional authenticator-provided metadata for callers and adapters.
	Claims map[string]any
}

// Principal describes an internal application actor.
type Principal struct {
	// ID is the stable application-owned principal identifier.
	ID string

	// Kind classifies the principal for application policy and display.
	Kind PrincipalKind

	// DisplayName is a human-readable principal label.
	DisplayName string

	// Attributes contains optional application-owned principal metadata.
	Attributes map[string]any
}

// PrincipalKind identifies the supported principal categories.
type PrincipalKind string

const (
	// PrincipalKindUser identifies a human user principal.
	PrincipalKindUser PrincipalKind = "user"

	// PrincipalKindService identifies a non-human service principal.
	PrincipalKindService PrincipalKind = "service"
)

// Resource describes the authorization target for an action.
type Resource struct {
	// Type identifies the resource class in application policy.
	Type string

	// ID identifies one resource instance within Type.
	ID string

	// Attr contains optional durable resource metadata used by authorizers.
	Attr map[string]any
}

// Decision describes an authorization result.
type Decision struct {
	// Allowed reports whether the action may proceed.
	Allowed bool

	// Reason optionally explains the decision for logs, debugging, or response rendering.
	Reason string
}

// AuthorizationRequest describes a caller-supplied authorization request.
type AuthorizationRequest struct {
	// Action identifies the operation the caller wants to perform.
	Action string

	// Resource is the authorization target for Action.
	Resource Resource

	// Facts contains optional decision-time context supplied by the caller.
	Facts Facts
}

// AuthorizationCheck describes the complete input passed to an Authorizer.
type AuthorizationCheck struct {
	// Principal is the resolved internal application actor.
	Principal Principal

	// Action identifies the operation Principal wants to perform.
	Action string

	// Resource is the authorization target for Action.
	Resource Resource

	// Facts contains optional decision-time context supplied by the caller.
	Facts Facts
}

// ExternalIdentity links a provider-scoped identity to an internal principal.
type ExternalIdentity struct {
	// Provider identifies the authority or credential class for the identity.
	Provider string

	// Subject is the provider-scoped subject linked to the principal.
	Subject string

	// PrincipalID identifies the internal principal for this identity link.
	PrincipalID string
}
