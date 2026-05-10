package authkit

import "errors"

var (
	// ErrUnauthenticated indicates that no request credential authenticated successfully.
	ErrUnauthenticated = errors.New("authkit: unauthenticated")

	// ErrUnresolvedIdentity indicates that a valid credential has no linked principal.
	ErrUnresolvedIdentity = errors.New("authkit: unresolved identity")

	// ErrUnauthorized indicates that a resolved principal is not allowed to perform an action.
	ErrUnauthorized = errors.New("authkit: unauthorized")

	// ErrInternal indicates an auth pipeline failure that should be treated as internal.
	ErrInternal = errors.New("authkit: internal failure")

	// ErrProvisioningRuleNotFound indicates that a provisioning rule does not exist.
	ErrProvisioningRuleNotFound = errors.New("authkit: provisioning rule not found")

	// ErrPrincipalNotFound indicates that a principal does not exist.
	ErrPrincipalNotFound = errors.New("authkit: principal not found")
)
