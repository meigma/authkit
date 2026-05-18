package passkey

import (
	"context"

	"github.com/meigma/authkit"
)

// Store persists passkey users and credentials for one or more relying parties.
type Store interface {
	authkit.PrincipalResolver

	// FindUserByPrincipal returns the WebAuthn user for principalID and rpID.
	FindUserByPrincipal(ctx context.Context, rpID string, principalID string) (User, error)

	// FindUserByHandle returns the WebAuthn user with handle for rpID.
	FindUserByHandle(ctx context.Context, rpID string, handle []byte) (User, error)

	// ListCredentials returns credentials owned by userHandle for rpID.
	// Unknown handles should return an empty slice, not ErrUserNotFound.
	ListCredentials(ctx context.Context, rpID string, userHandle []byte) ([]Credential, error)

	// CreateRegistration atomically stores a passkey user, credential, and identity link.
	// An existing identical user handle should be accepted when adding another credential.
	// It returns ErrUserExists or ErrCredentialExists for registration conflicts.
	CreateRegistration(ctx context.Context, registration Registration) (RegistrationResult, error)

	// UpdateCredentialAfterLogin persists credential metadata updated by a successful login.
	UpdateCredentialAfterLogin(ctx context.Context, credential Credential) error
}
