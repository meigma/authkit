package passkey

import (
	"errors"
	"fmt"

	"github.com/meigma/authkit"
)

var (
	// ErrUserNotFound indicates that a passkey user handle is not known for a relying party.
	ErrUserNotFound = errors.New("passkey: user not found")

	// ErrUserExists indicates that a passkey user handle already exists for a relying party and principal.
	ErrUserExists = errors.New("passkey: user exists")

	// ErrCredentialExists indicates that a passkey credential is already stored.
	ErrCredentialExists = errors.New("passkey: credential exists")

	// ErrCloneWarning indicates that an authenticator counter signaled possible credential cloning.
	ErrCloneWarning = errors.New("passkey: clone warning")
)

func unauthenticated(reason string) error {
	return fmt.Errorf("%w: %s", authkit.ErrUnauthenticated, reason)
}

func cloneWarning() error {
	return fmt.Errorf("%w: %w", authkit.ErrUnauthenticated, ErrCloneWarning)
}

func internalError(op string, err error) error {
	return fmt.Errorf("%w: passkey: %s: %w", authkit.ErrInternal, op, err)
}
