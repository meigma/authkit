package apikey

import (
	"crypto/sha256"
	"time"

	"github.com/meigma/authkit"
)

// Provider identifies identities produced by API-token authentication.
const Provider = "api-token"

// IssueRequest describes a request to issue an opaque API token.
type IssueRequest struct {
	// PrincipalID identifies the principal the token should be linked to.
	PrincipalID string

	// Name is an optional human-readable token label.
	Name string

	// ExpiresAt is the time after which the token must no longer authenticate.
	ExpiresAt time.Time
}

// IssuedToken describes an API token immediately after issuance.
type IssuedToken struct {
	// ID is the stable lookup identifier embedded in the token.
	ID string

	// Plaintext is the full token secret shown once to the caller.
	Plaintext string

	// ExpiresAt is the time after which the token must no longer authenticate.
	ExpiresAt time.Time

	// IdentityLink is the explicit identity-link request applications can store for the token.
	IdentityLink authkit.LinkIdentityRequest
}

// TokenMetadata describes an API token without its secret material.
type TokenMetadata struct {
	// ID is the stable lookup identifier embedded in the token.
	ID string

	// PrincipalID identifies the principal the token authenticates as.
	PrincipalID string

	// Name is an optional human-readable token label.
	Name string

	// ExpiresAt is the time after which the token must no longer authenticate.
	ExpiresAt time.Time

	// LastUsedAt records the last successful token verification time when known.
	LastUsedAt *time.Time

	// RevokedAt records when the token was revoked.
	RevokedAt *time.Time
}

// StoredToken is the storage representation of an API token.
type StoredToken struct {
	// ID is the stable lookup identifier embedded in the token.
	ID string

	// PrincipalID identifies the principal the token was issued for.
	PrincipalID string

	// Name is an optional human-readable token label.
	Name string

	// SecretHash is the SHA-256 hash of the token secret.
	SecretHash [sha256.Size]byte

	// ExpiresAt is the time after which the token must no longer authenticate.
	ExpiresAt time.Time

	// LastUsedAt records the last successful token verification time when known.
	LastUsedAt *time.Time

	// RevokedAt records when the token was revoked.
	RevokedAt *time.Time
}
