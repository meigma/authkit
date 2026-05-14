package management

import "time"

// IssueAPITokenRequest describes a request to issue an API token.
type IssueAPITokenRequest struct {
	// PrincipalID identifies the principal the token should authenticate as.
	PrincipalID string

	// Name is an optional human-readable token label.
	Name string

	// ExpiresAt is the time after which the token must no longer authenticate.
	ExpiresAt time.Time
}

// IssuedAPIToken describes an issued API token.
type IssuedAPIToken struct {
	// ID is the stable lookup identifier embedded in the token.
	ID string

	// PrincipalID identifies the principal the token authenticates as.
	PrincipalID string

	// Plaintext is the full token secret shown once to the caller.
	Plaintext string

	// ExpiresAt is the time after which the token must no longer authenticate.
	ExpiresAt time.Time
}
