package apikey

import (
	"context"
	"time"
)

// TokenStore stores opaque API-token records.
type TokenStore interface {
	// CreateToken stores token.
	CreateToken(ctx context.Context, token StoredToken) error

	// FindToken returns the token for tokenID.
	FindToken(ctx context.Context, tokenID string) (StoredToken, error)

	// UpdateTokenLastUsed records the most recent successful use of tokenID.
	UpdateTokenLastUsed(ctx context.Context, tokenID string, usedAt time.Time) error

	// RevokeToken records tokenID as revoked.
	RevokeToken(ctx context.Context, tokenID string, revokedAt time.Time) error
}
