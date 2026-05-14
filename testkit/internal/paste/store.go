package paste

import "context"

// Repository stores and retrieves pastes.
type Repository interface {
	// Create stores a new paste.
	Create(ctx context.Context, paste Paste) error

	// Find returns a paste by ID.
	Find(ctx context.Context, id string) (Paste, error)

	// ListRecent returns recent pastes, newest first, up to limit.
	ListRecent(ctx context.Context, limit int) ([]Paste, error)
}
