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

	// Update replaces an existing paste owned by paste.OwnerPrincipalID.
	Update(ctx context.Context, paste Paste) error

	// Delete removes a paste owned by ownerPrincipalID.
	Delete(ctx context.Context, id string, ownerPrincipalID string) error
}
