package paste

import "time"

const (
	// DefaultMaxBodyBytes is the first-slice paste body limit.
	DefaultMaxBodyBytes = 64 * 1024

	// DefaultRecentLimit is the default number of pastes shown in recent lists.
	DefaultRecentLimit = 50
)

// Paste is a stored pastebin entry.
type Paste struct {
	// ID is the stable URL identifier for the paste.
	ID string

	// Title is the optional human-readable paste title.
	Title string

	// Body is the exact paste content.
	Body string

	// Syntax is an optional display label for the paste content type.
	Syntax string

	// CreatedAt is when the paste was created.
	CreatedAt time.Time
}

// CreatePasteRequest describes a paste creation request.
type CreatePasteRequest struct {
	// Title is an optional human-readable paste title.
	Title string

	// Body is the required paste content.
	Body string

	// Syntax is an optional display label for the paste content type.
	Syntax string
}
