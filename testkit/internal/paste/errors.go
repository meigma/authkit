package paste

import (
	"errors"
	"fmt"
)

var (
	// ErrEmptyBody indicates that a paste body is blank after trimming whitespace.
	ErrEmptyBody = errors.New("paste: body is required")

	// ErrPasteNotFound indicates that a paste ID does not exist.
	ErrPasteNotFound = errors.New("paste: paste not found")

	// ErrDuplicatePasteID indicates that a paste ID already exists in storage.
	ErrDuplicatePasteID = errors.New("paste: duplicate paste ID")
)

// BodyTooLargeError indicates that a paste body exceeds the configured byte limit.
type BodyTooLargeError struct {
	// MaxBytes is the largest accepted paste body size.
	MaxBytes int
}

func (e BodyTooLargeError) Error() string {
	return fmt.Sprintf("paste: body exceeds %d bytes", e.MaxBytes)
}
