package memory

import (
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/meigma/authkit/testkit/internal/paste"
)

const (
	sortBefore = -1
	sortEqual  = 0
	sortAfter  = 1
)

// Store keeps pastes in process memory.
type Store struct {
	mu     sync.RWMutex
	pastes map[string]paste.Paste
}

// NewStore constructs an empty in-memory paste store.
func NewStore() *Store {
	return &Store{
		pastes: make(map[string]paste.Paste),
	}
}

// Create stores a new paste.
func (s *Store) Create(ctx context.Context, created paste.Paste) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.pastes[created.ID]; exists {
		return paste.ErrDuplicatePasteID
	}
	s.pastes[created.ID] = created

	return nil
}

// Find returns a paste by ID.
func (s *Store) Find(ctx context.Context, id string) (paste.Paste, error) {
	if err := ctx.Err(); err != nil {
		return paste.Paste{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	found, exists := s.pastes[id]
	if !exists {
		return paste.Paste{}, paste.ErrPasteNotFound
	}

	return found, nil
}

// ListRecent returns recent pastes, newest first, up to limit.
func (s *Store) ListRecent(ctx context.Context, limit int) ([]paste.Paste, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return []paste.Paste{}, nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	recent := make([]paste.Paste, 0, len(s.pastes))
	for _, stored := range s.pastes {
		recent = append(recent, stored)
	}
	slices.SortFunc(recent, comparePasteRecency)
	if len(recent) > limit {
		recent = recent[:limit]
	}

	return recent, nil
}

func comparePasteRecency(left paste.Paste, right paste.Paste) int {
	switch {
	case left.CreatedAt.After(right.CreatedAt):
		return sortBefore
	case right.CreatedAt.After(left.CreatedAt):
		return sortAfter
	}

	return strings.Compare(left.ID, right.ID)
}
