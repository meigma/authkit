package memory

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/apikey"
)

// CreateToken stores token.
func (s *Store) CreateToken(ctx context.Context, token apikey.StoredToken) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if token.ID == "" {
		return errors.New("memory: token ID is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tokens[token.ID]; ok {
		return errors.New("memory: token already exists")
	}

	s.tokens[token.ID] = cloneStoredToken(token)

	return nil
}

// FindToken returns the token for tokenID.
func (s *Store) FindToken(ctx context.Context, tokenID string) (apikey.StoredToken, error) {
	if err := ctx.Err(); err != nil {
		return apikey.StoredToken{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	token, ok := s.tokens[tokenID]
	if !ok {
		return apikey.StoredToken{}, apikey.ErrTokenNotFound
	}

	return cloneStoredToken(token), nil
}

// UpdateTokenLastUsed records the most recent successful use of tokenID.
func (s *Store) UpdateTokenLastUsed(ctx context.Context, tokenID string, usedAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	token, ok := s.tokens[tokenID]
	if !ok {
		return apikey.ErrTokenNotFound
	}

	token.LastUsedAt = cloneTime(&usedAt)
	s.tokens[tokenID] = token

	return nil
}

// RevokeToken records tokenID as revoked.
func (s *Store) RevokeToken(ctx context.Context, tokenID string, revokedAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	token, ok := s.tokens[tokenID]
	if !ok {
		return apikey.ErrTokenNotFound
	}

	token.RevokedAt = cloneTime(&revokedAt)
	s.tokens[tokenID] = token

	return nil
}

// ListPrincipalTokenMetadata returns API-token metadata for principalID.
func (s *Store) ListPrincipalTokenMetadata(
	ctx context.Context,
	principalID string,
) ([]apikey.TokenMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if principalID == "" {
		return nil, errors.New("memory: principal ID is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, ok := s.principals[principalID]; !ok {
		return nil, authkit.ErrPrincipalNotFound
	}

	tokens := make([]apikey.TokenMetadata, 0)
	for _, token := range s.tokens {
		if token.PrincipalID != principalID {
			continue
		}
		tokens = append(tokens, tokenMetadataFromStored(token))
	}
	sort.Slice(tokens, func(i, j int) bool {
		return tokens[i].ID < tokens[j].ID
	})

	return tokens, nil
}

func cloneStoredToken(token apikey.StoredToken) apikey.StoredToken {
	token.LastUsedAt = cloneTime(token.LastUsedAt)
	token.RevokedAt = cloneTime(token.RevokedAt)

	return token
}

func tokenMetadataFromStored(token apikey.StoredToken) apikey.TokenMetadata {
	return apikey.TokenMetadata{
		ID:          token.ID,
		PrincipalID: token.PrincipalID,
		Name:        token.Name,
		ExpiresAt:   token.ExpiresAt,
		LastUsedAt:  cloneTime(token.LastUsedAt),
		RevokedAt:   cloneTime(token.RevokedAt),
	}
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}

	cloned := *value

	return &cloned
}
