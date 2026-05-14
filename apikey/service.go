package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/meigma/authkit"
)

const (
	tokenPrefix     = "ak"
	tokenSeparator  = "_"
	tokenPartPrefix = tokenPrefix + tokenSeparator
)

// Service issues, verifies, and revokes opaque API tokens.
type Service struct {
	store TokenStore
	clock func() time.Time
}

// NewService constructs an API-token service.
func NewService(store TokenStore, opts ...Option) (*Service, error) {
	if store == nil {
		return nil, errors.New("apikey: token store is required")
	}

	cfg := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	return &Service{
		store: store,
		clock: cfg.clock,
	}, nil
}

// IssueToken issues an opaque API token for an existing principal.
func (s *Service) IssueToken(ctx context.Context, req IssueRequest) (IssuedToken, error) {
	if err := ctx.Err(); err != nil {
		return IssuedToken{}, err
	}

	now := s.clock()
	if req.PrincipalID == "" {
		return IssuedToken{}, errors.New("apikey: principal ID is required")
	}
	if !req.ExpiresAt.After(now) {
		return IssuedToken{}, errors.New("apikey: expiration must be in the future")
	}

	tokenID := rand.Text()
	secret := rand.Text()
	plaintext := formatToken(tokenID, secret)

	if err := s.store.CreateToken(ctx, StoredToken{
		ID:          tokenID,
		PrincipalID: req.PrincipalID,
		Name:        req.Name,
		SecretHash:  hashSecret(secret),
		ExpiresAt:   req.ExpiresAt,
	}); err != nil {
		return IssuedToken{}, fmt.Errorf("apikey: create token: %w", err)
	}

	return IssuedToken{
		ID:        tokenID,
		Plaintext: plaintext,
		ExpiresAt: req.ExpiresAt,
	}, nil
}

// VerifyAPIToken authenticates plaintext and returns its API-token metadata.
func (s *Service) VerifyAPIToken(ctx context.Context, plaintext string) (VerifiedToken, error) {
	if err := ctx.Err(); err != nil {
		return VerifiedToken{}, err
	}

	tokenID, secret, ok := parseToken(plaintext)
	if !ok {
		return VerifiedToken{}, unauthenticated("malformed token")
	}

	stored, err := s.store.FindToken(ctx, tokenID)
	if errors.Is(err, ErrTokenNotFound) {
		return VerifiedToken{}, unauthenticated("token not found")
	}
	if err != nil {
		return VerifiedToken{}, fmt.Errorf("%w: find token: %w", authkit.ErrInternal, err)
	}

	secretHash := hashSecret(secret)
	if subtle.ConstantTimeCompare(secretHash[:], stored.SecretHash[:]) != 1 {
		return VerifiedToken{}, unauthenticated("token secret mismatch")
	}

	now := s.clock()
	if stored.RevokedAt != nil {
		return VerifiedToken{}, unauthenticated("token revoked")
	}
	if !now.Before(stored.ExpiresAt) {
		return VerifiedToken{}, unauthenticated("token expired")
	}
	if stored.PrincipalID == "" {
		return VerifiedToken{}, fmt.Errorf("%w: stored token principal ID is required", authkit.ErrInternal)
	}

	_ = s.store.UpdateTokenLastUsed(ctx, tokenID, now)

	return VerifiedToken{
		ID:          tokenID,
		PrincipalID: stored.PrincipalID,
		ExpiresAt:   stored.ExpiresAt,
	}, nil
}

// RevokeToken revokes tokenID.
func (s *Service) RevokeToken(ctx context.Context, tokenID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if tokenID == "" {
		return errors.New("apikey: token ID is required")
	}

	if err := s.store.RevokeToken(ctx, tokenID, s.clock()); err != nil {
		return fmt.Errorf("apikey: revoke token: %w", err)
	}

	return nil
}

func formatToken(tokenID string, secret string) string {
	return tokenPartPrefix + tokenID + tokenSeparator + secret
}

func parseToken(plaintext string) (string, string, bool) {
	rest, ok := strings.CutPrefix(plaintext, tokenPartPrefix)
	if !ok {
		return "", "", false
	}

	tokenID, secret, ok := strings.Cut(rest, tokenSeparator)
	if !ok || tokenID == "" || secret == "" || strings.Contains(secret, tokenSeparator) {
		return "", "", false
	}

	return tokenID, secret, true
}

func hashSecret(secret string) [sha256.Size]byte {
	return sha256.Sum256([]byte(secret))
}

func unauthenticated(reason string) error {
	return fmt.Errorf("%w: %s", authkit.ErrUnauthenticated, reason)
}
