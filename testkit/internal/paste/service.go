package paste

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

const idEntropyBytes = 12

// IDGenerator returns a new paste ID.
type IDGenerator func() (string, error)

// Option configures a Service.
type Option func(*serviceOptions)

type serviceOptions struct {
	clock        func() time.Time
	idGenerator  IDGenerator
	maxBodyBytes int
}

// Service coordinates paste creation and lookup behavior.
type Service struct {
	repo         Repository
	clock        func() time.Time
	idGenerator  IDGenerator
	maxBodyBytes int
}

// NewService constructs a paste service around repo.
func NewService(repo Repository, opts ...Option) (*Service, error) {
	if repo == nil {
		return nil, errors.New("paste: repository is required")
	}

	cfg := serviceOptions{
		clock:        time.Now,
		idGenerator:  generateID,
		maxBodyBytes: DefaultMaxBodyBytes,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.clock == nil {
		cfg.clock = time.Now
	}
	if cfg.idGenerator == nil {
		cfg.idGenerator = generateID
	}
	if cfg.maxBodyBytes <= 0 {
		cfg.maxBodyBytes = DefaultMaxBodyBytes
	}

	return &Service{
		repo:         repo,
		clock:        cfg.clock,
		idGenerator:  cfg.idGenerator,
		maxBodyBytes: cfg.maxBodyBytes,
	}, nil
}

// WithClock sets the clock used for paste creation timestamps.
func WithClock(clock func() time.Time) Option {
	return func(opts *serviceOptions) {
		opts.clock = clock
	}
}

// WithIDGenerator sets the ID generator used for new pastes.
func WithIDGenerator(generator IDGenerator) Option {
	return func(opts *serviceOptions) {
		opts.idGenerator = generator
	}
}

// WithMaxBodyBytes sets the maximum accepted paste body size.
func WithMaxBodyBytes(maxBytes int) Option {
	return func(opts *serviceOptions) {
		opts.maxBodyBytes = maxBytes
	}
}

// Create validates and stores a new paste.
func (s *Service) Create(ctx context.Context, req CreatePasteRequest) (Paste, error) {
	if strings.TrimSpace(req.Body) == "" {
		return Paste{}, ErrEmptyBody
	}
	if len(req.Body) > s.maxBodyBytes {
		return Paste{}, BodyTooLargeError{MaxBytes: s.maxBodyBytes}
	}

	id, err := s.idGenerator()
	if err != nil {
		return Paste{}, fmt.Errorf("paste: generate ID: %w", err)
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return Paste{}, errors.New("paste: generated ID is empty")
	}

	created := Paste{
		ID:        id,
		Title:     strings.TrimSpace(req.Title),
		Body:      req.Body,
		Syntax:    strings.TrimSpace(req.Syntax),
		CreatedAt: s.clock().UTC(),
	}
	if err := s.repo.Create(ctx, created); err != nil {
		return Paste{}, fmt.Errorf("paste: store paste: %w", err)
	}

	return created, nil
}

// Read returns a paste by ID.
func (s *Service) Read(ctx context.Context, id string) (Paste, error) {
	paste, err := s.repo.Find(ctx, strings.TrimSpace(id))
	if err != nil {
		return Paste{}, fmt.Errorf("paste: find paste: %w", err)
	}

	return paste, nil
}

// ListRecent returns recent pastes, newest first.
func (s *Service) ListRecent(ctx context.Context, limit int) ([]Paste, error) {
	if limit <= 0 {
		limit = DefaultRecentLimit
	}

	pastes, err := s.repo.ListRecent(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("paste: list recent pastes: %w", err)
	}

	return pastes, nil
}

func generateID() (string, error) {
	var entropy [idEntropyBytes]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(entropy[:]), nil
}
