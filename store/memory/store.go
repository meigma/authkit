package memory

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"sync"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/apikey"
)

const principalIDPrefix = "principal_"

// Store keeps principals and external identity links in memory.
type Store struct {
	mu                  sync.RWMutex
	nextPrincipalNumber int
	principals          map[string]authkit.Principal
	links               map[identityKey]authkit.ExternalIdentity
	tokens              map[string]apikey.StoredToken
}

type identityKey struct {
	provider string
	subject  string
}

// NewStore creates an empty in-memory store.
func NewStore() *Store {
	return &Store{
		nextPrincipalNumber: 1,
		principals:          make(map[string]authkit.Principal),
		links:               make(map[identityKey]authkit.ExternalIdentity),
		tokens:              make(map[string]apikey.StoredToken),
	}
}

// CreatePrincipal creates a principal in the store.
func (s *Store) CreatePrincipal(ctx context.Context, req authkit.CreatePrincipalRequest) (authkit.Principal, error) {
	if err := ctx.Err(); err != nil {
		return authkit.Principal{}, err
	}

	if req.Kind != authkit.PrincipalKindUser && req.Kind != authkit.PrincipalKindService {
		return authkit.Principal{}, fmt.Errorf("memory: unsupported principal kind %q", req.Kind)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	principal := authkit.Principal{
		ID:          principalIDPrefix + strconv.Itoa(s.nextPrincipalNumber),
		Kind:        req.Kind,
		DisplayName: req.DisplayName,
		Attributes:  cloneAttributes(req.Attributes),
	}
	s.nextPrincipalNumber++
	s.principals[principal.ID] = principal

	return clonePrincipal(principal), nil
}

// LinkIdentity links an external identity to an existing principal.
func (s *Store) LinkIdentity(ctx context.Context, req authkit.LinkIdentityRequest) (authkit.ExternalIdentity, error) {
	if err := ctx.Err(); err != nil {
		return authkit.ExternalIdentity{}, err
	}

	if req.Provider == "" {
		return authkit.ExternalIdentity{}, errors.New("memory: provider is required")
	}
	if req.Subject == "" {
		return authkit.ExternalIdentity{}, errors.New("memory: subject is required")
	}
	if req.PrincipalID == "" {
		return authkit.ExternalIdentity{}, errors.New("memory: principal ID is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.principals[req.PrincipalID]; !ok {
		return authkit.ExternalIdentity{}, fmt.Errorf("memory: principal %q does not exist", req.PrincipalID)
	}

	key := identityKey{
		provider: req.Provider,
		subject:  req.Subject,
	}
	if link, ok := s.links[key]; ok {
		if link.PrincipalID == req.PrincipalID {
			return link, nil
		}

		return authkit.ExternalIdentity{}, fmt.Errorf(
			"memory: identity %q/%q is already linked to principal %q",
			req.Provider,
			req.Subject,
			link.PrincipalID,
		)
	}

	link := authkit.ExternalIdentity(req)
	s.links[key] = link

	return link, nil
}

// ResolveIdentity returns the principal linked to identity.
func (s *Store) ResolveIdentity(ctx context.Context, identity authkit.Identity) (*authkit.Principal, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if identity.Provider == "" || identity.Subject == "" {
		return nil, fmt.Errorf("%w: provider and subject are required", authkit.ErrUnresolvedIdentity)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	link, ok := s.links[identityKey{
		provider: identity.Provider,
		subject:  identity.Subject,
	}]
	if !ok {
		return nil, fmt.Errorf(
			"%w: identity %q/%q is not linked",
			authkit.ErrUnresolvedIdentity,
			identity.Provider,
			identity.Subject,
		)
	}

	principal, ok := s.principals[link.PrincipalID]
	if !ok {
		return nil, fmt.Errorf(
			"%w: linked principal %q does not exist",
			authkit.ErrUnresolvedIdentity,
			link.PrincipalID,
		)
	}

	resolved := clonePrincipal(principal)

	return &resolved, nil
}

func cloneAttributes(attrs map[string]any) map[string]any {
	if len(attrs) == 0 {
		return nil
	}

	cloned := make(map[string]any, len(attrs))
	maps.Copy(cloned, attrs)

	return cloned
}

func clonePrincipal(principal authkit.Principal) authkit.Principal {
	principal.Attributes = cloneAttributes(principal.Attributes)

	return principal
}
