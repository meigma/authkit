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
	"github.com/meigma/authkit/oidc"
)

const principalIDPrefix = "principal_"

// Store keeps principals, external identity links, API tokens, and OIDC provider trust in memory.
type Store struct {
	mu                  sync.RWMutex
	nextPrincipalNumber int
	principals          map[string]authkit.Principal
	links               map[identityKey]authkit.ExternalIdentity
	tokens              map[string]apikey.StoredToken
	providers           map[string]oidc.Provider
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
		providers:           make(map[string]oidc.Provider),
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

// ProvisionIdentity creates and links a principal for identity or returns the existing link.
func (s *Store) ProvisionIdentity(
	ctx context.Context,
	req authkit.ProvisionIdentityRequest,
) (authkit.ProvisionIdentityResult, error) {
	if err := ctx.Err(); err != nil {
		return authkit.ProvisionIdentityResult{}, err
	}
	if req.Identity.Provider == "" || req.Identity.Subject == "" {
		return authkit.ProvisionIdentityResult{}, fmt.Errorf(
			"%w: provider and subject are required",
			authkit.ErrUnresolvedIdentity,
		)
	}
	if req.Principal.Kind != authkit.PrincipalKindUser && req.Principal.Kind != authkit.PrincipalKindService {
		return authkit.ProvisionIdentityResult{}, fmt.Errorf(
			"memory: unsupported principal kind %q",
			req.Principal.Kind,
		)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := identityKey{
		provider: req.Identity.Provider,
		subject:  req.Identity.Subject,
	}
	if link, ok := s.links[key]; ok {
		principal, ok := s.principals[link.PrincipalID]
		if !ok {
			return authkit.ProvisionIdentityResult{}, fmt.Errorf(
				"%w: linked principal %q does not exist",
				authkit.ErrUnresolvedIdentity,
				link.PrincipalID,
			)
		}

		return authkit.ProvisionIdentityResult{
			Principal: clonePrincipal(principal),
			Link:      link,
			Created:   false,
		}, nil
	}

	principal := authkit.Principal{
		ID:          principalIDPrefix + strconv.Itoa(s.nextPrincipalNumber),
		Kind:        req.Principal.Kind,
		DisplayName: req.Principal.DisplayName,
		Attributes:  cloneAttributes(req.Principal.Attributes),
	}
	s.nextPrincipalNumber++
	s.principals[principal.ID] = principal

	link := authkit.ExternalIdentity{
		Provider:    req.Identity.Provider,
		Subject:     req.Identity.Subject,
		PrincipalID: principal.ID,
	}
	s.links[key] = link

	return authkit.ProvisionIdentityResult{
		Principal: clonePrincipal(principal),
		Link:      link,
		Created:   true,
	}, nil
}

// TrustProvider stores provider as trusted for its issuer.
func (s *Store) TrustProvider(ctx context.Context, provider oidc.Provider) (oidc.Provider, error) {
	if err := ctx.Err(); err != nil {
		return oidc.Provider{}, err
	}
	if err := provider.Validate(); err != nil {
		return oidc.Provider{}, err
	}

	trusted := cloneProvider(provider)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.providers[trusted.Issuer] = trusted

	return cloneProvider(trusted), nil
}

// FindProvider returns the trusted OIDC provider for issuer.
func (s *Store) FindProvider(ctx context.Context, issuer string) (oidc.Provider, error) {
	if err := ctx.Err(); err != nil {
		return oidc.Provider{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	provider, ok := s.providers[issuer]
	if !ok {
		return oidc.Provider{}, oidc.ErrProviderNotFound
	}

	return cloneProvider(provider), nil
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

func cloneProvider(provider oidc.Provider) oidc.Provider {
	provider.Audiences = cloneStrings(provider.Audiences)
	provider.SupportedSigningAlgorithms = cloneStrings(provider.SupportedSigningAlgorithms)

	return provider
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	cloned := make([]string, len(values))
	copy(cloned, values)

	return cloned
}
