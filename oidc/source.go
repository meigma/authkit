package oidc

import (
	"context"
	"fmt"
	"strings"

	"github.com/meigma/authkit"
)

// ProviderSource returns trusted provider configuration for an issuer.
type ProviderSource interface {
	// FindProvider returns the trusted provider for issuer.
	FindProvider(ctx context.Context, issuer string) (Provider, error)
}

// ProviderTrustStore stores and returns trusted provider configuration.
type ProviderTrustStore interface {
	ProviderSource

	// TrustProvider stores provider as trusted for its issuer.
	TrustProvider(ctx context.Context, provider Provider) (Provider, error)
}

// StaticProviderSource stores trusted providers in memory.
type StaticProviderSource struct {
	providers map[string]Provider
}

// NewStaticProviderSource constructs a static provider source.
func NewStaticProviderSource(providers ...Provider) (*StaticProviderSource, error) {
	source := &StaticProviderSource{
		providers: make(map[string]Provider, len(providers)),
	}

	for _, provider := range providers {
		if err := provider.Validate(); err != nil {
			return nil, err
		}
		if _, ok := source.providers[provider.Issuer]; ok {
			return nil, fmt.Errorf("oidc: duplicate provider issuer %q", provider.Issuer)
		}

		source.providers[provider.Issuer] = cloneProvider(provider)
	}

	return source, nil
}

// FindProvider returns the trusted provider for issuer.
func (s *StaticProviderSource) FindProvider(ctx context.Context, issuer string) (Provider, error) {
	if err := ctx.Err(); err != nil {
		return Provider{}, err
	}
	if s == nil {
		return Provider{}, ErrProviderNotFound
	}

	provider, ok := s.providers[issuer]
	if !ok {
		return Provider{}, ErrProviderNotFound
	}

	return cloneProvider(provider), nil
}

func cloneProvider(provider Provider) Provider {
	provider.Audiences = cloneStrings(provider.Audiences)
	provider.SupportedSigningAlgorithms = cloneStrings(provider.SupportedSigningAlgorithms)
	provider.ForwardedClaims = cloneClaimPaths(provider.ForwardedClaims)

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

func cloneClaimPaths(paths []authkit.ClaimPath) []authkit.ClaimPath {
	if len(paths) == 0 {
		return nil
	}

	cloned := make([]authkit.ClaimPath, len(paths))
	for i, path := range paths {
		cloned[i] = cloneClaimPath(path)
	}

	return cloned
}

func cloneClaimPath(path authkit.ClaimPath) authkit.ClaimPath {
	if len(path) == 0 {
		return nil
	}

	cloned := make(authkit.ClaimPath, len(path))
	copy(cloned, path)

	return cloned
}

func claimPathKey(path authkit.ClaimPath) string {
	if !path.Valid() {
		return ""
	}

	return strings.Join(path, "\x00")
}

func cloneClaimValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		cloned := make(map[string]any, len(typed))
		for key, item := range typed {
			cloned[key] = cloneClaimValue(item)
		}

		return cloned
	case []any:
		cloned := make([]any, len(typed))
		for i, item := range typed {
			cloned[i] = cloneClaimValue(item)
		}

		return cloned
	case []string:
		return cloneStrings(typed)
	default:
		return value
	}
}
