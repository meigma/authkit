package oidc

import (
	"context"
	"fmt"
)

// ProviderSource returns trusted provider configuration for an issuer.
type ProviderSource interface {
	// FindProvider returns the trusted provider for issuer.
	FindProvider(ctx context.Context, issuer string) (Provider, error)
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
