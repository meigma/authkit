package oidc

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
)

const (
	// Name identifies the OIDC JWT bearer authenticator.
	Name = "oidc"

	defaultSigningAlgorithm = "RS256"
)

// ErrProviderNotFound indicates that an issuer is not trusted by a provider source.
var ErrProviderNotFound = errors.New("oidc: provider not found")

// Provider describes a trusted OIDC issuer for JWT bearer-token validation.
type Provider struct {
	// Issuer is the exact expected iss claim for tokens from this provider.
	Issuer string

	// Audiences are the accepted aud claim values for this resource server.
	Audiences []string

	// JWKSURL is the trusted URL used to fetch public signing keys.
	JWKSURL string

	// SupportedSigningAlgorithms limits acceptable JWT signing algorithms.
	SupportedSigningAlgorithms []string
}

// Validate reports configuration errors that prevent provider trust.
func (p Provider) Validate() error {
	if err := validateHTTPSURL("issuer", p.Issuer); err != nil {
		return err
	}
	if err := validateHTTPSURL("JWKS URL", p.JWKSURL); err != nil {
		return err
	}
	if len(p.Audiences) == 0 {
		return errors.New("oidc: provider audiences are required")
	}
	for i, audience := range p.Audiences {
		if strings.TrimSpace(audience) == "" {
			return fmt.Errorf("oidc: provider audience %d is required", i)
		}
	}
	if _, err := p.signingAlgorithms(); err != nil {
		return err
	}

	return nil
}

func validateHTTPSURL(name string, raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("oidc: provider %s is required", name)
	}
	if strings.TrimSpace(raw) != raw {
		return fmt.Errorf("oidc: provider %s must not contain surrounding whitespace", name)
	}

	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("oidc: provider %s must be an absolute HTTPS URL", name)
	}

	return nil
}

func (p Provider) signingAlgorithms() ([]jwa.SignatureAlgorithm, error) {
	names := p.SupportedSigningAlgorithms
	if len(names) == 0 {
		names = []string{defaultSigningAlgorithm}
	}

	algorithms := make([]jwa.SignatureAlgorithm, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for i, name := range names {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			return nil, fmt.Errorf("oidc: provider signing algorithm %d is required", i)
		}

		algorithm, ok := jwa.LookupSignatureAlgorithm(trimmed)
		if !ok || algorithm == jwa.EmptySignatureAlgorithm() || algorithm == jwa.NoSignature() {
			return nil, fmt.Errorf("oidc: unsupported signing algorithm %q", trimmed)
		}
		if algorithm.IsSymmetric() {
			return nil, fmt.Errorf("oidc: symmetric signing algorithm %q is not supported", trimmed)
		}
		if _, ok := seen[algorithm.String()]; ok {
			continue
		}

		seen[algorithm.String()] = struct{}{}
		algorithms = append(algorithms, algorithm)
	}

	return algorithms, nil
}
