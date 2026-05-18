package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/oidc"
)

const (
	oidcIssuerEnv            = "TESTKIT_OIDC_ISSUER"
	oidcJWKSURLEnv           = "TESTKIT_OIDC_JWKS_URL"
	oidcAudiencesEnv         = "TESTKIT_OIDC_AUDIENCES"
	oidcForwardedClaimsEnv   = "TESTKIT_OIDC_FORWARDED_CLAIMS"
	oidcSigningAlgorithmsEnv = "TESTKIT_OIDC_SIGNING_ALGORITHMS"
	oidcClaimPathSeparator   = "."
	oidcEnvironmentSeparator = ","
)

func configureOIDCProvider(ctx context.Context, store oidc.ProviderTrustStore, getenv func(string) string) error {
	provider, configured, err := oidcProviderFromEnv(getenv)
	if err != nil {
		return err
	}
	if !configured {
		return nil
	}
	if store == nil {
		return errors.New("testkit: OIDC provider trust store is required")
	}

	if _, err := store.TrustProvider(ctx, provider); err != nil {
		return fmt.Errorf("testkit: trust OIDC provider: %w", err)
	}

	return nil
}

func oidcProviderFromEnv(getenv func(string) string) (oidc.Provider, bool, error) {
	issuer := strings.TrimSpace(getenv(oidcIssuerEnv))
	if issuer == "" {
		return oidc.Provider{}, false, nil
	}

	jwksURL := strings.TrimSpace(getenv(oidcJWKSURLEnv))
	if jwksURL == "" {
		return oidc.Provider{}, false, fmt.Errorf(
			"testkit: %s is required when %s is set",
			oidcJWKSURLEnv,
			oidcIssuerEnv,
		)
	}
	audiences, err := requiredCSV(getenv, oidcAudiencesEnv)
	if err != nil {
		return oidc.Provider{}, false, err
	}
	forwardedClaims, err := optionalClaimPaths(getenv, oidcForwardedClaimsEnv)
	if err != nil {
		return oidc.Provider{}, false, err
	}
	signingAlgorithms, err := optionalCSV(getenv, oidcSigningAlgorithmsEnv)
	if err != nil {
		return oidc.Provider{}, false, err
	}

	provider := oidc.Provider{
		Issuer:                     issuer,
		Audiences:                  audiences,
		JWKSURL:                    jwksURL,
		SupportedSigningAlgorithms: signingAlgorithms,
		ForwardedClaims:            forwardedClaims,
	}
	if err := provider.Validate(); err != nil {
		return oidc.Provider{}, false, fmt.Errorf("testkit: invalid OIDC provider config: %w", err)
	}

	return provider, true, nil
}

func requiredCSV(getenv func(string) string, envName string) ([]string, error) {
	values, err := csvValues(getenv(envName), envName, true)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("testkit: %s is required when %s is set", envName, oidcIssuerEnv)
	}

	return values, nil
}

func optionalCSV(getenv func(string) string, envName string) ([]string, error) {
	return csvValues(getenv(envName), envName, false)
}

func csvValues(raw string, envName string, required bool) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		if required {
			return nil, fmt.Errorf("testkit: %s is required when %s is set", envName, oidcIssuerEnv)
		}

		return nil, nil
	}

	parts := strings.Split(raw, oidcEnvironmentSeparator)
	values := make([]string, 0, len(parts))
	for i, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			return nil, fmt.Errorf("testkit: %s item %d is empty", envName, i+1)
		}

		values = append(values, value)
	}

	return values, nil
}

func optionalClaimPaths(getenv func(string) string, envName string) ([]authkit.ClaimPath, error) {
	values, err := optionalCSV(getenv, envName)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, nil
	}

	paths := make([]authkit.ClaimPath, 0, len(values))
	for _, value := range values {
		path := authkit.ClaimPath(strings.Split(value, oidcClaimPathSeparator))
		if !path.Valid() {
			return nil, fmt.Errorf("testkit: %s claim path %q is invalid", envName, value)
		}

		paths = append(paths, path)
	}

	return paths, nil
}
