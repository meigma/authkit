package compose

import (
	"github.com/meigma/authkit"
	"github.com/meigma/authkit/accessjwt"
	"github.com/meigma/authkit/accessjwtauth"
	"github.com/meigma/authkit/oidc"
)

// PrincipalAuthenticatorSpec builds one authkit principal authenticator for a composed service.
type PrincipalAuthenticatorSpec interface {
	// BuildPrincipalAuthenticator constructs the authenticator represented by the spec.
	BuildPrincipalAuthenticator() (authkit.PrincipalAuthenticator, error)
}

// AuthenticatorSpec builds one authkit authenticator for a composed service.
type AuthenticatorSpec interface {
	// BuildAuthenticator constructs the authenticator represented by the spec.
	BuildAuthenticator() (authkit.Authenticator, error)
}

type accessJWTAuthenticatorSpec struct {
	verifier        *accessjwt.Verifier
	principalFinder authkit.PrincipalFinder
}

// AccessJWT configures an access JWT authenticator from verifier and principalFinder.
func AccessJWT(
	verifier *accessjwt.Verifier,
	principalFinder authkit.PrincipalFinder,
) PrincipalAuthenticatorSpec {
	return accessJWTAuthenticatorSpec{
		verifier:        verifier,
		principalFinder: principalFinder,
	}
}

func (s accessJWTAuthenticatorSpec) BuildPrincipalAuthenticator() (authkit.PrincipalAuthenticator, error) {
	return accessjwtauth.NewAuthenticator(s.verifier, s.principalFinder)
}

type existingAuthenticatorSpec struct {
	authenticator authkit.Authenticator
}

// Existing wraps an already constructed authkit authenticator.
func Existing(authenticator authkit.Authenticator) AuthenticatorSpec {
	return existingAuthenticatorSpec{authenticator: authenticator}
}

func (s existingAuthenticatorSpec) BuildAuthenticator() (authkit.Authenticator, error) {
	return s.authenticator, nil
}

type oidcAuthenticatorSpec struct {
	source oidc.ProviderSource
	opts   []oidc.Option
}

// OIDC configures an OIDC JWT bearer-token authenticator from source.
func OIDC(source oidc.ProviderSource, opts ...oidc.Option) AuthenticatorSpec {
	copied := make([]oidc.Option, len(opts))
	copy(copied, opts)

	return oidcAuthenticatorSpec{
		source: source,
		opts:   copied,
	}
}

func (s oidcAuthenticatorSpec) BuildAuthenticator() (authkit.Authenticator, error) {
	return oidc.NewAuthenticator(s.source, s.opts...)
}
