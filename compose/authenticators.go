package compose

import (
	"github.com/meigma/authkit"
	"github.com/meigma/authkit/apikey"
	"github.com/meigma/authkit/oidc"
)

// AuthenticatorSpec builds one authkit authenticator for a composed service.
type AuthenticatorSpec interface {
	// BuildAuthenticator constructs the authenticator represented by the spec.
	BuildAuthenticator() (authkit.Authenticator, error)
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

type apiTokenAuthenticatorSpec struct {
	service *apikey.Service
}

// APIToken configures an API-token authenticator from service.
func APIToken(service *apikey.Service) AuthenticatorSpec {
	return apiTokenAuthenticatorSpec{service: service}
}

func (s apiTokenAuthenticatorSpec) BuildAuthenticator() (authkit.Authenticator, error) {
	return apikey.NewAuthenticator(s.service)
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
