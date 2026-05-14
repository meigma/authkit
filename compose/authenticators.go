package compose

import (
	"github.com/meigma/authkit"
	"github.com/meigma/authkit/accessjwt"
	"github.com/meigma/authkit/accessjwtauth"
)

// PrincipalAuthenticatorSpec builds one authkit principal authenticator for a composed service.
type PrincipalAuthenticatorSpec interface {
	// BuildPrincipalAuthenticator constructs the authenticator represented by the spec.
	BuildPrincipalAuthenticator() (authkit.PrincipalAuthenticator, error)
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
