// Package oidc authenticates signed JWT bearer tokens from trusted OIDC issuers.
//
// The package is intended for API resource servers. It validates bearer tokens
// against explicitly trusted issuer, audience, and JWKS configuration, then
// returns authkit identities keyed by issuer and subject. It does not implement
// hosted browser login, OAuth authorization server behavior, auto-provisioning,
// or permission grants from token claims.
package oidc
