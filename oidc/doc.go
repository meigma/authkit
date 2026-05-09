// Package oidc authenticates signed JWT bearer tokens from trusted OIDC issuers.
//
// The package is intended for API resource servers. It validates bearer tokens
// against explicitly trusted issuer, audience, and JWKS configuration, then
// returns authkit identities keyed by issuer and subject. It does not implement
// hosted browser login, OAuth authorization server behavior, or permission
// grants from token claims. Trusted provider configuration can select which
// verified claims are forwarded into authkit identities for application-owned
// policy. Provider trust can come from static configuration, memory or Postgres
// stores, or an application-owned source. Use the provisioning package when a
// service wants opt-in principal creation for selected verified identities.
package oidc
