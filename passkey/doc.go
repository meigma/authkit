// Package passkey verifies WebAuthn passkey ceremonies for explicit authkit exchange flows.
//
// The package owns relying-party ceremony mechanics and credential state, but it
// does not provide HTTP handlers, browser session management, CSRF protection, or
// UI flows. Consumers should use the returned WebAuthn options and session data
// in their own transport layer, then exchange verified identities through
// authkit's onboarding or exchange packages.
package passkey
