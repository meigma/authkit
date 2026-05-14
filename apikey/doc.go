// Package apikey provides opaque API-token issuing and verification.
//
// Tokens are storage-backed, revocable credentials. The service stores only a
// SHA-256 hash of the token secret, returns the plaintext token only at issue
// time, and verifies successful tokens to principal-bearing token metadata.
// Deprecated identity-compatible authentication remains temporarily available
// while callers migrate to access JWT exchange.
package apikey
