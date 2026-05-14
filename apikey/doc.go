// Package apikey provides opaque API-token issuing and verification.
//
// Tokens are storage-backed, revocable credentials. The service stores only a
// SHA-256 hash of the token secret, returns the plaintext token only at issue
// time, and verifies successful tokens to principal-bearing token metadata for
// access JWT exchange.
package apikey
