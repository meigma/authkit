// Package apikey provides opaque API-token issuing and authentication.
//
// Tokens are storage-backed, revocable credentials. The service stores only a
// SHA-256 hash of the token secret, returns the plaintext token only at issue
// time, and authenticates successful tokens to authkit.Identity values with the
// Provider set to "api-token".
package apikey
