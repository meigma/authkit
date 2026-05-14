// Package accessjwt issues and verifies authkit-owned access JWTs.
//
// Access JWTs authenticate an authkit principal. They intentionally carry only
// principal identity and token metadata; authorization data stays in authkit
// storage and is evaluated at request time.
package accessjwt
