package exchange

import (
	"context"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/accessjwt"
	"github.com/meigma/authkit/apikey"
)

// APITokenVerifier verifies opaque API tokens.
type APITokenVerifier interface {
	// VerifyAPIToken verifies plaintext and returns its authenticated token metadata.
	VerifyAPIToken(ctx context.Context, plaintext string) (apikey.VerifiedToken, error)
}

// AccessTokenIssuer issues authkit access JWTs.
type AccessTokenIssuer interface {
	// IssueToken issues an access JWT for req.PrincipalID.
	IssueToken(ctx context.Context, req accessjwt.IssueRequest) (accessjwt.IssuedToken, error)
}

// APITokenOptions configures an APITokenExchanger.
type APITokenOptions struct {
	// APITokens verifies opaque API tokens.
	APITokens APITokenVerifier

	// Principals loads principals authenticated by API tokens.
	Principals authkit.PrincipalFinder

	// AccessTokens issues authkit access JWTs.
	AccessTokens AccessTokenIssuer
}

// APITokenRequest describes an API-token exchange request.
type APITokenRequest struct {
	// Plaintext is the opaque API token presented for exchange.
	Plaintext string
}

// APITokenResult describes a completed API-token exchange.
type APITokenResult struct {
	// APIToken is the verified opaque API token metadata.
	APIToken apikey.VerifiedToken

	// Principal is the principal authenticated by APIToken.
	Principal authkit.Principal

	// AccessToken is the authkit access JWT issued for Principal.
	AccessToken accessjwt.IssuedToken
}
