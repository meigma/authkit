package exchange

import (
	"context"
	"errors"
	"fmt"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/accessjwt"
)

// IdentityExchanger exchanges verified external identities for authkit access JWTs.
type IdentityExchanger struct {
	resolver     authkit.PrincipalResolver
	accessTokens AccessTokenIssuer
}

// NewIdentityExchanger constructs an IdentityExchanger from opts.
func NewIdentityExchanger(opts IdentityOptions) (*IdentityExchanger, error) {
	if opts.Resolver == nil {
		return nil, errors.New("exchange: principal resolver is required")
	}
	if opts.AccessTokens == nil {
		return nil, errors.New("exchange: access token issuer is required")
	}

	return &IdentityExchanger{
		resolver:     opts.Resolver,
		accessTokens: opts.AccessTokens,
	}, nil
}

// Exchange resolves req.Identity and issues an access JWT for its principal.
func (e *IdentityExchanger) Exchange(ctx context.Context, req IdentityRequest) (IdentityResult, error) {
	if err := ctx.Err(); err != nil {
		return IdentityResult{}, err
	}

	principal, err := e.resolver.ResolveIdentity(ctx, req.Identity)
	if err != nil {
		return IdentityResult{}, exchangeError("resolve identity", err)
	}
	if principal == nil {
		return IdentityResult{}, fmt.Errorf("%w: resolve identity returned nil principal", authkit.ErrInternal)
	}
	if principal.ID == "" {
		return IdentityResult{}, fmt.Errorf("%w: resolved principal ID is required", authkit.ErrInternal)
	}

	accessToken, err := e.accessTokens.IssueToken(ctx, accessjwt.IssueRequest{
		PrincipalID: principal.ID,
	})
	if err != nil {
		return IdentityResult{}, exchangeError("issue access token", err)
	}

	return IdentityResult{
		Identity:    req.Identity,
		Principal:   *principal,
		AccessToken: accessToken,
	}, nil
}
