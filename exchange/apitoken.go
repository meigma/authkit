package exchange

import (
	"context"
	"errors"
	"fmt"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/accessjwt"
)

// APITokenExchanger exchanges opaque API tokens for authkit access JWTs.
type APITokenExchanger struct {
	apiTokens    APITokenVerifier
	principals   authkit.PrincipalFinder
	accessTokens AccessTokenIssuer
}

// NewAPITokenExchanger constructs an APITokenExchanger from opts.
func NewAPITokenExchanger(opts APITokenOptions) (*APITokenExchanger, error) {
	if opts.APITokens == nil {
		return nil, errors.New("exchange: API token verifier is required")
	}
	if opts.Principals == nil {
		return nil, errors.New("exchange: principal finder is required")
	}
	if opts.AccessTokens == nil {
		return nil, errors.New("exchange: access token issuer is required")
	}

	return &APITokenExchanger{
		apiTokens:    opts.APITokens,
		principals:   opts.Principals,
		accessTokens: opts.AccessTokens,
	}, nil
}

// Exchange verifies req.Plaintext and issues an access JWT for the token principal.
func (e *APITokenExchanger) Exchange(ctx context.Context, req APITokenRequest) (APITokenResult, error) {
	if err := ctx.Err(); err != nil {
		return APITokenResult{}, err
	}

	apiToken, err := e.apiTokens.VerifyAPIToken(ctx, req.Plaintext)
	if err != nil {
		return APITokenResult{}, exchangeError("verify API token", err)
	}

	principal, err := e.principals.FindPrincipal(ctx, apiToken.PrincipalID)
	if errors.Is(err, authkit.ErrPrincipalNotFound) {
		return APITokenResult{}, unauthenticated("principal not found")
	}
	if err != nil {
		return APITokenResult{}, exchangeError("find principal", err)
	}

	accessToken, err := e.accessTokens.IssueToken(ctx, accessjwt.IssueRequest{
		PrincipalID: principal.ID,
	})
	if err != nil {
		return APITokenResult{}, exchangeError("issue access token", err)
	}

	return APITokenResult{
		APIToken:    apiToken,
		Principal:   principal,
		AccessToken: accessToken,
	}, nil
}

func exchangeError(operation string, err error) error {
	if isContextError(err) {
		return err
	}
	if errors.Is(err, authkit.ErrUnauthenticated) {
		return err
	}

	return fmt.Errorf("%w: %s: %w", authkit.ErrInternal, operation, err)
}

func unauthenticated(reason string) error {
	return fmt.Errorf("%w: %s", authkit.ErrUnauthenticated, reason)
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
