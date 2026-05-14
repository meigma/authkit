package accessjwtauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/accessjwt"
)

const (
	// Name identifies the authkit access-token authenticator.
	Name = "authkit-access-token"

	bearerScheme = "Bearer"
)

// Authenticator verifies authkit access JWT bearer tokens from HTTP requests.
type Authenticator struct {
	verifier        *accessjwt.Verifier
	principalFinder authkit.PrincipalFinder
}

// NewAuthenticator constructs an access JWT request authenticator.
func NewAuthenticator(
	verifier *accessjwt.Verifier,
	principalFinder authkit.PrincipalFinder,
) (*Authenticator, error) {
	if verifier == nil {
		return nil, errors.New("accessjwtauth: verifier is required")
	}
	if principalFinder == nil {
		return nil, errors.New("accessjwtauth: principal finder is required")
	}

	return &Authenticator{
		verifier:        verifier,
		principalFinder: principalFinder,
	}, nil
}

// Name returns the stable authenticator name.
func (a *Authenticator) Name() string {
	return Name
}

// AuthenticatePrincipal verifies the request's access JWT and loads its principal.
func (a *Authenticator) AuthenticatePrincipal(
	ctx context.Context,
	req *http.Request,
) (*authkit.PrincipalAuthentication, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, unauthenticated("request is required")
	}

	rawToken, err := bearerToken(req)
	if err != nil {
		return nil, err
	}

	verified, err := a.verifier.VerifyToken(ctx, rawToken)
	if err != nil {
		return nil, err
	}

	principal, err := a.principalFinder.FindPrincipal(ctx, verified.PrincipalID)
	if errors.Is(err, authkit.ErrPrincipalNotFound) {
		return nil, unauthenticated("principal not found")
	}
	if err != nil {
		return nil, fmt.Errorf("%w: find principal: %w", authkit.ErrInternal, err)
	}
	if principal.ID == "" {
		return nil, fmt.Errorf("%w: principal finder returned principal without ID", authkit.ErrInternal)
	}

	return &authkit.PrincipalAuthentication{
		Principal: principal,
	}, nil
}

func bearerToken(req *http.Request) (string, error) {
	header := req.Header.Get("Authorization")
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], bearerScheme) {
		return "", unauthenticated("bearer token is required")
	}

	return parts[1], nil
}

func unauthenticated(reason string) error {
	return fmt.Errorf("%w: %s", authkit.ErrUnauthenticated, reason)
}
