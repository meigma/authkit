package apikey

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/meigma/authkit"
)

const bearerScheme = "Bearer"

// Authenticator verifies API tokens from HTTP Authorization headers.
//
// Deprecated: use VerifyAPIToken with exchange.APITokenExchanger for access JWT exchange.
type Authenticator struct {
	service *Service
}

// NewAuthenticator constructs an API-token authenticator.
func NewAuthenticator(service *Service) (*Authenticator, error) {
	if service == nil {
		return nil, errors.New("apikey: service is required")
	}

	return &Authenticator{
		service: service,
	}, nil
}

// Name returns the stable authenticator name.
func (a *Authenticator) Name() string {
	return Provider
}

// Authenticate verifies the request's bearer API token.
func (a *Authenticator) Authenticate(ctx context.Context, req *http.Request) (*authkit.Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if req == nil {
		return nil, unauthenticated("request is required")
	}

	header := req.Header.Get("Authorization")
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], bearerScheme) {
		return nil, unauthenticated("bearer token is required")
	}

	return a.service.VerifyToken(ctx, parts[1])
}
