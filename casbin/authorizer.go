package casbin

import (
	"context"
	"errors"

	"github.com/meigma/authkit"
)

const deniedReason = "casbin policy denied"

// Enforcer is the Casbin enforcement surface required by Authorizer.
type Enforcer interface {
	// Enforce decides whether the request values satisfy the loaded Casbin policy.
	Enforce(rvals ...any) (bool, error)
}

// RequestBuilder projects authkit authorization inputs into Casbin request values.
type RequestBuilder func(authkit.Principal, string, authkit.Resource) ([]any, error)

// Authorizer adapts a Casbin enforcer to authkit.Authorizer.
type Authorizer struct {
	enforcer       Enforcer
	requestBuilder RequestBuilder
}

// NewAuthorizer constructs an Authorizer around enforcer.
func NewAuthorizer(enforcer Enforcer, opts ...Option) (*Authorizer, error) {
	if enforcer == nil {
		return nil, errors.New("casbin: enforcer is required")
	}

	cfg := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.requestBuilder == nil {
		return nil, errors.New("casbin: request builder is required")
	}

	return &Authorizer{
		enforcer:       enforcer,
		requestBuilder: cfg.requestBuilder,
	}, nil
}

// Can returns the Casbin decision for principal, action, and resource.
func (a *Authorizer) Can(
	ctx context.Context,
	principal authkit.Principal,
	action string,
	resource authkit.Resource,
) (authkit.Decision, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return authkit.Decision{}, ctxErr
	}

	request, err := a.requestBuilder(principal, action, resource)
	if err != nil {
		return authkit.Decision{}, err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return authkit.Decision{}, ctxErr
	}

	allowed, err := a.enforcer.Enforce(request...)
	if err != nil {
		return authkit.Decision{}, err
	}
	if !allowed {
		return authkit.Decision{
			Allowed: false,
			Reason:  deniedReason,
		}, nil
	}

	return authkit.Decision{Allowed: true}, nil
}

// DefaultRequestBuilder projects to the classic Casbin sub, obj, act request.
func DefaultRequestBuilder(
	principal authkit.Principal,
	action string,
	resource authkit.Resource,
) ([]any, error) {
	if principal.ID == "" {
		return nil, errors.New("casbin: principal ID is required")
	}
	if action == "" {
		return nil, errors.New("casbin: action is required")
	}
	if resource.Type == "" {
		return nil, errors.New("casbin: resource type is required")
	}

	return []any{principal.ID, resourceObject(resource), action}, nil
}

func resourceObject(resource authkit.Resource) string {
	if resource.ID == "" {
		return resource.Type
	}

	return resource.Type + ":" + resource.ID
}
