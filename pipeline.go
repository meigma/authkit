package authkit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// PipelineOptions configures a Pipeline.
type PipelineOptions struct {
	// PrincipalAuthenticators verify request credentials that authenticate directly to principals.
	PrincipalAuthenticators []PrincipalAuthenticator

	// Authorizer decides whether resolved principals may act on resources.
	Authorizer Authorizer
}

// Pipeline composes principal authentication and authorization.
type Pipeline struct {
	principalAuthenticators []PrincipalAuthenticator
	authorizer              Authorizer
}

// Authentication describes a successfully authenticated request.
type Authentication struct {
	// AuthenticatorName is the name of the authenticator that accepted the request.
	AuthenticatorName string

	// Principal is the internal principal authenticated by the request.
	Principal Principal
}

// Authorization describes a successfully authenticated authorization attempt.
type Authorization struct {
	// Authentication is the authenticated and resolved request subject.
	Authentication Authentication

	// Check is the complete input used for the authorizer decision.
	Check AuthorizationCheck

	// Decision is the authorizer decision for Check.
	Decision Decision
}

// NewPipeline constructs a request auth pipeline from opts.
func NewPipeline(opts PipelineOptions) (*Pipeline, error) {
	if len(opts.PrincipalAuthenticators) == 0 {
		return nil, errors.New("authkit: at least one principal authenticator is required")
	}
	for i, authenticator := range opts.PrincipalAuthenticators {
		if authenticator == nil {
			return nil, fmt.Errorf("authkit: principal authenticator %d is required", i)
		}
	}
	if opts.Authorizer == nil {
		return nil, errors.New("authkit: authorizer is required")
	}

	principalAuthenticators := make([]PrincipalAuthenticator, len(opts.PrincipalAuthenticators))
	copy(principalAuthenticators, opts.PrincipalAuthenticators)

	return &Pipeline{
		principalAuthenticators: principalAuthenticators,
		authorizer:              opts.Authorizer,
	}, nil
}

// Authenticate authenticates req and returns the resulting principal.
func (p *Pipeline) Authenticate(ctx context.Context, req *http.Request) (Authentication, error) {
	for _, authenticator := range p.principalAuthenticators {
		authentication, authenticated, err := p.authenticatePrincipalWith(ctx, req, authenticator)
		if err != nil {
			return authentication, err
		}
		if authenticated {
			return authentication, nil
		}
	}

	return Authentication{}, fmt.Errorf("%w: no principal authenticator accepted request", ErrUnauthenticated)
}

func (p *Pipeline) authenticatePrincipalWith(
	ctx context.Context,
	req *http.Request,
	authenticator PrincipalAuthenticator,
) (Authentication, bool, error) {
	principalAuthentication, err := authenticator.AuthenticatePrincipal(ctx, req)
	if err != nil {
		if isContextError(err) {
			return Authentication{}, false, err
		}
		if errors.Is(err, ErrUnauthenticated) {
			return Authentication{}, false, nil
		}

		return Authentication{}, false, fmt.Errorf(
			"%w: principal authenticator %q failed: %w",
			ErrInternal,
			authenticator.Name(),
			err,
		)
	}
	if principalAuthentication == nil {
		return Authentication{}, false, fmt.Errorf(
			"%w: principal authenticator %q returned nil authentication",
			ErrInternal,
			authenticator.Name(),
		)
	}
	if principalAuthentication.Principal.ID == "" {
		return Authentication{}, false, fmt.Errorf(
			"%w: principal authenticator %q returned principal without ID",
			ErrInternal,
			authenticator.Name(),
		)
	}

	return Authentication{
		AuthenticatorName: authenticator.Name(),
		Principal:         principalAuthentication.Principal,
	}, true, nil
}

// Authorize authenticates req and evaluates authorization.
func (p *Pipeline) Authorize(
	ctx context.Context,
	req *http.Request,
	authorizationRequest AuthorizationRequest,
) (Authorization, error) {
	authentication, err := p.Authenticate(ctx, req)
	authorization := Authorization{
		Authentication: authentication,
	}
	if err != nil {
		return authorization, err
	}

	return p.AuthorizeAuthenticated(ctx, authentication, authorizationRequest)
}

// AuthorizeAuthenticated evaluates authorization for an already authenticated request subject.
func (p *Pipeline) AuthorizeAuthenticated(
	ctx context.Context,
	authentication Authentication,
	authorizationRequest AuthorizationRequest,
) (Authorization, error) {
	authorization := Authorization{
		Authentication: authentication,
	}

	check := AuthorizationCheck{
		Principal: authentication.Principal,
		Action:    authorizationRequest.Action,
		Resource:  authorizationRequest.Resource,
		Facts:     authorizationRequest.Facts.Clone(),
	}
	authorization.Check = check

	decision, err := p.authorizer.Can(ctx, check)
	authorization.Decision = decision
	if err != nil {
		if isContextError(err) {
			return authorization, err
		}

		return authorization, fmt.Errorf("%w: authorize: %w", ErrInternal, err)
	}
	if !decision.Allowed {
		if decision.Reason == "" {
			return authorization, fmt.Errorf("%w: decision denied", ErrUnauthorized)
		}

		return authorization, fmt.Errorf("%w: %s", ErrUnauthorized, decision.Reason)
	}

	return authorization, nil
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
