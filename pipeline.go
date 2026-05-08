package authkit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// PipelineOptions configures a Pipeline.
type PipelineOptions struct {
	// Authenticators verify request credentials in order.
	Authenticators []Authenticator

	// Resolver maps authenticated identities to internal principals.
	Resolver PrincipalResolver

	// Authorizer decides whether resolved principals may act on resources.
	Authorizer Authorizer
}

// Pipeline composes authentication, principal resolution, and authorization.
type Pipeline struct {
	authenticators []Authenticator
	resolver       PrincipalResolver
	authorizer     Authorizer
}

// Authentication describes a successfully authenticated and resolved request.
type Authentication struct {
	// AuthenticatorName is the name of the authenticator that accepted the request.
	AuthenticatorName string

	// Identity is the external identity returned by the authenticator.
	Identity Identity

	// Principal is the internal principal resolved from Identity.
	Principal Principal
}

// Authorization describes a successfully authenticated authorization attempt.
type Authorization struct {
	// Authentication is the authenticated and resolved request subject.
	Authentication Authentication

	// Decision is the authorizer decision for the requested action and resource.
	Decision Decision
}

// NewPipeline constructs a request auth pipeline from opts.
func NewPipeline(opts PipelineOptions) (*Pipeline, error) {
	if len(opts.Authenticators) == 0 {
		return nil, errors.New("authkit: at least one authenticator is required")
	}
	for i, authenticator := range opts.Authenticators {
		if authenticator == nil {
			return nil, fmt.Errorf("authkit: authenticator %d is required", i)
		}
	}
	if opts.Resolver == nil {
		return nil, errors.New("authkit: principal resolver is required")
	}
	if opts.Authorizer == nil {
		return nil, errors.New("authkit: authorizer is required")
	}

	authenticators := make([]Authenticator, len(opts.Authenticators))
	copy(authenticators, opts.Authenticators)

	return &Pipeline{
		authenticators: authenticators,
		resolver:       opts.Resolver,
		authorizer:     opts.Authorizer,
	}, nil
}

// Authenticate authenticates req and resolves the resulting identity to a principal.
func (p *Pipeline) Authenticate(ctx context.Context, req *http.Request) (Authentication, error) {
	for _, authenticator := range p.authenticators {
		authentication, authenticated, err := p.authenticateWith(ctx, req, authenticator)
		if err != nil {
			return authentication, err
		}
		if authenticated {
			return authentication, nil
		}
	}

	return Authentication{}, fmt.Errorf("%w: no authenticator accepted request", ErrUnauthenticated)
}

func (p *Pipeline) authenticateWith(
	ctx context.Context,
	req *http.Request,
	authenticator Authenticator,
) (Authentication, bool, error) {
	identity, err := authenticator.Authenticate(ctx, req)
	if err != nil {
		if isContextError(err) {
			return Authentication{}, false, err
		}
		if errors.Is(err, ErrUnauthenticated) {
			return Authentication{}, false, nil
		}

		return Authentication{}, false, fmt.Errorf(
			"%w: authenticator %q failed: %w",
			ErrInternal,
			authenticator.Name(),
			err,
		)
	}
	if identity == nil {
		return Authentication{}, false, fmt.Errorf(
			"%w: authenticator %q returned nil identity",
			ErrInternal,
			authenticator.Name(),
		)
	}

	authentication := Authentication{
		AuthenticatorName: authenticator.Name(),
		Identity:          *identity,
	}

	principal, err := p.resolver.ResolveIdentity(ctx, *identity)
	if err != nil {
		if isContextError(err) {
			return authentication, false, err
		}
		if errors.Is(err, ErrUnresolvedIdentity) {
			return authentication, false, err
		}

		return authentication, false, fmt.Errorf("%w: resolve identity: %w", ErrInternal, err)
	}
	if principal == nil {
		return authentication, false, fmt.Errorf("%w: resolver returned nil principal", ErrInternal)
	}

	authentication.Principal = *principal

	return authentication, true, nil
}

// Authorize authenticates req, resolves its principal, and checks action against resource.
func (p *Pipeline) Authorize(
	ctx context.Context,
	req *http.Request,
	action string,
	resource Resource,
) (Authorization, error) {
	authentication, err := p.Authenticate(ctx, req)
	authorization := Authorization{
		Authentication: authentication,
	}
	if err != nil {
		return authorization, err
	}

	decision, err := p.authorizer.Can(ctx, authentication.Principal, action, resource)
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
