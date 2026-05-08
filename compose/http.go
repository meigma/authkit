package compose

import (
	"errors"
	"fmt"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/httpauth"
)

// HTTPOptions configures HTTP auth composition.
type HTTPOptions struct {
	// Authenticators are built and tried in order.
	Authenticators []AuthenticatorSpec

	// Resolver maps authenticated identities to internal principals.
	Resolver authkit.PrincipalResolver

	// Authorizer decides whether resolved principals may act on resources.
	Authorizer authkit.Authorizer

	// HTTPOptions configure the generated httpauth middleware.
	HTTPOptions []httpauth.Option
}

// HTTP is a composed authkit HTTP setup.
type HTTP struct {
	// Pipeline authenticates requests, resolves principals, and authorizes actions.
	Pipeline *authkit.Pipeline

	// Middleware adapts Pipeline to net/http handlers.
	Middleware *httpauth.Middleware
}

// NewHTTP composes authenticators, a pipeline, and net/http middleware.
func NewHTTP(opts HTTPOptions) (*HTTP, error) {
	authenticators, err := buildAuthenticators(opts.Authenticators)
	if err != nil {
		return nil, err
	}

	pipeline, err := authkit.NewPipeline(authkit.PipelineOptions{
		Authenticators: authenticators,
		Resolver:       opts.Resolver,
		Authorizer:     opts.Authorizer,
	})
	if err != nil {
		return nil, fmt.Errorf("compose: create pipeline: %w", err)
	}

	middleware, err := httpauth.NewMiddleware(pipeline, opts.HTTPOptions...)
	if err != nil {
		return nil, fmt.Errorf("compose: create HTTP middleware: %w", err)
	}

	return &HTTP{
		Pipeline:   pipeline,
		Middleware: middleware,
	}, nil
}

func buildAuthenticators(specs []AuthenticatorSpec) ([]authkit.Authenticator, error) {
	if len(specs) == 0 {
		return nil, errors.New("compose: at least one authenticator is required")
	}

	authenticators := make([]authkit.Authenticator, 0, len(specs))
	for i, spec := range specs {
		if spec == nil {
			return nil, fmt.Errorf("compose: authenticator spec %d is required", i)
		}

		authenticator, err := spec.BuildAuthenticator()
		if err != nil {
			return nil, fmt.Errorf("compose: build authenticator %d: %w", i, err)
		}
		if authenticator == nil {
			return nil, fmt.Errorf("compose: authenticator %d built nil authenticator", i)
		}

		authenticators = append(authenticators, authenticator)
	}

	return authenticators, nil
}
