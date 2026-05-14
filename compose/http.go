package compose

import (
	"errors"
	"fmt"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/httpauth"
)

// HTTPOptions configures HTTP auth composition.
type HTTPOptions struct {
	// PrincipalAuthenticators are built and tried in order.
	PrincipalAuthenticators []PrincipalAuthenticatorSpec

	// Authorizer decides whether resolved principals may act on resources.
	Authorizer authkit.Authorizer

	// MiddlewareOptions configure the generated httpauth middleware.
	MiddlewareOptions []httpauth.Option
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
	principalAuthenticators, err := buildPrincipalAuthenticators(opts.PrincipalAuthenticators)
	if err != nil {
		return nil, err
	}
	if len(principalAuthenticators) == 0 {
		return nil, errors.New("compose: at least one principal authenticator is required")
	}

	pipeline, err := authkit.NewPipeline(authkit.PipelineOptions{
		PrincipalAuthenticators: principalAuthenticators,
		Authorizer:              opts.Authorizer,
	})
	if err != nil {
		return nil, fmt.Errorf("compose: create pipeline: %w", err)
	}

	middleware, err := httpauth.NewMiddleware(pipeline, opts.MiddlewareOptions...)
	if err != nil {
		return nil, fmt.Errorf("compose: create HTTP middleware: %w", err)
	}

	return &HTTP{
		Pipeline:   pipeline,
		Middleware: middleware,
	}, nil
}

func buildPrincipalAuthenticators(
	specs []PrincipalAuthenticatorSpec,
) ([]authkit.PrincipalAuthenticator, error) {
	authenticators := make([]authkit.PrincipalAuthenticator, 0, len(specs))
	for i, spec := range specs {
		if spec == nil {
			return nil, fmt.Errorf("compose: principal authenticator spec %d is required", i)
		}

		authenticator, err := spec.BuildPrincipalAuthenticator()
		if err != nil {
			return nil, fmt.Errorf("compose: build principal authenticator %d: %w", i, err)
		}
		if authenticator == nil {
			return nil, fmt.Errorf("compose: principal authenticator %d built nil authenticator", i)
		}

		authenticators = append(authenticators, authenticator)
	}

	return authenticators, nil
}
