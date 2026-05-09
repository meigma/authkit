package httpauth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/meigma/authkit"
)

// ErrorRenderer renders auth failures to an HTTP response.
type ErrorRenderer func(http.ResponseWriter, *http.Request, error)

// ResourceExtractor extracts the authorization target from an HTTP request.
type ResourceExtractor func(*http.Request) (authkit.Resource, error)

// AuthorizationExtractor extracts an authorization request from an authenticated HTTP request.
type AuthorizationExtractor func(*http.Request) (authkit.AuthorizationRequest, error)

// Middleware adapts an authkit Pipeline to net/http handlers.
type Middleware struct {
	pipeline *authkit.Pipeline
	renderer ErrorRenderer
}

// NewMiddleware constructs HTTP middleware around pipeline.
func NewMiddleware(pipeline *authkit.Pipeline, opts ...Option) (*Middleware, error) {
	if pipeline == nil {
		return nil, errors.New("httpauth: pipeline is required")
	}

	cfg := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.renderer == nil {
		cfg.renderer = defaultErrorRenderer
	}

	return &Middleware{
		pipeline: pipeline,
		renderer: cfg.renderer,
	}, nil
}

// Authenticate authenticates req, stores auth data in request context, and calls next.
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authentication, err := m.pipeline.Authenticate(req.Context(), req)
		if err != nil {
			m.renderer(w, req, err)

			return
		}

		next.ServeHTTP(w, req.WithContext(contextWithAuthentication(req.Context(), authentication)))
	})
}

// Require returns middleware that authorizes action against resource.
func (m *Middleware) Require(
	action string,
	resource authkit.Resource,
) func(http.Handler) http.Handler {
	return m.RequireAuthorization(func(*http.Request) (authkit.AuthorizationRequest, error) {
		return authkit.AuthorizationRequest{
			Action:   action,
			Resource: resource,
		}, nil
	})
}

// RequireFunc returns middleware that extracts a resource and authorizes action.
func (m *Middleware) RequireFunc(
	action string,
	extract ResourceExtractor,
) func(http.Handler) http.Handler {
	return m.RequireAuthorization(func(req *http.Request) (authkit.AuthorizationRequest, error) {
		if extract == nil {
			return authkit.AuthorizationRequest{}, errors.New("resource extractor is required")
		}

		resource, err := extract(req)
		if err != nil {
			return authkit.AuthorizationRequest{}, fmt.Errorf("extract resource: %w", err)
		}

		return authkit.AuthorizationRequest{
			Action:   action,
			Resource: resource,
		}, nil
	})
}

// RequireAuthorization authenticates, extracts, and evaluates an authorization request.
func (m *Middleware) RequireAuthorization(
	extract AuthorizationExtractor,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			authentication, err := m.pipeline.Authenticate(req.Context(), req)
			if err != nil {
				m.renderer(w, req, err)

				return
			}

			authenticatedReq := req.WithContext(contextWithAuthentication(req.Context(), authentication))
			if extract == nil {
				m.renderer(
					w,
					authenticatedReq,
					fmt.Errorf("%w: authorization extractor is required", authkit.ErrInternal),
				)

				return
			}

			authorizationRequest, err := extract(authenticatedReq)
			if err != nil {
				m.renderer(
					w,
					authenticatedReq,
					fmt.Errorf("%w: extract authorization: %w", authkit.ErrInternal, err),
				)

				return
			}

			authorization, err := m.pipeline.AuthorizeAuthenticated(
				authenticatedReq.Context(),
				authentication,
				authorizationRequest,
			)
			if err != nil {
				m.renderer(w, authenticatedReq, err)

				return
			}

			ctx := contextWithAuthentication(authenticatedReq.Context(), authorization.Authentication)
			next.ServeHTTP(w, authenticatedReq.WithContext(ctx))
		})
	}
}

func defaultErrorRenderer(w http.ResponseWriter, _ *http.Request, err error) {
	status := http.StatusInternalServerError
	if errors.Is(err, authkit.ErrUnauthenticated) || errors.Is(err, authkit.ErrUnresolvedIdentity) {
		status = http.StatusUnauthorized
	}
	if errors.Is(err, authkit.ErrUnauthorized) {
		status = http.StatusForbidden
	}

	http.Error(w, http.StatusText(status), status)
}
