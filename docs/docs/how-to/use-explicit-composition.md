---
title: How To Use Explicit Composition
description: Wire principal authenticators, the authkit pipeline, and HTTP middleware directly.
---

# How To Use Explicit Composition

Use explicit composition when you need full control over principal authenticator
construction, ordering, middleware options, or non-standard runtime wiring.

## Build Principal Authenticators

```go
accessAuthenticator, err := accessjwtauth.NewAuthenticator(accessVerifier, principalFinder)
if err != nil {
	return err
}
```

API tokens are exchanged for access JWTs before they reach protected-resource
middleware. Runtime resource routes should authenticate authkit-issued access
JWTs.

## Build The Pipeline

```go
pipeline, err := authkit.NewPipeline(authkit.PipelineOptions{
	PrincipalAuthenticators: []authkit.PrincipalAuthenticator{
		accessAuthenticator,
	},
	Authorizer: authorizer,
})
if err != nil {
	return err
}
```

The access JWT authenticator verifies the bearer token and loads the principal.
The authorizer receives an authorization check containing that principal,
action, resource, and optional facts.

## Build HTTP Middleware

```go
middleware, err := httpauth.NewMiddleware(
	pipeline,
	httpauth.WithErrorRenderer(customRenderer),
)
if err != nil {
	return err
}
```

Use `Authenticate` when a route only needs a resolved principal. Use `Require`
or `RequireFunc` when a route only needs an action and resource. Use
`RequireAuthorization` when a route also needs to supply decision-time facts.

```go
mux.Handle("GET /me", middleware.Authenticate(meHandler))

mux.Handle(
	"GET /notes/{noteID}",
	middleware.RequireFunc("note:read", extractNoteResource)(notesHandler),
)

mux.Handle(
	"POST /deployments/{deploymentID}",
	middleware.RequireAuthorization(extractDeploymentAuthorization)(deployHandler),
)
```

For route facts, see [Supply authorization facts](supply-authorization-facts.md).
For the standard HTTP path, see
[Compose HTTP authentication](compose-http-auth.md).
