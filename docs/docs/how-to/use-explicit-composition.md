---
title: How To Use Explicit Composition
description: Wire authenticators, the authkit pipeline, and HTTP middleware directly.
---

# How To Use Explicit Composition

Use explicit composition when you need full control over authenticator
construction, ordering, middleware options, or non-standard runtime wiring.

## Build Authenticators

```go
tokenAuthenticator, err := apikey.NewAuthenticator(tokenService)
if err != nil {
	return err
}

oidcAuthenticator, err := oidc.NewAuthenticator(
	providerSource,
	oidc.WithForwardedClaims("email", "name"),
)
if err != nil {
	return err
}
```

Authenticator order matters because API tokens and OIDC JWTs both use the
`Authorization: Bearer ...` header. The pipeline tries authenticators in the
order supplied.

## Build The Pipeline

```go
pipeline, err := authkit.NewPipeline(authkit.PipelineOptions{
	Authenticators: []authkit.Authenticator{
		tokenAuthenticator,
		oidcAuthenticator,
	},
	Resolver:   principalResolver,
	Authorizer: authorizer,
})
if err != nil {
	return err
}
```

The resolver maps external identities to internal principals. The authorizer
receives the resolved principal, action, and resource.

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
or `RequireFunc` when a route also needs an authorization decision.

```go
mux.Handle("GET /me", middleware.Authenticate(meHandler))

mux.Handle(
	"GET /notes/{noteID}",
	middleware.RequireFunc("note:read", extractNoteResource)(notesHandler),
)
```

For the standard HTTP path, see
[Compose HTTP authentication](compose-http-auth.md).
