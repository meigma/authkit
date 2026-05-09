---
title: How To Compose HTTP Authentication
description: Use compose.NewHTTP to wire authkit for a net/http API service.
---

# How To Compose HTTP Authentication

Use `compose.NewHTTP` when you want the standard `net/http` path with less
boilerplate. The helper builds authenticators, an `authkit.Pipeline`, and
`httpauth.Middleware`; your application still owns storage, provider trust,
Casbin policy setup, and management workflows.

## Create The Stores And Services

```go
store := memory.NewStore()

tokenService, err := apikey.NewService(store)
if err != nil {
	return err
}

managementService, err := management.NewService(management.Options{
	PrincipalCreator: store,
	IdentityLinker:   store,
	APITokens:        tokenService,
})
if err != nil {
	return err
}
```

Use `store/postgres` instead of `store/memory` for production persistence after
running the Postgres migrations.

## Configure Provider Trust

Use a static provider source, a mutable store, or an application-owned source:

```go
oidcSource, err := oidc.NewStaticProviderSource(oidc.Provider{
	Issuer:    "https://issuer.example",
	Audiences: []string{"notes-api"},
	JWKSURL:   "https://issuer.example/.well-known/jwks.json",
})
if err != nil {
	return err
}
```

## Configure Authorization

Applications own the Casbin model and policy. Adapt an enforcer with the Casbin
adapter:

```go
authorizer, err := authkitcasbin.NewAuthorizer(enforcer)
if err != nil {
	return err
}
```

## Build The HTTP Auth Path

```go
kit, err := compose.NewHTTP(compose.HTTPOptions{
	Authenticators: []compose.AuthenticatorSpec{
		compose.APIToken(tokenService),
		compose.OIDC(oidcSource, oidc.WithForwardedClaims("email", "name")),
	},
	Resolver:   store,
	Authorizer: authorizer,
})
if err != nil {
	return err
}
```

`kit.Pipeline` is the core pipeline. `kit.Middleware` adapts the pipeline to
`net/http`.

## Protect A Route

```go
mux.Handle(
	"GET /notes/{noteID}",
	kit.Middleware.RequireAuthorization(func(req *http.Request) (authkit.AuthorizationRequest, error) {
		return authkit.AuthorizationRequest{
			Action: "note:read",
			Resource: authkit.Resource{
				Type: "note",
				ID:   req.PathValue("noteID"),
			},
			Facts: authkit.MergeFacts(
				httpfacts.Method(req),
				httpfacts.Header(req, "X-Tenant-Id"),
			),
		}, nil
	})(notesHandler),
)
```

For lower-level wiring, see
[Use explicit composition](use-explicit-composition.md).
