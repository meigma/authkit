---
title: How To Compose HTTP Authentication
description: Use compose.NewHTTP to wire authkit for a net/http API service.
---

# How To Compose HTTP Authentication

Use `compose.NewHTTP` when you want the standard `net/http` path with less
boilerplate. The helper builds authenticators, an `authkit.Pipeline`, and
`httpauth.Middleware`; your application still owns storage, provider trust,
local role or Casbin policy setup, and management workflows.

## Prerequisites

- A principal resolver, such as `store/memory.Store` or `store/postgres.Store`
- At least one authenticator source, such as an API-token service or OIDC
  provider source
- An authorizer, such as `roleauth.NewAuthorizer` or `casbin.NewAuthorizer`

## Create The Store And Token Service

```go
store := memory.NewStore()

tokenService, err := apikey.NewService(store)
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
	ForwardedClaims: []authkit.ClaimPath{
		{"email"},
		{"groups"},
	},
})
if err != nil {
	return err
}
```

For mutable provider trust and provisioning rules, see
[How to auto-provision OIDC principals](auto-provision-oidc-principals.md).

## Configure Authorization

For action-only local role checks, grant actions to roles and adapt the store
with `roleauth`:

```go
authorizer, err := roleauth.NewAuthorizer(store)
if err != nil {
	return err
}
```

For role setup, see [How to configure local roles](configure-local-roles.md).

For resource-aware policy, applications can own the Casbin model and policy and
adapt an enforcer with the Casbin adapter:

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
		compose.OIDC(oidcSource),
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

For fact extraction details, see
[How to supply authorization facts](supply-authorization-facts.md).

For lower-level wiring, see
[Use explicit composition](use-explicit-composition.md).
