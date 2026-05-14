---
title: How To Compose HTTP Authentication
description: Use compose.NewHTTP to wire authkit for a net/http API service.
---

# How To Compose HTTP Authentication

Use `compose.NewHTTP` when you want the standard `net/http` path with less
boilerplate. The helper builds principal authenticators, an `authkit.Pipeline`, and
`httpauth.Middleware`; your application still owns storage, provider trust,
local role or Casbin policy setup, and management workflows.

## Prerequisites

- A principal finder, such as `store/memory.Store` or `store/postgres.Store`
- An `accessjwt.Verifier` configured for authkit-issued access JWTs
- An authorizer, such as `roleauth.NewAuthorizer` or `casbin.NewAuthorizer`

API tokens are exchange credentials. Keep API-token verification in an
application-owned exchange route and protect resource routes with access JWTs.

## Create The Store

```go
store := memory.NewStore()
```

Use `store/postgres` instead of `store/memory` for production persistence after
running the Postgres migrations.

## Configure Access JWT Verification

```go
accessVerifier, err := accessjwt.NewVerifier(accessjwt.VerifierOptions{
	Issuer:   "https://auth.example",
	Audience: "notes-api",
	KeySet:   keySet,
})
if err != nil {
	return err
}
```

Your exchange routes should issue matching tokens with `accessjwt.Issuer`.

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
	PrincipalAuthenticators: []compose.PrincipalAuthenticatorSpec{
		compose.AccessJWT(accessVerifier, store),
	},
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
