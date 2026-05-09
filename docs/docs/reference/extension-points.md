---
title: Extension Points Reference
description: Reference for authkit interfaces and replaceable adapters.
---

# Extension Points Reference

authkit is built around small interfaces. Applications can use the provided
adapters or replace each boundary with application-owned code.

## Core Ports

### `authkit.Authenticator`

Verifies a request credential and returns an external identity. Implement this
for a custom credential source.

Provided adapters:

- `apikey.NewAuthenticator`
- `oidc.NewAuthenticator`

### `authkit.PrincipalResolver`

Maps an authenticated external identity to an internal principal. Implement this
when principal links live outside the provided stores.

Provided adapters:

- `store/memory.Store`
- `store/postgres.Store`

### `authkit.Authorizer`

Decides whether a principal can perform an action on a resource. Implement this
for a policy engine other than Casbin.

Provided adapter:

- `casbin.NewAuthorizer`

## Management Ports

### `authkit.PrincipalCreator`

Creates internal principals.

### `authkit.IdentityLinker`

Links external identities to internal principals.

The `management` package composes these ports with API-token issuing and
revocation for setup workflows.

## API Token Storage

`apikey.TokenStore` stores token metadata and hashed secrets. Implement it when
tokens need to live outside the provided memory or Postgres stores.

Provided adapters:

- `store/memory.Store`
- `store/postgres.Store`

## OIDC Provider Trust

`oidc.ProviderSource` returns trusted provider configuration for an issuer.
`oidc.ProviderTrustStore` adds mutation for setup flows.

Provided sources:

- `oidc.NewStaticProviderSource`
- `store/memory.Store`
- `store/postgres.Store`

## HTTP Adapter

`httpauth.WithErrorRenderer` replaces the default HTTP error rendering. Use it
when an API needs JSON errors, custom status bodies, or structured error
responses.

`httpauth.ResourceExtractor` lets a route map request state to an
`authkit.Resource` before authorization.

## Casbin Adapter

`casbin.WithRequestBuilder` replaces the default projection from
`Principal + action + Resource` to Casbin request values. Use it when an
application model expects a different subject, object, action, or attribute
shape.

## Composition Helper

`compose.NewHTTP` wires common `net/http` setups. It builds authenticators in
the order supplied, then constructs an `authkit.Pipeline` and
`httpauth.Middleware`.

Use direct composition instead when you need complete control over
authenticator construction or middleware setup.
