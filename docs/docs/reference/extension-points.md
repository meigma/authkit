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
- `provisioning.NewResolver`

### `authkit.IdentityProvisioner`

Atomically creates a principal and links an external identity, or returns the
existing linked principal. Implement this when auto-provisioned principals live
outside the provided stores.

Provided adapters:

- `store/memory.Store`
- `store/postgres.Store`

### `authkit.Authorizer`

Decides whether an `authkit.AuthorizationCheck` is allowed. The check contains
the resolved principal, action, resource, and caller-supplied decision facts.
Implement this for a policy engine other than Casbin.

Provided adapters:

- `roleauth.NewAuthorizer`
- `casbin.NewAuthorizer`

## Management Ports

### `authkit.PrincipalCreator`

Creates internal principals.

### `authkit.RoleCreator`

Creates admin-managed local roles.

### `authkit.RoleActionGranter`

Grants authorization action strings to local roles.

### `authkit.PrincipalRoleAssigner`

Assigns principals to local roles.

### `authkit.PrincipalActionResolver`

Resolves a principal's effective action strings from local role membership.

### `authkit.IdentityLinker`

Links external identities to internal principals.

The `management` package composes these ports with API-token issuing and
revocation for setup workflows.

## Auto-Provisioning

`provisioning.NewResolver` wraps an existing `PrincipalResolver` with an
`authkit.IdentityProvisioner` and a caller-supplied principal factory. The
factory is the approval point for auto-provisioning and maps verified identity
claims into an `authkit.CreatePrincipalRequest`.

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

`httpauth.AuthorizationExtractor` lets a route map request state to an
`authkit.AuthorizationRequest` before authorization. Use it when a route needs
to supply decision-time facts. The extractor receives a request whose context
already contains the resolved `authkit.Authentication`.

`httpauth.ResourceExtractor` remains available for routes that only need to map
request state to an `authkit.Resource`.

The `httpfacts` package provides optional helpers for deriving method, host,
path, remote address, selected header, and path-value facts from HTTP requests.
These helpers do not inject facts automatically.

## Casbin Adapter

`casbin.WithRequestBuilder` replaces the default projection from
`authkit.AuthorizationCheck` to Casbin request values. Use it when an
application model expects facts, a different subject, object, action, or
attribute shape.

## Local Role Adapter

`roleauth.NewAuthorizer` checks whether the resolved principal has the requested
`authkit.AuthorizationCheck.Action` through admin-managed local role grants. It
does not inspect resource metadata, facts, or external provider claims.

## Composition Helper

`compose.NewHTTP` wires common `net/http` setups. It builds authenticators in
the order supplied, then constructs an `authkit.Pipeline` and
`httpauth.Middleware`.

Use direct composition instead when you need complete control over
authenticator construction or middleware setup.
