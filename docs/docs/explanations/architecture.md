---
title: Architecture
description: Understand the authkit authentication and authorization architecture.
---

# Architecture

authkit separates credentials, application principals, and authorization policy.
That separation lets API tokens and OIDC-issued JWTs authenticate through
different mechanisms while resolving to the same internal principal.

## Core Pipeline

The core request path is:

```text
Authenticator -> Identity -> PrincipalResolver -> Principal -> Authorizer
```

An `Authenticator` verifies a credential on an HTTP request and returns an
external `Identity`. A `PrincipalResolver` maps that external identity to an
internal `Principal`. An `Authorizer` decides whether the principal can perform
an action on a resource.

The invariant is credential independence: permissions attach to the internal
principal, not to a token, JWT, email address, or provider-specific user record.

## Ports And Adapters

The root `authkit` package contains the core types, errors, ports, and
`Pipeline`. It does not know whether principals, identity links, tokens, or
provider trust come from memory, Postgres, static configuration, or application
code.

Adapters sit at the edges:

- `apikey` issues and verifies opaque API tokens.
- `oidc` verifies signed JWT bearer tokens from trusted issuers.
- `httpauth` adapts a pipeline to `net/http`.
- `casbin` adapts Casbin enforcement to the `authkit.Authorizer` port.
- `store/memory` and `store/postgres` implement storage contracts.
- `compose` wires common HTTP setups without replacing the lower-level ports.

## Identity Linking

Identity linking is explicit. Applications create principals, trust providers,
and link external identities to principals through setup code, migrations, CLIs,
or admin handlers they own.

For API tokens, the external identity is keyed as:

```text
provider = "api-token"
subject  = token ID
```

For OIDC, the external identity is keyed as:

```text
provider = issuer URL
subject  = JWT sub
```

A valid credential with no linked principal authenticates as a credential but
does not become an application principal.

## HTTP Runtime

`httpauth.Middleware` stores the resolved authentication data in request context.
Authorization wrappers extract a resource from the request, pass the principal,
action, and resource to the authorizer, and call the handler only when the
decision allows it.

Default HTTP failure mapping is:

- missing, invalid, or unlinked credentials -> `401 Unauthorized`
- denied authorization decisions -> `403 Forbidden`
- unexpected collaborator or extraction failures -> `500 Internal Server Error`

Applications can replace error rendering with `httpauth.WithErrorRenderer`.

## Composition Layers

For most `net/http` services, start with
[Compose HTTP authentication](../how-to/compose-http-auth.md). For full control,
use [explicit composition](../how-to/use-explicit-composition.md). Both paths
use the same root pipeline and extension points.
