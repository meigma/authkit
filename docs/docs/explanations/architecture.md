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
internal `Principal`. An `Authorizer` decides whether an authorization check
containing the principal, action, resource, and caller-supplied facts is allowed.

The invariant is credential independence: permissions attach to the internal
principal, not to a token, JWT, email address, or provider-specific user record.

## Authorization Model

Authorization receives the resolved principal, an action, a resource, and
optional decision-time facts. That shape keeps authorization independent from
the credential that authenticated the request.

authkit provides two authorizer adapters today. `roleauth` checks local
role-derived actions. `casbin` projects the same authorization check into an
application-owned Casbin model. Both sit behind the same `authkit.Authorizer`
port.

## Local Roles

Local roles are admin-managed authorization state. Applications define the
action vocabulary they enforce at handlers, such as `note:read`, while
administrators create roles, grant actions to roles, and assign principals to
roles through application-owned setup paths.

`roleauth` authorizes by resolving the principal's effective action set and
checking whether it contains the requested action. It does not derive
permissions from external identity metadata, provider groups, or token claims.

Provisioning rules can assign local roles when an external identity is first
auto-provisioned. Those rules remain local admin policy: they match only
verified claims explicitly forwarded by trusted provider configuration, and
they do not continuously sync external groups into local role membership.

## Authorization Facts

`authkit.Facts` is a generic decision-time context bag. Applications supply
facts per authorization decision for data such as tenant, environment, request
source, or loaded resource state. Facts are not injected automatically and do
not become durable principal or resource metadata.

`Principal.Attributes` remains application-owned actor metadata.
`Resource.Attributes` remains resource metadata. `AuthorizationRequest.Facts` is for
the current decision.

Facts are deliberately supplied by the route or application layer. authkit does
not automatically turn request headers, token claims, or provider metadata into
authorization facts because those inputs usually need application-specific
trust and normalization decisions.

## Ports And Adapters

The root `authkit` package contains the core types, errors, ports, and
`Pipeline`. It does not know whether principals, identity links, tokens, or
provider trust come from memory, Postgres, static configuration, or application
code.

Adapters sit at the edges:

- `apikey` issues and verifies opaque API tokens.
- `oidc` verifies signed JWT bearer tokens from trusted issuers.
- `onboarding` coordinates explicit identity attachment and principal provisioning.
- `provisioning` can create principals for caller-approved unresolved identities.
- `httpauth` adapts a pipeline to `net/http`.
- `httpfacts` provides optional helpers for deriving facts from HTTP requests.
- `roleauth` authorizes from local role-derived effective actions.
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

## Explicit Onboarding

Credential method packages own proof and method-specific storage. After a
credential method verifies auth material and returns an `authkit.Identity`,
applications can use `onboarding.Service` to attach that identity to an existing
principal or provision a new principal for it.

Onboarding is an explicit application flow. Authenticators and the runtime
pipeline do not create principals or attach identities while handling normal
authenticated requests. This keeps browser login, admin enrollment, recovery,
and trust checks in application-owned code while still reusing the same generic
identity link and principal provisioning ports.

## Auto-Provisioning

Auto-provisioning is an opt-in resolver behavior. A `provisioning.Resolver`
first tries normal identity resolution. If the identity is unresolved, it calls
application-owned policy code to decide whether that verified identity may
create a principal.

Provisioning always starts with an application-owned approval point. When a
rule source is configured, enabled provisioning rules may add initial local
role assignments during the same create-and-link operation. Rule conditions are
CEL bool expressions over the verified identity and forwarded claims; missing
claims and evaluation errors do not match rules, and existing principals are
not re-synced.

The OIDC authenticator and provisioning resolver have separate jobs. The
authenticator verifies the token and forwards only configured claims. The
resolver decides whether an unresolved verified identity may become a local
principal. Provisioning rules only inspect claims that crossed the provider's
forwarding boundary.

## HTTP Runtime

`httpauth.Middleware` stores the resolved authentication data in request context.
Authorization wrappers extract an authorization request from HTTP request state,
then pass the resolved principal, action, resource, and facts to the authorizer.
`RequireAuthorization` authenticates before it calls the extractor, so extractors
can read the resolved authentication from request context and unauthenticated
requests do not trigger resource or fact loading. The handler runs only when the
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
