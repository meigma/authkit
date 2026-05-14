---
title: Extension Points Reference
description: Reference for authkit interfaces and replaceable adapters.
---

# Extension Points Reference

authkit is built around small interfaces. Applications can use the provided
adapters or replace each boundary with application-owned code.

For root data types and request shapes, see
[Core contracts reference](core-contracts.md).

## Core Ports

### `authkit.PrincipalAuthenticator`

Verifies a request credential and returns an internal principal. Use this for
protected-resource routes that accept authkit-issued access JWTs. External
credentials should be verified and exchanged before they reach protected
resource middleware.

Provided adapters:

- `accessjwtauth.NewAuthenticator`

### `authkit.PrincipalResolver`

Maps a verified external identity to an internal principal. Implement this when
principal links live outside the provided stores. The request pipeline no longer
uses this port directly; exchange and provisioning flows use it before issuing
authkit access JWTs.

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

### `authkit.ProvisioningRuleCreator` And Related Ports

Create, update, delete, find, and list admin-managed provisioning rules.
Applications can expose these through their own admin endpoints, CLIs, seed
scripts, or migrations.

### `authkit.IdentityLinker`

Links external identities to internal principals.

The `management` package composes these ports with API-token issuing and
revocation for setup and exchange workflows.

## Explicit Onboarding

`onboarding.NewService` composes `authkit.PrincipalFinder`,
`authkit.IdentityLinker`, and `authkit.IdentityProvisioner` for application-owned
onboarding flows.

Use `AttachIdentity` after an application has already verified that an existing
principal should receive a newly verified identity. Use `ProvisionPrincipal`
when application policy has approved creating a principal for a verified
identity. Credential method packages still own method-specific proof and
storage; onboarding only coordinates the generic identity relationship.

## Auto-Provisioning

`provisioning.NewResolver` wraps an existing `PrincipalResolver` with an
`authkit.IdentityProvisioner` and a caller-supplied principal factory. The
factory is the approval point for auto-provisioning and maps verified identity
claims into an `authkit.CreatePrincipalRequest`.

When configured with an `authkit.ProvisioningRuleLister`, the resolver matches
enabled provisioning rules and passes matching local role IDs to
`authkit.IdentityProvisioner` as initial role assignments.

For setup steps, see
[How to auto-provision OIDC principals](../how-to/auto-provision-oidc-principals.md).

## Exchange Services

`exchange.APITokenExchanger` verifies an opaque API token, resolves its
principal, and issues an authkit access JWT.

`exchange.IdentityExchanger` accepts an already verified `authkit.Identity`,
resolves or provisions the corresponding principal through an
`authkit.PrincipalResolver`, and issues an authkit access JWT.

Applications own the HTTP endpoint shape, CSRF protection, rate limiting,
response body, and browser/session behavior around exchange routes.

## API Token Storage

`apikey.TokenStore` stores token metadata and hashed secrets. Implement it when
tokens need to live outside the provided memory or Postgres stores.

Provided adapters:

- `store/memory.Store`
- `store/postgres.Store`

## OIDC Provider Trust

`oidc.ProviderSource` returns trusted provider configuration for an issuer.
`oidc.ProviderTrustStore` adds mutation for setup flows.

Trusted provider configuration can include forwarded claim paths. The OIDC
verifier copies only those verified claims, plus any static claims selected with
`oidc.WithForwardedClaims` or `oidc.WithForwardedClaimPaths`, into
`authkit.Identity.Claims`.

`oidc.NewVerifier` validates raw JWTs from trusted issuers and returns
`authkit.Identity` values. Use those identities with
`exchange.IdentityExchanger`; do not place OIDC JWTs directly on protected
resource routes.

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

For setup steps, see [How to configure local roles](../how-to/configure-local-roles.md).

## Composition Helper

`compose.NewHTTP` wires common `net/http` setups. It builds principal
authenticators in the order supplied, then constructs an `authkit.Pipeline` and
`httpauth.Middleware`.

Use direct composition instead when you need complete control over
authenticator construction or middleware setup.
