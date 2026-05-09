---
title: Security Model
description: Understand authkit security invariants, guarantees, and non-goals.
---

# Security Model

authkit is a library for API services that already own their application domain,
deployment model, and authorization policy. It verifies credentials, resolves
principals, and delegates policy decisions to an authorizer.

## API Tokens

API tokens are opaque, revocable, storage-backed credentials.

authkit generates token IDs and secrets with high entropy. The plaintext token
is returned only when issued. Storage adapters persist only the token secret
hash, expiration, revocation state, and metadata.

Token verification rejects malformed, unknown, expired, revoked, or mismatched
tokens. Successful verification returns an `authkit.Identity`; it does not bypass
principal resolution.

## OIDC JWT Bearer Tokens

OIDC support is for API resource servers validating externally issued JWT bearer
tokens. It is not hosted browser login and it is not an OAuth authorization
server.

The OIDC authenticator validates issuer, audience, signature, expiration, and
standard time claims against trusted provider configuration. Provider trust is
explicit and must come from static configuration, memory, Postgres, or an
application-owned `oidc.ProviderSource`.

OIDC identities use `(issuer, subject)` as the stable key. Email is not a stable
identity key.

## Auto-Provisioning

Auto-provisioning is opt in. The provisioning resolver runs only after a
credential has authenticated and normal identity resolution reports
`authkit.ErrUnresolvedIdentity`.

Provider trust does not imply provisioning approval. Applications provide the
factory that decides which identities may create principals and how forwarded
claims become display names or attributes.

Provisioning rules may assign initial local roles only when the principal is
first created. Rules are admin-managed local policy, match exact values from
verified forwarded token claims, and do not turn raw provider groups or roles
into permissions directly. Existing principals are not continuously reconciled
against external identity metadata.

## Fail-Closed Behavior

Provider trust lookup and token validation fail closed. If authkit cannot find
trusted provider configuration, cannot fetch or parse usable JWKS data, or
cannot verify a token, the request is unauthenticated.

Unexpected storage, provider, resolver, authorizer, or authorization-extractor
errors are treated as internal failures.

## Authorization

authkit does not grant permissions from arbitrary JWT claims. Verified claims
can be forwarded for display, logging, or application-owned policy hooks, but
the core authorization path is the resolved principal plus an action, resource,
and caller-supplied facts.

Trusted OIDC provider configuration controls which verified claims are exposed
through `authkit.Identity.Claims`. A provisioning rule can reference only
claims that provider configuration exposes. If a token omits an exposed claim,
the rule simply does not match.

Facts are decision-time context. authkit does not automatically inject HTTP
request data, token claims, or provider-specific groups into authorization
facts. Applications choose the facts they trust and pass them explicitly.

Local roles are admin-managed and grant action strings to principals through
role membership. The `roleauth` adapter checks only the principal's effective
action set; it does not inspect resources, facts, or provider metadata.

The Casbin adapter uses the principal ID as the default subject. Applications
own Casbin models, policy design, fact projection, and policy storage.

## Non-Goals

authkit does not provide:

- identity-provider behavior
- hosted browser login
- OAuth authorization server behavior
- SAML, SCIM, MFA, or user-management workflows
- built-in admin HTTP APIs
- a custom policy language or relationship graph

For scope and application responsibility details, see
[Current scope and API notes](../reference/deferred-scope.md).
