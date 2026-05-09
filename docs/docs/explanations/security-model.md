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

Provisioning does not grant permissions. A newly provisioned principal still
needs application-owned authorization policy before it can access protected
resources.

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

Facts are decision-time context. authkit does not automatically inject HTTP
request data, token claims, or provider-specific groups into authorization
facts. Applications choose the facts they trust and pass them explicitly.

The Casbin adapter uses the principal ID as the default subject. Applications
own Casbin models, policy, role design, fact projection, and policy storage.

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
