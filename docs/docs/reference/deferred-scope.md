---
title: Current Scope And API Notes
description: Reference for authkit supported surfaces, deferred scope, and application responsibilities.
---

# Current Scope And API Notes

authkit's public API may change as service integrations shape the library. The
immediate goal is to integrate the library into a real service and learn from
that integration before committing to a compatibility promise.

## Current Supported Surface

authkit currently supports:

- core identity, principal, resource, decision, authorization fact, and port contracts
- explicit `Identity -> Principal -> Authorizer` request pipeline
- opaque API-token issuing, verification, revocation, expiration, and last-used tracking
- memory and Postgres storage for principals, local roles, identity links, API tokens, and OIDC provider trust
- Go-level management service for setup flows
- OIDC-issued JWT bearer-token authentication
- opt-in principal auto-provisioning for caller-approved external identities
- `net/http` middleware and context helpers
- optional HTTP fact helpers
- thin HTTP composition helpers
- local role authorization from effective action grants
- Casbin authorization adapter
- runnable notes example and tests

## Deferred Scope

The following items are intentionally out of scope:

- hosted browser login
- OAuth authorization server behavior
- SAML, SCIM, MFA, and user-management workflows
- built-in admin HTTP APIs
- router/framework-specific adapters
- SQLite storage
- advanced Casbin examples or policy models
- built-in principal enrichment from OIDC/JWT claims or external groups
- auto-provisioning rules that assign roles from external identity metadata
- custom policy language or relationship graph
- a compatibility promise before at least one real service integration

## Application Responsibilities

Applications own:

- admin endpoints, CLIs, seed scripts, or migrations
- principal lifecycle beyond the narrow setup operations
- provider trust lifecycle and approval workflows
- permission/action vocabulary and endpoint enforcement
- Casbin model, policy, and policy storage when using Casbin
- audit/event handling
- concrete production deployment and observability choices

For extension boundaries, see [Extension points](extension-points.md).
