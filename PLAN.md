# Implementation Plan

Status: refreshed after the OIDC exchange migration

This plan starts from the current working prototype instead of replaying the
original phase sequence. The goal is to turn the proven shape into a usable v0
library while preserving the same working style: small phases, real behavior,
and room to reshape the next step based on what implementation teaches us.

## Current Baseline

The first API-token prototype is present in the repository:

- core `authkit` identity, principal, resource, decision, authorization fact, and port contracts
- explicit `PrincipalAuthenticator -> Principal -> Authorizer` protected-resource pipeline
- memory-backed principal, local-role, identity-link, and API-token storage
- local role authorization from effective action grants
- opaque API-token issuing, verification, revocation, expiration, and last-used tracking
- router-neutral `net/http` middleware with context helpers and authorization wrappers
- thin Casbin authorizer adapter with replaceable request projection
- opt-in principal auto-provisioning for caller-approved external identities
- admin-managed CEL provisioning rules for initial role assignment from verified forwarded OIDC claims
- `testkit`, a runnable pastebin app that wires the real packages together
- focused behavior tests around token exchange, memory, pipeline, HTTP, local roles, Casbin, and testkit paths

The prototype intentionally does not include hosted login, router-specific
adapters, built-in admin HTTP APIs, or browser session management.

## Planning Principles

- Preserve the central invariant: external proof is exchanged before protected
  resource access, and authorization operates on `Principal + action + Resource
  + caller-supplied Facts`.
- Keep explicit composition as the architectural foundation. Convenience APIs
  can wrap the common path later, but they must not hide or replace the ports.
- Prove each new capability through a real vertical path before broadening it.
- Keep concrete storage, provider trust, HTTP rendering, and authorization
  policy replaceable at adapter boundaries.
- Do not add a built-in admin HTTP API. Reusable Go services are useful;
  applications decide whether to expose them through REST, CLI, seed scripts,
  migrations, or internal setup code.
- Do not build a second policy language above Casbin. The library should feed
  stable subjects, actions, and resources into application-owned policy.
- Keep action strings as the current permission vocabulary until a real cleanup
  is worthwhile. A future API pass may add a named action/permission type, but
  local roles should not force that refactor.
- Keep docs and design notes practical. Update them when implementation changes
  the shape, but do not let documentation work become a waterfall design pass.

## Phase 1: Tighten The Prototype

Close the obvious gaps from the API-token prototype without expanding feature
scope.

- Refresh `README.md` so it describes the working prototype and points to the
  shortest path through `testkit`.
- Refresh stale package docs where they still describe future behavior as if it
  does not exist.
- Review the public API seams exposed by `testkit` and make only small
  changes that remove real friction.
- Confirm and document the current failure mapping: invalid or missing
  credentials, valid but unlinked identities, denied authorization decisions,
  and internal collaborator failures.
- Keep OIDC, Postgres, provider storage, and builders out of this phase.

Done when the docs match the current implementation, testkit remains the
main acceptance path, and `moon ci --summary minimal` passes.

## Phase 2: Add A Postgres Storage Adapter

Add the first production storage backend for the API-token path already proven
by memory storage.

- Add a `store/postgres` adapter that satisfies the existing principal creation,
  identity linking, principal resolution, and API-token storage contracts.
- Add migrations for principals, external identity links, and API tokens.
- Preserve hash-only token storage, expiration, revocation, and best-effort
  last-used behavior.
- Use database constraints for uniqueness and referential integrity instead of
  relying only on application checks.
- Build shared behavior tests that can run against both memory and Postgres
  where practical.
- Keep Casbin policy storage delegated to Casbin's adapter ecosystem unless
  real use proves tighter integration is necessary.

Done when the existing API-token pipeline can run against Postgres and the
Postgres adapter has deterministic integration coverage.

## Phase 3: Harden Service-Level Management

Tighten the reusable Go management surface for operations that applications
need to expose or run during setup.

- Keep the existing narrow operations: create principal, link identity, issue
  API token, and revoke API token.
- Add a small composition facade only if it reduces real boilerplate after the
  Postgres adapter exists.
- Choose the package boundary during implementation so the facade does not
  create import cycles between the root package and adapter packages.
- Keep request and result types boring and explicit.
- Do not add list/search/update/admin workflows until a real service needs them.
- Do not add a built-in admin HTTP API.

Done when an application can script common management flows without knowing the
details of every adapter, while still being able to use the lower-level
packages directly.

## Phase 4: Add OIDC/JWT Verification And Exchange

Add real bearer-token validation without changing the protected-resource
pipeline.

- Add an `oidc` package for bearer-token verification.
- Define the trusted-provider lookup contract at the smallest useful boundary.
- Validate issuer, audience, signature, expiry, and standard token validity
  using current upstream OIDC/JWT libraries and docs at implementation time.
- Produce `authkit.Identity` values that use a stable issuer-and-subject identity
  key. Do not use email as a stable identity key.
- Expose selected claims for application display, logging, or policy hooks
  without granting permissions directly from arbitrary claims in core.
- Fail closed when provider trust cannot be established or token validation
  cannot complete.
- Prove behavior with local test issuers and JWKS fixtures, not live external
  providers.

Done when a validated OIDC/JWT bearer token verifies to `Identity`, exchange can
resolve or provision a principal, and protected-resource middleware accepts only
authkit access JWTs.

## Phase 5: Add Trusted-Provider Sources

Add provider trust adapters after the OIDC verifier shape is proven.

- Start with static or memory provider sources if the OIDC phase does not
  already include them.
- Add Postgres-backed provider trust only once the minimal provider shape is
  clear from the verifier.
- Keep provider records focused on trust and validation inputs such as issuer,
  audiences, and optional display metadata.
- Keep management of trusted providers as Go-level service operations or
  app-owned code, not a built-in HTTP admin surface.
- Preserve fail-closed behavior for missing or unavailable trusted-provider
  configuration.

Done when applications can choose static, memory, or Postgres provider trust
without changing the verifier or core pipeline.

## Phase 6: Prove Mixed Credentials Vertically

Prove that API tokens and OIDC exchange both use the same application
principal and authorization model.

- Add or extend testkit with both API-token and OIDC exchange.
- Link an API-token identity and an OIDC identity to the same principal.
- Protect one route through the existing `httpauth` and Casbin path.
- Cover allowed, denied, missing credential, invalid token, wrong audience or
  issuer, and unresolved identity cases.
- Use this phase to identify API seams that should be fixed before adding a
  builder.

Done when the mixed-credential example is the acceptance test for the intended
multi-credential architecture.

## Phase 7: Add A Thin Composition API

Add a convenience API only after explicit composition has survived production
storage and OIDC.

- Wrap common setup for principal authenticators, authorizer, pipeline, and HTTP
  middleware.
- Keep lower-level packages and explicit composition fully supported.
- Avoid global mutable state and hidden defaults that make production behavior
  hard to inspect.
- Keep package placement flexible so the builder does not introduce import
  cycles or force the root package to depend on concrete adapters.
- Treat the builder as a convenience layer, not the primary architecture.

Done when a small service can use the common path with less wiring while an
advanced service can still replace every adapter explicitly.

## Phase 8: v0 Readiness Pass

Prepare the library for real service integration without pretending the public
API is final.

- Review exported APIs, package docs, README, and design docs for consistency.
- Add or update examples that show the supported composition paths.
- Document security invariants and extension points that matter to consumers.
- Confirm CI, formatting, linting, and test coverage on all supported packages.
- Record known deferred scope clearly.
- If no real service has integrated the library yet, mark the API as
  experimental and avoid declaring it stable.

Done when the library is ready to integrate into one real service and learn
from that integration.

## Still Deferred

- Hosted browser login
- OAuth authorization server behavior
- SAML, SCIM, MFA, and user-management workflows
- Built-in admin HTTP APIs
- Router/framework-specific adapters
- SQLite storage
- Advanced Casbin examples or policy models
- A custom policy language or relationship graph
- Continuous role synchronization from external identity metadata
- A named action or permission type replacing raw action strings
- v1 API stability before at least one real service integration
