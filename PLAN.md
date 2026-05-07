# Implementation Plan

Status: proposed

This plan is intentionally high-level. The goal is to guide the first implementation without pretending the API is already known perfectly. Each phase should produce a small, reviewable result and let the next phase adjust based on what the code teaches us.

## Prototype Target

The first full prototype should prove the core auth shape with API tokens only:

- core model and contracts
- explicit identity-to-principal resolution
- in-memory stores
- opaque API-token issuing and verification
- `net/http` middleware and request-context helpers
- authorization wrapper with injectable resource extraction
- Casbin authorizer adapter
- one small runnable example route
- focused tests around the real request path

Postgres, OIDC/JWT validation, migrations, router adapters, admin HTTP APIs, and advanced Casbin examples should stay out of the first prototype unless the implementation uncovers a blocking reason to pull one forward.

## Phase 1: Establish The Go Skeleton

Create the smallest Go module scaffold that can compile, test, and host the package boundaries from the design. Keep repository wiring practical: module metadata, package directories, basic test/lint commands, and enough CI/task configuration to run the prototype.

This phase should avoid polishing public docs or finalizing every package name. The only important outcome is a working workspace where small packages can evolve quickly.

## Phase 2: Define The Core Contract

Implement the root package with the boring center of the system:

- identity, principal, resource, and decision types
- authenticator, principal resolver, and authorizer ports
- pipeline-level errors or result categories for unauthenticated, unresolved, unauthorized, and internal failure cases
- small service contracts for creating principals and linking identities

Keep these contracts narrow. If a storage or service method is not needed by the API-token prototype path, leave it out until a later phase proves the shape.

## Phase 3: Build Memory-Backed Principal Resolution

Add memory stores and services for principals and external identity links. This is the first useful bottom-up behavior: create a principal, link an external identity, and resolve that identity back to the principal.

The memory adapter should bias toward deterministic tests and examples over production features. Concurrency safety is useful, but durability, migrations, and query generality are not part of this phase.

## Phase 4: Prove Opaque API Tokens

Build the API-token package around storage-backed opaque tokens:

- secure token issuance
- token lookup by stable ID or prefix
- hash-only storage
- expiration and revocation checks
- best-effort last-used update hook
- authenticator that converts a valid token into an external identity

The important design check is that API tokens still go through the same `Identity -> Principal` path that OIDC will eventually use. Do not let token verification jump directly to a principal just because it is easier in the first pass.

## Phase 5: Assemble The Auth Pipeline

Compose authenticators, the principal resolver, and the authorizer into a reusable request pipeline. This is where failure semantics should become concrete enough for HTTP to consume without overfitting the core package to HTTP status codes.

Use the implementation to decide whether the pipeline belongs mostly in the root package or the HTTP adapter. The invariant is more important than the exact file layout: credentials authenticate to identities, identities resolve to principals, and principals are authorized for actions on resources.

## Phase 6: Add The `net/http` Adapter

Implement the HTTP adapter after the core pipeline works in tests:

- middleware that runs authentication and principal resolution
- context helpers for identity and principal access
- `Require` and `RequireFunc` authorization wrappers
- injectable resource extraction
- default error rendering that distinguishes unauthenticated, unauthorized, and internal failures
- option hooks for applications to customize rendering later

Keep this router-neutral. The standard library path-value flow can be supported in examples, but framework-specific assumptions should not leak into the core adapter.

## Phase 7: Add The Casbin Adapter

Implement the smallest Casbin adapter that satisfies the authorizer port. Default to principal ID as the Casbin subject and keep action/resource projection replaceable.

Ship only a starter model or example policy if it helps prove the prototype. Avoid creating a second policy abstraction above Casbin.

## Phase 8: Write The Vertical Example

Create one small example service that uses the real packages together:

- create or seed a principal
- issue an API token
- link the token identity to the principal
- protect one route with `RequireFunc`
- authorize through Casbin
- show the allowed and denied paths in tests or a simple runnable example

This phase should expose awkward API seams. Fix the seams discovered here before broadening scope. The example is the prototype's main acceptance test.

## Phase 9: Tighten The Prototype

Finish with a focused quality pass:

- unit tests for token generation, hash-only storage, expiration, revocation, identity resolution, and Casbin projection
- HTTP tests for context population, allow/deny behavior, unresolved identity behavior, and error mapping
- package-level doc comments only where they help users understand composition
- README refresh with the shortest working path through the example
- design notes updated only for discoveries that materially changed the architecture

Do not turn this phase into a documentation or framework-building project. The output should be a working prototype that is ready to integrate into one real service and learn from.

## Decisions To Leave Open Until Implementation

- Exact module path and root package name.
- Exact API-token string format.
- Whether unresolved valid credentials map to a default `401`, `403`, or configurable HTTP response.
- Whether the high-level builder is useful in v0 or should wait until explicit composition feels stable.
- How much starter Casbin policy material belongs in the library versus examples.
- Whether token last-used updates should be synchronous, asynchronous, or purely adapter-defined.

## Implementation Rhythm

Work phase by phase, but do not treat the plan as a contract. After each phase, run the narrow test set that proves that phase and adjust the next phase if the API shape feels wrong. Prefer deleting or reshaping early code over preserving a bad abstraction.
