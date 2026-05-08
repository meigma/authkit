# Auth Library Design

Status: first-pass design

This document describes a small Go library for authentication and authorization in Web API services. It is intentionally a working design, not a final architecture reference. The first implementation should prove the shape with API tokens before expanding to OIDC and production storage adapters.

## Problem Statement

Several Go API services need the same auth foundation:

- authenticate requests from API tokens or bearer tokens
- map external credentials to application principals
- ask whether a principal may perform an action on a resource
- avoid rewriting the same integration code in every service

The library should reduce boilerplate around modern API auth without becoming an identity provider, hosted login system, enterprise authorization platform, or generic auth framework for every possible application shape.

## Goals

- Support Go Web API services first.
- Keep `net/http` support first-class.
- Separate authentication, principal resolution, and authorization.
- Support local opaque API tokens as the first credential type.
- Add OIDC/JWT bearer-token validation without redesigning the core.
- Treat internal principals as independent from credentials.
- Make Casbin integration natural by feeding it stable principal subjects.
- Use hexagonal architecture: core contracts in the center, adapters at the edge.
- Keep storage, HTTP rendering, provider configuration, and authorization policy replaceable.
- Provide a thin high-level setup API while preserving explicit lower-level composition.

## Non-Goals

- Do not build an identity provider.
- Do not build hosted browser login.
- Do not build SAML, SCIM, MFA, or user-management workflows.
- Do not build an OAuth authorization server.
- Do not build enterprise audit/reporting workflows.
- Do not design a complex multi-tenant SaaS auth system.
- Do not create a policy language or relationship model that recreates Casbin.
- Do not make JWTs the default for local API tokens.
- Do not ship a default admin HTTP API in v0.
- Do not target full web applications, mobile applications, or desktop applications.

## Core Model

The library is organized around this pipeline:

```text
Authenticator -> Identity -> PrincipalResolver -> Principal -> Authorizer
```

An authenticator verifies a request credential and returns an external identity. A principal resolver maps that external identity to an internal application principal. An authorizer decides whether the resolved principal can perform an action on a resource.

The important invariant is credential independence. An API token and an OIDC bearer token can both resolve to the same internal principal, and permissions attach to that principal instead of to the credential.

## Architecture

The library should follow a ports-and-adapters structure.

```text
core domain:
  principals
  external identities
  auth pipeline
  service-level management operations
  ports for storage, provider lookup, and authorization

inbound adapters:
  net/http middleware
  optional router/framework adapters later

outbound adapters:
  API-token storage
  OIDC/JWT verification
  trusted-provider sources
  Casbin authorization
  memory and Postgres storage
```

Core code should not know whether data comes from static configuration, Postgres, memory, application code, or another backend. Those are adapters to core ports.

## Package Layout

The exact package tree can evolve during implementation, but the hierarchy should make the hexagonal design obvious.

```text
github.com/meigma/authkit/
  *.go
    core types, pipeline, services, low-level ports
  httpauth/
    net/http middleware and request helpers
  apikey/
    opaque API-token service and authenticator
  oidc/
    OIDC/JWT authenticator and provider contracts
  casbin/
    Casbin authorizer adapter
  store/memory/
    memory adapter for tests and examples
  store/postgres/
    Postgres adapter for real services
```

The root package should stay small and use package name `authkit`. It may expose a convenience builder, but concrete adapters should live in explicit packages.

## Core Types

The first pass of the public contracts should stay small and boring.

```go
type Identity struct {
    Provider     string
    Subject      string
    CredentialID string
    Claims       map[string]any
}

type Principal struct {
    ID          string
    Kind        PrincipalKind
    DisplayName string
    Attributes  map[string]any
}

type PrincipalKind string

const (
    PrincipalKindUser    PrincipalKind = "user"
    PrincipalKindService PrincipalKind = "service"
)

type Resource struct {
    Type string
    ID   string
    Attr map[string]any
}

type Decision struct {
    Allowed bool
    Reason  string
}
```

Teams and organizations are intentionally not v0 principal kinds. Applications can model team/org membership and inherited permissions through their domain model or authorization policy.

## Core Ports

```go
type Authenticator interface {
    Name() string
    Authenticate(ctx context.Context, r *http.Request) (*Identity, error)
}

type PrincipalResolver interface {
    ResolveIdentity(ctx context.Context, identity Identity) (*Principal, error)
}

type Authorizer interface {
    Can(ctx context.Context, principal Principal, action string, resource Resource) (Decision, error)
}
```

Storage ports should be narrow at first and allowed to evolve with usage. Likely v0 ports include:

- principal storage
- external identity link storage
- API-token storage
- trusted OIDC provider lookup
- API-token last-used updates

The first implementation should avoid broad repository interfaces that try to predict every future query.

## Identity Linking

Identity linking is explicit in v0.

Expected administrator flow:

1. Create an internal principal, either `user` or `service`.
2. Configure a trusted provider.
3. Link the internal principal to an external identity.
4. Grant roles or permissions to the internal principal through the authorization layer.

For OIDC, the external identity key is `(issuer, subject)`, not `subject` alone. In a normal user flow, `sub` identifies the user at that issuer, but some providers and token flows may use `sub` for service accounts, clients, workloads, or automation actors. The resolver maps the external identity to the correct principal kind.

Auto-provisioning is out of scope for v0. A valid but unlinked external identity should authenticate as a valid credential but fail principal resolution.

## API Tokens

Local API tokens are opaque, revocable, storage-backed credentials. They are issued for existing principals and do not create principals.

The library owns:

- secure token generation
- token format convention with lookup prefix or ID
- hashing before storage
- verification without storing plaintext secrets
- expiration checks
- revocation checks
- last-used tracking hook
- token-to-principal identity production
- HTTP credential extraction

Applications own:

- admin endpoints or CLI commands
- token naming and approval workflow
- audit/event handling
- concrete persistence choice
- how operators see the token once at creation time

The API-token authenticator should still produce an `Identity`, not a `Principal`, so the API-token path exercises the same pipeline OIDC will use later.

## OIDC And JWT Bearer Tokens

OIDC/JWT support is not part of the first prototype, but the architecture must support it without redesign.

The OIDC authenticator should:

- find trusted provider configuration through a port
- validate issuer, audience, signature, and expiry
- use `(issuer, subject)` as the stable external identity key
- avoid email as the primary identity key
- expose selected claims for display, logging, and app policy hooks

Provider configuration is adapter-backed. Static config, memory, Postgres, or app-owned configuration should all be able to satisfy the same provider source contract.

```go
type OIDCProvider struct {
    Name      string
    IssuerURL string
    Audiences []string
}

type OIDCProviderSource interface {
    FindOIDCProviders(ctx context.Context, issuer string) ([]OIDCProvider, error)
}
```

The exact interface can change during prototyping, but provider lookup must remain a port rather than hardcoded storage.

## Authorization And Casbin

The library should build with Casbin, not build a hidden authorization system on top of Casbin.

The recurring problem is not replacing Casbin. The recurring problem is getting real API credentials and external identities to resolve into stable application principals that Casbin can use as subjects.

The Casbin adapter should:

- implement the small `Authorizer` port
- use principal IDs as the default Casbin subject
- allow applications to supply their own Casbin model and policy
- optionally provide a simple starter model for examples
- avoid introducing a separate policy DSL, relationship graph, or role system

Application services own the meaning of actions and resources:

- `note:read`
- `note:update`
- `project:deploy`
- `team:share`

The library may provide helpers for projecting a `Resource` into Casbin arguments, but the projection must be replaceable.

## Storage Adapters

v0 should define core storage ports and implement:

1. memory adapter for tests, examples, and prototypes
2. Postgres adapter as the first real backend

SQLite can come later if a concrete service or deployment target needs it.

The Postgres schema should cover at least:

- principals
- external identity links
- API tokens
- trusted providers, if the application wants provider trust in storage

Casbin policy storage should be delegated to Casbin's own adapter story unless a prototype proves that tighter integration is necessary.

## Service-Level Management

The library should expose reusable Go services for management operations, not a built-in admin HTTP API.

Likely service methods:

```go
CreatePrincipal(ctx, req CreatePrincipalRequest) (Principal, error)
LinkIdentity(ctx, req LinkIdentityRequest) (ExternalIdentity, error)
IssueAPIToken(ctx, req IssueAPITokenRequest) (IssuedAPIToken, error)
RevokeAPIToken(ctx, tokenID string) error
```

Applications decide whether to expose these through REST routes, CLI commands, seed scripts, migrations, or internal setup code.

## HTTP Middleware

`net/http` is the first-class inbound adapter.

HTTP support should:

- authenticate requests using configured authenticators
- resolve and attach the principal to request context
- expose helpers to read principal and identity data from context
- provide authorization wrappers
- distinguish unauthenticated from unauthorized responses
- allow custom error rendering
- avoid router-specific assumptions

Likely shape:

```go
type ResourceExtractor func(*http.Request) (Resource, error)

func Require(action string, resource Resource) Middleware
func RequireFunc(action string, extract ResourceExtractor) Middleware
```

The standard library `http.Request.PathValue` can support the happy path, but framework-specific resource extraction must be injectable.

## Request Lifecycle

For an authorized request:

1. HTTP middleware receives the request.
2. Authenticator chain tries configured authenticators.
3. The successful authenticator returns an external `Identity`.
4. Principal resolver maps the identity to a `Principal`.
5. Middleware stores identity and principal in request context.
6. Authorization wrapper extracts the target `Resource`.
7. Authorizer checks `principal`, `action`, and `resource`.
8. Handler runs only when the decision allows it.

Failure modes should remain distinct:

- no credential or invalid credential: unauthenticated
- valid credential with no linked principal: unauthenticated or unresolved identity, exact HTTP mapping TBD
- resolved principal without permission: unauthorized
- storage/provider failure: internal error

## API Shape

The library should support explicit composition and a thin composition helper.

Explicit composition is the architectural foundation:

```go
tokenSvc, err := apikey.NewService(tokenStore)
apiTokenAuth, err := apikey.NewAuthenticator(tokenSvc)
authorizer, err := casbin.NewAuthorizer(enforcer)

pipeline, err := authkit.NewPipeline(authkit.PipelineOptions{
    Authenticators: []authkit.Authenticator{apiTokenAuth},
    Resolver:       principalResolver,
    Authorizer:     authorizer,
})

mw, err := httpauth.NewMiddleware(pipeline)
```

A convenience helper can compose common HTTP wiring for simple services:

```go
kit, err := compose.NewHTTP(compose.HTTPOptions{
    Authenticators: []compose.AuthenticatorSpec{
        compose.APIToken(tokenSvc),
        compose.OIDC(providerSource),
    },
    Resolver:   principalResolver,
    Authorizer: authorizer,
})

mw := kit.Middleware
```

The composition helper should stay thin and replaceable.

## Example Usage

```go
principal, err := principals.CreatePrincipal(ctx, authkit.CreatePrincipalRequest{
    Kind:        authkit.PrincipalKindUser,
    DisplayName: "Ada",
})
if err != nil {
    return err
}

issued, err := tokens.IssueAPIToken(ctx, apikey.IssueRequest{
    PrincipalID: principal.ID,
    Name:        "deploy script",
    ExpiresAt:   time.Now().Add(90 * 24 * time.Hour),
})
if err != nil {
    return err
}

_ = issued.PlaintextToken // show once to the operator

mux.Handle(
    "POST /notes/{noteID}",
    httpauth.RequireFunc("note:update", func(r *http.Request) (authkit.Resource, error) {
        return authkit.Resource{
            Type: "note",
            ID:   r.PathValue("noteID"),
        }, nil
    })(updateNoteHandler),
)
```

## Security Considerations

- Store only API-token hashes, never plaintext tokens.
- Generate local API tokens with high entropy.
- Include a lookup ID or prefix so token verification does not require scanning all hashes.
- Make token revocation and expiration first-class.
- Treat token last-used tracking as best-effort and avoid turning it into request latency bottleneck if possible.
- Use `(issuer, subject)` for OIDC identity keys.
- Validate issuer, audience, signature, and expiry for JWT bearer tokens.
- Do not use email as a stable identity key.
- Do not grant permissions directly from arbitrary JWT claims in core.
- Keep auto-provisioning out of v0.
- Avoid global mutable state.
- Keep observability opt-in and avoid logging secrets.

## Testing Strategy

The first prototype should have focused tests for:

- API-token generation and verification
- hash-only token storage behavior
- expiration and revocation checks
- identity-to-principal resolution
- unresolved identity behavior
- middleware context population
- authorization wrapper allow/deny behavior
- Casbin adapter subject projection

Memory adapters should make these tests fast and deterministic. Postgres adapter tests can come after the core path is proven.

## v0 Prototype

The first implementation should prove the architecture with API tokens only:

- core principal model
- authenticator interface
- API-token service and authenticator
- explicit identity linking
- memory stores
- Casbin authorizer adapter
- `net/http` middleware
- `RequireFunc(...)`
- one small example route

The prototype should defer:

- real OIDC/JWT validation
- Postgres adapter
- migrations
- router adapters
- admin HTTP endpoints
- SQLite
- advanced Casbin models

This keeps the first slice small while protecting the later OIDC path.

## Roadmap

### v0.1

- module scaffold
- core types and ports
- memory stores
- opaque API-token service
- API-token authenticator
- explicit principal resolution
- Casbin authorizer adapter
- `net/http` middleware
- minimal example

### v0.2

- Postgres adapter
- migration story
- service-level management APIs hardened by real use
- stronger examples for API services

### v0.3

- OIDC/JWT bearer-token authenticator
- trusted-provider source port and adapters
- claim extraction
- explicit OIDC identity linking

### v1

- stabilize public contracts after at least one real service integration
- document extension points
- document migration from API-token-only to API-token-plus-OIDC
- avoid expanding scope unless real service usage proves the need

## Open Questions

- Exact API-token string format.
- Whether unresolved linked-identity failures should return 401, 403, or a configurable result.
- How much starter Casbin policy/model material should ship with examples.
- Whether provider trust belongs in the Postgres adapter's initial schema or remains app-provided until OIDC lands.
- How token last-used updates should be batched or made best-effort.
