# Temporary Architecture Refactor Notes

This is a temporary working document. It is not intended to become permanent
reference documentation in this form. Its job is to capture the proposed
architecture direction before the next implementation slices refine the details.

## Proposal

authkit should move toward a model where external authentication methods are
explicit ingress paths into authkit-owned principal credentials.

The motivation is expansion. authkit started with API-style bearer
authentication, but the library is moving toward broader API and web-service
use. Passkeys, browser OIDC login, OIDC bearer exchange, manually issued API
tokens, and future credential methods do not share the same proof ceremony.
They can, however, share the same destination: a verified identity becomes an
authkit principal relationship and an authkit-owned credential used for normal
API access.

Today, the core request path is:

```text
Authenticator -> Identity -> PrincipalResolver -> Principal -> Authorizer
```

That shape remains valuable. The change is where external protocols participate.
Instead of every protected API request carrying an external credential, authkit
should treat external credentials as proof material for an explicit exchange or
onboarding flow. Successful exchange produces an authkit-owned credential that
is already coupled to an internal principal.

The future shape is:

```text
external proof -> authkit.Identity -> onboarding/exchange -> authkit credential -> Principal
```

Normal API requests then use the authkit credential:

```text
authkit credential -> PrincipalResolver -> Principal -> Authorizer
```

## Why This Matters

This keeps runtime authentication side-effect-free. An ordinary protected route
should not create principals, attach new external identities, or evaluate
onboarding policy while handling business traffic.

It also gives different credential methods the same destination. API tokens,
OIDC login, OIDC bearer exchange, passkeys, and future mechanisms can all prove
different things in different ways, but they should converge on an authkit-owned
credential linked to a principal.

The purpose is not to force every credential method into one generic proof API.
OIDC bearer validation, passkey assertion verification, and other future
mechanisms have different inputs and different security ceremonies. The shared
boundary starts after proof succeeds and an `authkit.Identity` exists.

## Existing Concepts To Preserve

The proposal builds on existing authkit language instead of replacing it:

- `authkit.Identity` remains the result of verified external proof.
- `authkit.ExternalIdentity` remains the durable relationship between a
  provider-scoped identity and a principal.
- `authkit.Principal` remains the internal actor authorization uses.
- `authkit.PrincipalResolver` remains the runtime bridge from credential
  identity to principal.
- `authkit.IdentityLinker` remains the low-level operation for attaching an
  external identity to an existing principal.
- `authkit.IdentityProvisioner` remains the atomic create-and-link operation.
- `onboarding.Service` is the explicit helper for principal attachment and
  provisioning flows, not a runtime authenticator.

The new architectural center is not "OIDC" or "passkeys"; it is explicit
conversion from verified auth material into an authkit-owned credential and
principal relationship.

## Identity Exchange

The exchange boundary should be generalized around `authkit.Identity`, not
around HTTP or any one provider protocol. A future exchange service can accept a
verified identity, resolve or provision the corresponding principal, and issue
an authkit-owned credential.

Conceptually:

```text
authkit.Identity -> resolve/provision Principal -> issue authkit credential
```

Provider packages still own proof:

```text
OIDC bearer token -> oidc.Authenticator -> authkit.Identity
passkey assertion -> passkey service -> authkit.Identity
future method     -> method package -> authkit.Identity
```

The consumer still owns the HTTP endpoint shape, response body, rate limiting,
auditing, and any UI/session behavior. authkit provides the service-level tools
so those endpoints converge on the same principal and credential semantics.

This avoids each provider package inventing its own exchange behavior. Without
a shared exchange layer, OIDC, passkeys, and future mechanisms could drift into
different provisioning rules, token issuance semantics, error expectations, and
principal-link handling.

## OIDC Auto-Provisioning Reframed

Current OIDC auto-provisioning happens when an API request arrives with a valid
external bearer token whose identity is not yet linked. The resolver may create
and link a principal after provisioning rules approve it.

The proposed direction moves that behavior out of ordinary request
authentication. A service could expose a token exchange endpoint instead:

```text
external OIDC bearer -> verify as authkit.Identity -> optional provisioning -> authkit bearer
```

After exchange, later API requests use the authkit bearer. Provisioning remains
optional, policy-driven, and explicit, but it no longer happens as a side effect
of normal API access.

In code terms, the consumer-facing endpoint would verify external proof with
the OIDC package, then pass the resulting `authkit.Identity` into the shared
exchange service. The endpoint remains application-owned, but the exchange
semantics are authkit-owned.

## Passkeys Fit The Same Shape

Passkeys are not naturally bearer authenticators. They are an interactive proof
ceremony. In the proposed model, a passkey assertion is another exchange path:

```text
passkey proof -> authkit.Identity -> onboarding/exchange -> authkit bearer or session credential
```

The browser UI, route shape, CSRF handling, cookies, and recovery flows stay
application-owned. authkit provides the backend tools to verify proof, bind the
result to a principal, and issue an authkit-owned credential.

## Authkit-Owned Credentials

This proposal implies authkit needs a first-party credential story distinct from
external credentials. The existing `apikey` package is close in spirit, but it
is currently shaped around manually issued opaque API tokens. Exchange-issued
credentials may need different lifetime, metadata, revocation, and transport
decisions.

Those details should be worked out during implementation. The key architectural
point is that protected API requests should eventually depend on authkit-owned
credentials rather than directly depending on every possible external protocol.

## Deferred Details

This document intentionally does not settle every implementation detail. Future
slices still need to decide:

- whether the authkit-owned credential is one token type or multiple related
  credential/session types
- how short-lived bearer tokens, long-lived API tokens, and browser sessions
  relate to each other
- how exchange endpoints should be packaged without becoming a built-in hosted
  login product
- how existing OIDC bearer auto-provisioning should migrate, if at all
- how refresh, revocation, expiry, audit metadata, and token introspection should
  work

Those are implementation questions. The architectural direction is that many
external proof mechanisms can enter authkit, but normal authorization should
center on authkit-owned credentials linked to principals.
