# authkit

authkit is an early-stage Go library for authentication and authorization in Web API services.
It provides reusable request authentication, principal resolution, and authorization plumbing without becoming an identity provider, hosted login system, or policy framework.

The current prototype proves the shared auth path end to end: an API token or OIDC-issued JWT bearer token authenticates to an external identity, the identity resolves to an internal principal, and Casbin authorizes that principal against an application resource.

## Status

authkit is experimental and not API-stable.

Implemented today:

- core `authkit` identity, principal, resource, decision, and port contracts
- an explicit `Identity -> Principal -> Authorizer` pipeline
- opaque API-token issuing, verification, revocation, expiration, and last-used tracking
- memory-backed principal, identity-link, API-token, and OIDC provider-trust storage
- Postgres-backed principal, identity-link, API-token, and OIDC provider-trust storage
- Go-level management service for principal, identity-link, and API-token setup flows
- OIDC-issued JWT bearer-token authentication from static, memory, Postgres, or app-owned trusted-provider sources
- `net/http` middleware with context helpers and authorization wrappers
- a thin Casbin authorizer adapter with replaceable request projection
- `examples/notes`, a runnable vertical example that wires the real packages together

Deferred for later phases:

- router-specific adapters
- built-in admin HTTP APIs
- broader high-level composition builders

## Installation

```sh
go get github.com/meigma/authkit
```

For repository development, use the pinned toolchain in `.prototools` and run checks through Moon:

```sh
moon ci --summary minimal
```

## Quick Start

Run the vertical example:

```sh
go run ./examples/notes
```

The example prints a seed API token and starts `http://localhost:8080`.

Use the printed token to call the allowed route:

```sh
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/notes/allowed
```

The same token is authenticated but denied by policy for another note:

```sh
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/notes/denied
```

The example is also covered by tests:

```sh
go test ./examples/notes
```

## Composition Shape

The public API is intentionally explicit. Applications wire the adapters they want:

```go
store := memory.NewStore()
tokenService, err := apikey.NewService(store)
if err != nil {
	return err
}

managementService, err := management.NewService(management.Options{
	PrincipalCreator: store,
	IdentityLinker:   store,
	APITokens:        tokenService,
})
if err != nil {
	return err
}

principal, err := managementService.CreatePrincipal(ctx, authkit.CreatePrincipalRequest{
	Kind:        authkit.PrincipalKindService,
	DisplayName: "deploy service",
})
if err != nil {
	return err
}

issued, err := managementService.IssueAPIToken(ctx, management.IssueAPITokenRequest{
	PrincipalID: principal.ID,
	Name:        "deploy token",
	ExpiresAt:   time.Now().Add(24 * time.Hour),
})
if err != nil {
	return err
}

tokenAuthenticator, err := apikey.NewAuthenticator(tokenService)
if err != nil {
	return err
}

oidcSource, err := oidc.NewStaticProviderSource(oidc.Provider{
	Issuer:    "https://issuer.example",
	Audiences: []string{"notes-api"},
	JWKSURL:   "https://issuer.example/.well-known/jwks.json",
})
if err != nil {
	return err
}

// Memory and Postgres stores can also be used directly as mutable OIDC provider
// trust sources by calling TrustProvider and passing the store to NewAuthenticator.
oidcAuthenticator, err := oidc.NewAuthenticator(oidcSource, oidc.WithForwardedClaims("email", "name"))
if err != nil {
	return err
}

authorizer, err := authkitcasbin.NewAuthorizer(enforcer)
if err != nil {
	return err
}

pipeline, err := authkit.NewPipeline(authkit.PipelineOptions{
	Authenticators: []authkit.Authenticator{tokenAuthenticator, oidcAuthenticator},
	Resolver:       store,
	Authorizer:     authorizer,
})
if err != nil {
	return err
}

middleware, err := httpauth.NewMiddleware(pipeline)
if err != nil {
	return err
}
```

The management service is a Go-level convenience for setup code; the lower-level
`authkit`, `apikey`, `oidc`, and store packages remain directly usable.
`examples/notes` shows the complete runnable API-token version, including the
Casbin model, policy, HTTP route, and request tests.

## Failure Mapping

The core pipeline keeps failure categories distinct:

- Missing, malformed, unknown, expired, revoked, or otherwise invalid credentials return `authkit.ErrUnauthenticated`.
- A valid credential with no linked principal returns `authkit.ErrUnresolvedIdentity`.
- A resolved principal denied by policy returns `authkit.ErrUnauthorized`.
- Unexpected authenticator, resolver, authorizer, or resource-extractor failures return `authkit.ErrInternal`.
- Context cancellation and deadline errors pass through unchanged.

`httpauth` maps those categories by default:

- `ErrUnauthenticated` and `ErrUnresolvedIdentity` -> HTTP 401
- `ErrUnauthorized` -> HTTP 403
- `ErrInternal` and unexpected failures -> HTTP 500

Applications can replace the renderer with `httpauth.WithErrorRenderer`.

## Documentation

- Working design: [DESIGN.md](DESIGN.md)
- Implementation plan: [PLAN.md](PLAN.md)
- Docs home: [docs/docs/index.md](docs/docs/index.md)
- Docusaurus design page: [docs/docs/design.md](docs/docs/design.md)

## Support

Use [GitHub Discussions](https://github.com/meigma/authkit/discussions) for questions and general support.
Use [GitHub Issues](https://github.com/meigma/authkit/issues) for non-security bug reports.
Do not report vulnerabilities in public channels. See [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines, local setup expectations, and pull request workflow.

## Security

See [SECURITY.md](SECURITY.md) for supported versions and the private vulnerability reporting path.

## License

authkit is dual-licensed under the [Apache License 2.0](LICENSE-APACHE) and the [MIT License](LICENSE-MIT).
You may choose either license for your use.
