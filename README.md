# authkit

authkit is an early-stage Go library for authentication and authorization in Web API services.
It provides reusable request authentication, principal resolution, and authorization plumbing without becoming an identity provider, hosted login system, or policy framework.

The current prototype proves the API-token path end to end: an opaque API token authenticates to an external identity, the identity resolves to an internal principal, and Casbin authorizes that principal against an application resource.

## Status

authkit is experimental and not API-stable.

Implemented today:

- core `authkit` identity, principal, resource, decision, and port contracts
- an explicit `Identity -> Principal -> Authorizer` pipeline
- opaque API-token issuing, verification, revocation, expiration, and last-used tracking
- memory-backed principal, identity-link, and API-token storage
- `net/http` middleware with context helpers and authorization wrappers
- a thin Casbin authorizer adapter with replaceable request projection
- `examples/notes`, a runnable vertical example that wires the real packages together

Deferred for later phases:

- OIDC/JWT bearer-token validation
- Postgres storage and migrations
- trusted-provider storage
- router-specific adapters
- built-in admin HTTP APIs
- high-level composition builders

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

principal, err := store.CreatePrincipal(ctx, authkit.CreatePrincipalRequest{
	Kind:        authkit.PrincipalKindService,
	DisplayName: "deploy service",
})
if err != nil {
	return err
}

issued, err := tokenService.IssueToken(ctx, apikey.IssueRequest{
	PrincipalID: principal.ID,
	Name:        "deploy token",
	ExpiresAt:   time.Now().Add(24 * time.Hour),
})
if err != nil {
	return err
}

_, err = store.LinkIdentity(ctx, issued.IdentityLink)
if err != nil {
	return err
}

tokenAuthenticator, err := apikey.NewAuthenticator(tokenService)
if err != nil {
	return err
}

authorizer, err := authkitcasbin.NewAuthorizer(enforcer)
if err != nil {
	return err
}

pipeline, err := authkit.NewPipeline(authkit.PipelineOptions{
	Authenticators: []authkit.Authenticator{tokenAuthenticator},
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

`examples/notes` shows the complete runnable version, including the Casbin model, policy, HTTP route, and request tests.

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
