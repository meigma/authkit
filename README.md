# authkit

authkit is a Go library for authentication and authorization in Web API services.
It provides reusable request authentication, principal resolution, and authorization plumbing without becoming an identity provider, hosted login system, or policy framework.

The shared auth path works end to end: an API token or OIDC-issued JWT bearer token authenticates to an external identity, the identity resolves to an internal principal, and an authorizer checks that principal against an action, application resource, and optional caller-supplied facts.

## Installation

```sh
go get github.com/meigma/authkit
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

## Using Authkit

authkit has two composition layers:

- The root `authkit` package contains the core contracts and `Pipeline`.
- The `compose` package is the standard `net/http` helper for common API
  service wiring.

For most `net/http` services, start with
[Compose HTTP authentication](docs/docs/how-to/compose-http-auth.md).
Applications that need full control can use
[explicit composition](docs/docs/how-to/use-explicit-composition.md).
Common setup tasks are covered by focused guides for
[local roles](docs/docs/how-to/configure-local-roles.md),
[OIDC auto-provisioning](docs/docs/how-to/auto-provision-oidc-principals.md),
and [authorization facts](docs/docs/how-to/supply-authorization-facts.md).

The [architecture](docs/docs/explanations/architecture.md) and
[security model](docs/docs/explanations/security-model.md) explain the request
pipeline, credential independence, failure mapping, and security invariants.

## Documentation

- Docs home: [docs/docs/index.md](docs/docs/index.md)
- Tutorial: [Learn authkit with the notes service](docs/docs/tutorials/notes-service.md)
- How-to: [Compose HTTP authentication](docs/docs/how-to/compose-http-auth.md)
- Explanation: [Architecture](docs/docs/explanations/architecture.md)
- Reference: [Core contracts](docs/docs/reference/core-contracts.md) and
  [extension points](docs/docs/reference/extension-points.md)

## Development

Use the pinned toolchain in `.prototools` and run checks through Moon:

```sh
moon ci --summary minimal
moon run docs:typecheck
moon run docs:build
```

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
