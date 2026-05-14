# authkit

authkit is a Go library for authentication and authorization in Web API services.
It provides reusable request authentication, token exchange, principal resolution, and authorization plumbing without becoming an identity provider, hosted login system, or policy framework.

The shared auth path works end to end: a short-lived authkit access JWT authenticates to an internal principal, and an authorizer checks that principal against an action, application resource, and optional caller-supplied facts.

## Installation

```sh
go get github.com/meigma/authkit
```

## Quick Start

Run the vertical example:

```sh
go run ./testkit/cmd/testkit
```

The testkit pastebin prints a seed API token and starts `http://localhost:8080`.

Open `/login`, paste the seed token, and create a paste. The login form
exchanges the API token for an authkit access JWT carried in the temporary
`authkit_testkit_access` cookie.

The same exchange path is available to tests and applications through Go APIs:

```go
result, err := apiTokenExchanger.Exchange(ctx, exchange.APITokenRequest{
	Plaintext: seedToken,
})
if err != nil {
	return err
}
_ = result.AccessToken.Plaintext
```

The example is also covered by tests:

```sh
go test ./testkit/...
```

## Using Authkit

authkit has two composition layers:

- The root `authkit` package contains the core contracts and `Pipeline`.
- The `compose` package is the standard `net/http` helper for common API
  service wiring.

For most `net/http` services, start with
[Compose HTTP authentication](https://authkit.meigma.dev/how-to/compose-http-auth).
Applications that need full control can use
[explicit composition](https://authkit.meigma.dev/how-to/use-explicit-composition).
Common setup tasks are covered by focused guides for
[local roles](https://authkit.meigma.dev/how-to/configure-local-roles),
[OIDC exchange and auto-provisioning](https://authkit.meigma.dev/how-to/auto-provision-oidc-principals),
and [authorization facts](https://authkit.meigma.dev/how-to/supply-authorization-facts).

The [architecture](https://authkit.meigma.dev/explanations/architecture) and
[security model](https://authkit.meigma.dev/explanations/security-model) explain the request
pipeline, credential independence, failure mapping, and security invariants.

## Documentation

- Docs home: [authkit.meigma.dev](https://authkit.meigma.dev/)
- Tutorial: [Learn authkit with the testkit pastebin](https://authkit.meigma.dev/tutorials/testkit-pastebin)
- How-to: [Compose HTTP authentication](https://authkit.meigma.dev/how-to/compose-http-auth)
- Explanation: [Architecture](https://authkit.meigma.dev/explanations/architecture)
- Reference: [Core contracts](https://authkit.meigma.dev/reference/core-contracts) and
  [extension points](https://authkit.meigma.dev/reference/extension-points)

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
