# authkit

authkit is an early-stage Go library for authentication and authorization in Web API services.
It is intended to provide reusable request authentication, principal resolution, and authorization plumbing without becoming an identity provider or hosted login system.

The repository currently contains the project scaffold, documentation site, and working design for the first API-token prototype.

## Quick Start

### Prerequisites

- Node.js 22.22.2
- npm
- Go 1.26
- Moon 2.x

### Check the repository

```sh
moon ci --summary minimal
```

### Work on the docs

```sh
moon run docs:start
```

The Go module path is `github.com/meigma/authkit`, with root package name `authkit`.

## Documentation

- Docs home: [docs/docs/index.md](docs/docs/index.md)
- Working design: [docs/docs/design.md](docs/docs/design.md)

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
