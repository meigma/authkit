# Contributing

Thank you for your interest in contributing to authkit.
This guide covers questions, bug reports, feature requests, and pull requests.
For private vulnerability reporting, use [SECURITY.md](SECURITY.md) instead of public channels.

## Asking Questions

Use [GitHub Discussions](https://github.com/meigma/authkit/discussions) for usage questions, troubleshooting, and general discussion.

## Reporting Bugs

Report non-security bugs through [GitHub Issues](https://github.com/meigma/authkit/issues).
Include the following details when possible:

- version, commit, or environment details
- steps to reproduce
- expected behavior
- actual behavior
- logs, screenshots, or a minimal reproduction

If you are reporting a security issue, stop and follow [SECURITY.md](SECURITY.md) instead.

## Proposing Features

Use [GitHub Discussions](https://github.com/meigma/authkit/discussions) for feature requests and design proposals.
For larger changes, describe the problem and a small proposed next step before starting implementation.

## Pull Requests

Contributors should:

1. Keep changes focused and scoped to a single problem.
2. Add or update tests when behavior changes.
3. Update documentation when user-facing behavior changes.
4. Describe the change clearly in the pull request.
5. Make sure CI passes before requesting review.

## Local Setup

Install the docs dependencies and run the repository checks:

```sh
npm --prefix docs install
moon ci --summary minimal
```

Useful project commands:

```sh
moon run docs:build
moon run docs:start
moon run docs:typecheck
```

Keep Go tests, linting, and docs checks passing together as the runtime packages grow.

## License

Unless stated otherwise, contributions are accepted under the repository's dual license:
Apache License 2.0 or MIT, at your option.
