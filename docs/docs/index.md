---
title: authkit Docs
slug: /
description: Documentation for the authkit Go authentication and authorization library.
---

# authkit Docs

authkit is a Go library for authentication and authorization in Web API
services. It provides reusable authentication, principal resolution,
authorization, token exchange, HTTP middleware, and setup helpers without
becoming an identity provider, hosted login system, or policy framework.

## Start Here

- [Learn authkit with the testkit pastebin](tutorials/testkit-pastebin.md) if
  you want the shortest hands-on path through a working service.
- [Compose HTTP authentication](how-to/compose-http-auth.md) if you are wiring a
  typical `net/http` API service.
- [Use explicit composition](how-to/use-explicit-composition.md) if you need to
  construct authenticators, the pipeline, or middleware yourself.
- [Configure local roles](how-to/configure-local-roles.md) if you need
  action-based role authorization.
- [Exchange OIDC tokens and auto-provision principals](how-to/auto-provision-oidc-principals.md)
  if trusted JWT identities should become authkit access JWTs.
- [Supply authorization facts](how-to/supply-authorization-facts.md) if route
  authorization needs request, tenant, or loaded resource context.

## Understand The Design

- [Architecture](explanations/architecture.md) explains the pipeline,
  credential independence, and package boundaries.
- [Security model](explanations/security-model.md) explains the security
  invariants and what authkit deliberately does not do.

## Reference

- [Extension points](reference/extension-points.md) lists the interfaces and
  adapters applications can replace.
- [Core contracts](reference/core-contracts.md) describes root types, request
  shapes, facts, claim paths, and errors.
- [Current scope and API notes](reference/deferred-scope.md) records what is
  intentionally out of scope and what applications own.
