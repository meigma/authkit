---
title: authkit Docs
slug: /
description: Documentation for the authkit Go authentication and authorization library.
---

# authkit Docs

authkit is a Go library for authentication and authorization in Web API services.
The current prototype proves the shared auth path end to end: opaque API-token
authentication, OIDC-issued JWT bearer authentication from static or stored
provider trust, reusable management setup flows, identity-to-principal
resolution, `net/http` middleware, and Casbin authorization.

Start with the [working design](design.md) for the architecture and package
layout. For the shortest runnable path, use `examples/notes` from the
repository root.
