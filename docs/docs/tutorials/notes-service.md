---
title: Learn Authkit With The Notes Service
description: Learn the authkit request path by running the notes example.
---

# Learn Authkit With The Notes Service

In this tutorial, you will run the notes example and make authenticated requests
through the same path a real API service uses.

The example creates a service principal, issues an opaque API token, links the
token identity to the principal, installs a Casbin policy, and protects a
`GET /notes/{noteID}` route.

## Run The Example

From the repository root, start the example service:

```sh
go run ./examples/notes
```

The process prints a seed API token and listens on `http://localhost:8080`.
Keep the process running in that terminal.

In another terminal, put the printed token in `TOKEN`:

```sh
TOKEN='ak_...'
```

## Call An Allowed Route

Request the note that the seeded policy allows:

```sh
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/notes/allowed
```

The service returns the note body. This proves the request can authenticate,
resolve to the seeded principal, pass authorization, and reach the handler.

## Call A Denied Route

Request a note outside the seeded policy:

```sh
curl -i -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/notes/denied
```

The service returns `403 Forbidden`. The same token authenticated successfully,
but the resolved principal was not authorized for that resource.

## Try A Missing Credential

Call the allowed route without a bearer token:

```sh
curl -i http://localhost:8080/notes/allowed
```

The service returns `401 Unauthorized` because no authenticator accepted the
request.

## What You Learned

You have exercised the core authkit lifecycle:

```text
credential -> Identity -> Principal -> authorization decision -> handler
```

For task-oriented setup guidance, see
[Compose HTTP authentication](../how-to/compose-http-auth.md). For the design
behind this flow, see [Architecture](../explanations/architecture.md).
