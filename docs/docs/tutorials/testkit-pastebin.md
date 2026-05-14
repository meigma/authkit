---
title: Learn Authkit With The Testkit Pastebin
description: Learn the authkit exchange and protected-resource path by running testkit.
---

# Learn Authkit With The Testkit Pastebin

In this tutorial, we will run `testkit`, the pastebin app used to validate
authkit in realistic application code.

The app creates a bootstrap principal, issues a seed API token, exposes token
exchange forms, stores a short-lived authkit access JWT in an app cookie, keeps
paste reads public, and protects paste creation with the access JWT path.

This tutorial follows the API-token exchange path. The same testkit authflow
also validates OIDC token exchange for services that trust external JWTs.

## Run Testkit

From the repository root, start the app:

```sh
go run ./testkit/cmd/testkit
```

The process prints a seed API token and listens on `http://localhost:8080`.
Keep the process running in that terminal.

You should see output shaped like this:

```text
testkit seed API token: ak_...
testkit listening on http://localhost:8080
```

## Sign In

Open `http://localhost:8080/login` in a browser, paste the seed API token, and
submit the form.

The form posts to `/auth/token`. The handler exchanges the opaque API token for
an authkit access JWT and sets the temporary `authkit_testkit_access` cookie.

## Create A Paste

After sign-in, create a paste from `http://localhost:8080/new`.

Submitting the form posts to `/pastes`. The route accepts only authkit access
JWTs, so the seed API token itself cannot create pastes as a bearer token or
cookie value.

## Read Public Pastes

Open the paste URL after creation. Paste pages and raw paste reads are public:

```text
GET /p/{id}
GET /raw/{id}
```

This keeps the authentication boundary clear: creation is protected, reads are
not.

## What You Learned

You have exercised the core authkit lifecycle:

```text
exchange credential -> authkit access JWT -> Principal -> authorization decision -> handler
```

For task-oriented setup guidance, see
[Compose HTTP authentication](../how-to/compose-http-auth.md). For external JWT
exchange, see
[Exchange OIDC tokens and auto-provision principals](../how-to/auto-provision-oidc-principals.md).
For the design behind these flows, see
[Architecture](../explanations/architecture.md).
