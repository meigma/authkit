# authkit testkit

`testkit` is a small pastebin-style web app used to exercise authkit in realistic application code.

The current slice uses authkit exchange paths for paste creation. Reading pastes
remains public; creating pastes requires exchanging the startup API token or a
trusted OIDC JWT for a short-lived authkit access JWT carried in a temporary app
cookie. Editing and deleting pastes requires the same access JWT and is limited
to the principal that created the paste.

## Run

```bash
go run ./testkit/cmd/testkit
```

The server listens on `:8080` by default. Override it with `TESTKIT_ADDR`:

```bash
TESTKIT_ADDR=:8090 go run ./testkit/cmd/testkit
```

Startup prints a fresh development API token:

```text
testkit seed API token: ak_...
```

Use that token on `/login`. The token is shown only at startup and expires after
24 hours.

The OIDC exchange form is present for validation, but the standalone CLI does
not seed trusted OIDC providers. Tests configure provider trust directly around
the same authflow runtime.

## Persistence

By default, testkit stores pastes in process memory. Restarting the server clears them.

Set `TESTKIT_DATABASE_URL` to use PostgreSQL paste persistence instead:

```bash
TESTKIT_DATABASE_URL='postgres://testkit:testkit@localhost:5432/testkit?sslmode=disable' \
  go run ./testkit/cmd/testkit
```

When `TESTKIT_DATABASE_URL` is set, startup opens a Postgres pool, runs testkit's `testkit_*` paste migrations, runs authkit's Postgres migrations, stores paste data in `testkit_*` tables, and stores authkit principals/API tokens in `authkit_*` tables.

Without `TESTKIT_DATABASE_URL`, both paste data and authkit state are in memory.

## Routes

- `GET /` lists recent pastes.
- `GET /login` renders API-token and OIDC-token exchange forms.
- `POST /auth/token` exchanges an API token and sets the temporary access cookie.
- `POST /auth/oidc-token` exchanges a trusted OIDC JWT and sets the temporary access cookie.
- `POST /logout` clears the temporary access cookie.
- `GET /new` renders the create form for authenticated browsers.
- `POST /pastes` creates a paste for authenticated browsers and redirects to its page.
- `GET /p/{id}` renders a paste.
- `GET /p/{id}/edit` renders the owner-only edit form.
- `POST /p/{id}/edit` updates an owner-owned paste.
- `POST /p/{id}/delete` deletes an owner-owned paste.
- `GET /raw/{id}` returns the paste body as `text/plain`.

## Current Scope

The browser cookie is a temporary testkit transport for authkit access JWTs.
Refresh tokens, hosted OIDC login, richer session management, and API endpoints
are intentionally deferred.
