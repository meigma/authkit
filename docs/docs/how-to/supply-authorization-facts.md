---
title: How To Supply Authorization Facts
description: Pass decision-time facts from HTTP routes to authkit authorizers.
---

# How To Supply Authorization Facts

Supply authorization facts when a route needs decision-time context beyond the
principal, action, and resource.

## Prerequisites

- An `authkit.Pipeline`
- An `httpauth.Middleware`
- An authorizer that uses facts, such as a Casbin adapter with a custom request
  builder

## Use RequireAuthorization

Use `RequireAuthorization` for routes that need facts:

```go
mux.Handle(
	"GET /tenants/{tenantID}/notes/{noteID}",
	middleware.RequireAuthorization(func(req *http.Request) (authkit.AuthorizationRequest, error) {
		return authkit.AuthorizationRequest{
			Action: "note:read",
			Resource: authkit.Resource{
				Type: "note",
				ID:   req.PathValue("noteID"),
			},
			Facts: authkit.Facts{
				"tenant_id": req.PathValue("tenantID"),
			},
		}, nil
	})(notesHandler),
)
```

The extractor runs after authentication. It can read the resolved subject from
request context when it needs to load application-owned resource state.

## Merge HTTP Facts

Use `httpfacts` helpers for common request values:

```go
facts := authkit.MergeFacts(
	httpfacts.Method(req),
	httpfacts.PathValue(req, "tenantID"),
	httpfacts.Header(req, "X-Request-Source"),
	authkit.Facts{
		"resource.owner_id": note.OwnerID,
	},
)
```

`authkit.MergeFacts` applies later values over earlier values for the same key.

## Read Authentication In The Extractor

Load app-owned facts only after the request is authenticated:

```go
func extractNoteAuthorization(req *http.Request) (authkit.AuthorizationRequest, error) {
	authentication, ok := httpauth.AuthenticationFromContext(req.Context())
	if !ok {
		return authkit.AuthorizationRequest{}, errors.New("missing authentication")
	}

	note, err := loadNoteForPrincipal(req.Context(), authentication.Principal.ID, req.PathValue("noteID"))
	if err != nil {
		return authkit.AuthorizationRequest{}, err
	}

	return authkit.AuthorizationRequest{
		Action:   "note:read",
		Resource: authkit.Resource{Type: "note", ID: note.ID},
		Facts: authkit.Facts{
			"tenant_id":         note.TenantID,
			"resource.owner_id": note.OwnerID,
		},
	}, nil
}
```

Unauthenticated requests do not run this extractor.

## Project Facts Into Casbin

Project facts in a custom Casbin request builder:

```go
authorizer, err := authkitcasbin.NewAuthorizer(
	enforcer,
	authkitcasbin.WithRequestBuilder(func(check authkit.AuthorizationCheck) ([]any, error) {
		tenantID, _ := check.Facts["tenant_id"].(string)

		return []any{
			check.Principal.ID,
			check.Resource.Type + ":" + check.Resource.ID,
			check.Action,
			tenantID,
		}, nil
	}),
)
if err != nil {
	return err
}
```

The Casbin model must define a matching request shape.

## Verification

Send one request with facts that satisfy the authorizer and one request with a
different tenant, header, or loaded resource state. The allowed request should
reach the handler. The denied request should return `403 Forbidden`.

## Related

- [How to compose HTTP authentication](compose-http-auth.md)
- [Architecture](../explanations/architecture.md)
- [Extension points reference](../reference/extension-points.md)
