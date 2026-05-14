---
title: How To Configure Local Roles
description: Create local roles, grant actions, assign principals, and authorize with roleauth.
---

# How To Configure Local Roles

Configure admin-managed local roles when your service wants action-based
authorization without a separate policy engine.

## Prerequisites

- A store that implements the role ports, such as `store/memory.Store` or
  `store/postgres.Store`
- An existing principal ID
- The action strings your handlers enforce, such as `note:read`

## Create A Role

Create a role through your setup path:

```go
role, err := store.CreateRole(ctx, authkit.CreateRoleRequest{
	ID:          "notes-reader",
	DisplayName: "Notes reader",
	Description: "Can read notes.",
})
if err != nil {
	return err
}
```

Role IDs are application-owned stable IDs.

## Grant Actions To The Role

Grant every action the role should allow:

```go
err = store.GrantRoleAction(ctx, authkit.GrantRoleActionRequest{
	RoleID: role.ID,
	Action: "note:read",
})
if err != nil {
	return err
}
```

Action strings are the permission vocabulary authkit passes to authorizers.

## Assign The Role To A Principal

Assign the role to an existing principal:

```go
err = store.AssignPrincipalRole(ctx, authkit.AssignPrincipalRoleRequest{
	PrincipalID: principal.ID,
	RoleID:      role.ID,
})
if err != nil {
	return err
}
```

The provided stores make repeated grants and assignments idempotent.

## Build The Role Authorizer

Adapt the store with `roleauth`:

```go
authorizer, err := roleauth.NewAuthorizer(store)
if err != nil {
	return err
}
```

Pass the authorizer to the pipeline or composition helper:

```go
kit, err := compose.NewHTTP(compose.HTTPOptions{
	PrincipalAuthenticators: []compose.PrincipalAuthenticatorSpec{
		compose.AccessJWT(accessVerifier, store),
	},
	Authorizer: authorizer,
})
if err != nil {
	return err
}
```

## Protect A Route

Protect routes with the same action strings granted to roles:

```go
mux.Handle(
	"GET /notes/{noteID}",
	kit.Middleware.RequireFunc("note:read", func(req *http.Request) (authkit.Resource, error) {
		return authkit.Resource{
			Type: "note",
			ID:   req.PathValue("noteID"),
		}, nil
	})(notesHandler),
)
```

## Verification

Check the effective actions for the principal:

```go
actions, err := store.ResolvePrincipalActions(ctx, principal.ID)
if err != nil {
	return err
}
```

The returned actions should include `note:read`. A request from that principal
to the protected route should pass authorization; a request for an ungranted
action should return `403 Forbidden`.

## Related

- [How to compose HTTP authentication](compose-http-auth.md)
- [How to auto-provision OIDC principals](auto-provision-oidc-principals.md)
- [Security model](../explanations/security-model.md)
