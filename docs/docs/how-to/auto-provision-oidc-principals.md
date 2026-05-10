---
title: How To Auto-Provision OIDC Principals
description: Configure OIDC auto-provisioning and initial role assignment from forwarded claims.
---

# How To Auto-Provision OIDC Principals

Configure OIDC auto-provisioning when a trusted JWT bearer token should create a
local principal on first use.

## Prerequisites

- A trusted OIDC issuer and JWKS URL
- A store that implements principal resolution, identity provisioning, provider
  trust, provisioning-rule, and local-role ports
- Local roles already chosen for the initial access you want to grant
- An application-owned approval rule for which identities may be provisioned

## Trust The Provider With Forwarded Claims

Store trusted provider configuration and explicitly choose the claims authkit may
forward into `authkit.Identity.Claims`:

```go
provider, err := store.TrustProvider(ctx, oidc.Provider{
	Issuer:    "https://issuer.example",
	Audiences: []string{"notes-api"},
	JWKSURL:   "https://issuer.example/.well-known/jwks.json",
	ForwardedClaims: []authkit.ClaimPath{
		{"email"},
		{"groups"},
	},
})
if err != nil {
	return err
}
```

Provisioning rules can reference only forwarded claim paths.

## Create The Initial Role

Create a local role and grant the actions new principals should receive:

```go
_, err = store.CreateRole(ctx, authkit.CreateRoleRequest{
	ID:          "notes-reader",
	DisplayName: "Notes reader",
})
if err != nil {
	return err
}

err = store.GrantRoleAction(ctx, authkit.GrantRoleActionRequest{
	RoleID: "notes-reader",
	Action: "note:read",
})
if err != nil {
	return err
}
```

## Create A Provisioning Rule

Create a CEL-backed rule for the trusted provider and forwarded claims:

```go
_, err = store.CreateProvisioningRule(ctx, authkit.CreateProvisioningRuleRequest{
	ID:            "engineering-readers",
	DisplayName:   "Engineering readers",
	Provider:      provider.Issuer,
	Condition:     `hasAny(claims.groups, ["/engineering"])`,
	AssignRoleIDs: []string{"notes-reader"},
	Enabled:       true,
})
if err != nil {
	return err
}
```

Rules are compiled and type-checked when they are created or updated. The CEL
environment is intentionally small:

- `identity.provider`
- `identity.subject`
- `identity.credential_id`
- `claims`, containing only verified claims forwarded by trusted provider
  configuration

Conditions must return `bool`. Evaluation errors, missing claims, disabled
rules, and provider mismatches do not match. Two helpers cover common token
shapes: `hasAny(value, ["accepted"])` for string or string-list claims and
`hasToken(claims.scope, "scope-name")` for space-delimited OIDC scope strings.

## Build The OIDC Authenticator

Use the trusted provider store as the OIDC source:

```go
oidcAuthenticator, err := oidc.NewAuthenticator(store)
if err != nil {
	return err
}
```

The authenticator verifies JWT bearer tokens and returns `authkit.Identity`
values. It does not create principals.

## Wrap Principal Resolution

Wrap your normal resolver with `provisioning.NewResolver`:

```go
resolver, err := provisioning.NewResolver(provisioning.ResolverOptions{
	Resolver:    store,
	Provisioner: store,
	RuleSource:  store,
	Factory: func(_ context.Context, identity authkit.Identity) (authkit.CreatePrincipalRequest, bool, error) {
		if identity.Provider != provider.Issuer {
			return authkit.CreatePrincipalRequest{}, false, nil
		}

		email, ok := authkit.ClaimPath{"email"}.Lookup(identity.Claims)
		if !ok {
			return authkit.CreatePrincipalRequest{}, false, nil
		}

		return authkit.CreatePrincipalRequest{
			Kind:        authkit.PrincipalKindUser,
			DisplayName: fmt.Sprint(email),
			Attributes: map[string]any{
				"email": email,
			},
		}, true, nil
	},
})
if err != nil {
	return err
}
```

The factory is the approval point. Return `false` when the identity should stay
unresolved.

## Build The Pipeline

Use the provisioning resolver in the normal authkit pipeline:

```go
authorizer, err := roleauth.NewAuthorizer(store)
if err != nil {
	return err
}

pipeline, err := authkit.NewPipeline(authkit.PipelineOptions{
	Authenticators: []authkit.Authenticator{oidcAuthenticator},
	Resolver:       resolver,
	Authorizer:     authorizer,
})
if err != nil {
	return err
}
```

## Verification

Send a request with a JWT from the trusted issuer where:

- `aud` contains `notes-api`
- `sub` is a new external subject
- `groups` contains `/engineering`

The first request should create the principal, link `(issuer, sub)`, assign the
`notes-reader` role, and allow `note:read`.

Repeat the request with a token that omits `groups` or does not include
`/engineering`. The principal may still be created when the factory approves it,
but `note:read` should be denied unless another local role grant exists.

## Troubleshooting

### Rule Creation Fails Because The Provider Does Not Forward The Claim

Add the claim path to `oidc.Provider.ForwardedClaims`, then trust the provider
again before creating the rule.

### A Matching Rule Does Not Change An Existing Principal

Provisioning rules assign roles only when a new principal is created. Assign
roles explicitly for existing principals.

## Related

- [How to configure local roles](configure-local-roles.md)
- [Security model](../explanations/security-model.md)
- [Extension points reference](../reference/extension-points.md)
