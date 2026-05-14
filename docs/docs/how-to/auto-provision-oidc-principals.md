---
title: How To Exchange OIDC Tokens And Auto-Provision Principals
description: Verify OIDC JWTs, provision approved identities, and issue authkit access JWTs.
---

# How To Exchange OIDC Tokens And Auto-Provision Principals

Configure OIDC exchange when a trusted external JWT should become a short-lived
authkit access JWT. OIDC tokens are proof material for an exchange route; they
are not protected-resource credentials.

The flow is:

```text
OIDC JWT -> oidc.Verifier -> authkit.Identity -> exchange.IdentityExchanger -> authkit access JWT
```

Protected resource routes should then accept the authkit access JWT with
`accessjwtauth` or `compose.AccessJWT`.

## Prerequisites

- A trusted OIDC issuer and JWKS URL
- A store that implements principal resolution, identity provisioning, provider
  trust, provisioning-rule, and local-role ports
- Local roles already chosen for the initial access you want to grant
- An application-owned exchange endpoint with appropriate CSRF, rate limiting,
  response, audit, and browser/session behavior

## Trust The Provider With Forwarded Claims

Store trusted provider configuration and explicitly choose the claims authkit may
forward into `authkit.Identity.Claims`:

```go
provider, err := store.TrustProvider(ctx, oidc.Provider{
	Issuer:    "https://issuer.example",
	Audiences: []string{"pastebin"},
	JWKSURL:   "https://issuer.example/.well-known/jwks.json",
	ForwardedClaims: []authkit.ClaimPath{
		{"email"},
		{"name"},
		{"groups"},
	},
})
if err != nil {
	return err
}
```

Provisioning rules can reference only forwarded claim paths.

## Create Initial Roles And Rules

Create local roles and grant the actions new principals should receive:

```go
_, err = store.CreateRole(ctx, authkit.CreateRoleRequest{
	ID:          "paste-author",
	DisplayName: "Paste author",
})
if err != nil {
	return err
}

err = store.GrantRoleAction(ctx, authkit.GrantRoleActionRequest{
	RoleID: "paste-author",
	Action: "paste:create",
})
if err != nil {
	return err
}
```

Create a CEL-backed provisioning rule for the trusted provider and forwarded
claims:

```go
_, err = store.CreateProvisioningRule(ctx, authkit.CreateProvisioningRuleRequest{
	ID:            "engineering-authors",
	DisplayName:   "Engineering authors",
	Provider:      provider.Issuer,
	Condition:     `hasAny(claims.groups, ["/engineering"])`,
	AssignRoleIDs: []string{"paste-author"},
	Enabled:       true,
})
if err != nil {
	return err
}
```

Conditions must return `bool`. Evaluation errors, missing claims, disabled
rules, and provider mismatches do not match. The CEL environment exposes
`identity.provider`, `identity.subject`, `identity.credential_id`, and `claims`.
Two helpers cover common token shapes: `hasAny(value, ["accepted"])` for string
or string-list claims and `hasToken(claims.scope, "scope-name")` for
space-delimited OIDC scope strings.

## Build The OIDC Verifier

Use the trusted provider store as the OIDC source:

```go
verifier, err := oidc.NewVerifier(store)
if err != nil {
	return err
}
```

The verifier validates raw JWTs and returns `authkit.Identity` values. It does
not create principals, issue access tokens, or authorize resource access.

## Build The Identity Resolver

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

		name := identity.Subject
		if value, ok := authkit.ClaimPath{"name"}.Lookup(identity.Claims); ok {
			name = fmt.Sprint(value)
		}

		return authkit.CreatePrincipalRequest{
			Kind:        authkit.PrincipalKindUser,
			DisplayName: name,
		}, true, nil
	},
})
if err != nil {
	return err
}
```

The factory is the approval point. Return `false` when the identity should stay
unresolved.

## Build The Identity Exchanger

Create an access JWT issuer for your service, then wire the exchanger:

```go
identityExchanger, err := exchange.NewIdentityExchanger(exchange.IdentityOptions{
	Resolver:     resolver,
	AccessTokens: accessIssuer,
})
if err != nil {
	return err
}
```

## Exchange A Token

In your application-owned exchange route:

```go
identity, err := verifier.VerifyToken(req.Context(), rawOIDCToken)
if err != nil {
	return err
}

result, err := identityExchanger.Exchange(req.Context(), exchange.IdentityRequest{
	Identity: identity,
})
if err != nil {
	return err
}

accessToken := result.AccessToken.Plaintext
```

The route can return the access token in JSON, set an application cookie, or
integrate with an application-owned session flow. authkit does not prescribe
that transport.

## Protect Resource Routes

Protected routes should accept only authkit access JWTs:

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

Do not pass OIDC JWTs directly to resource routes. Verify and exchange them
first.

## Verification

Send a token from the trusted issuer where:

- `aud` contains your configured audience
- `sub` is a new external subject
- forwarded claims satisfy your provisioning rule

The exchange should verify the token, create and link the principal if the
factory approves it, assign matching initial roles, and issue an authkit access
JWT. A later protected request should succeed only when it presents that authkit
access JWT.

Repeat the exchange with a token that omits required claims. The identity may
still be provisioned when the factory approves it, but initial role assignment
should not occur unless a provisioning rule matches.

## Troubleshooting

### Rule Creation Fails Because The Provider Does Not Forward The Claim

Add the claim path to `oidc.Provider.ForwardedClaims`, then trust the provider
again before creating the rule.

### A Matching Rule Does Not Change An Existing Principal

Provisioning rules assign roles only when a new principal is created. Assign
roles explicitly for existing principals.

### Direct OIDC Tokens Are Rejected On Resource Routes

That is expected. OIDC tokens are accepted only by your exchange route. Resource
routes authenticate authkit access JWTs.

## Related

- [How to compose HTTP authentication](compose-http-auth.md)
- [How to configure local roles](configure-local-roles.md)
- [Security model](../explanations/security-model.md)
- [Extension points reference](../reference/extension-points.md)
