---
title: Core Contracts Reference
description: Reference for authkit root types, request shapes, facts, claim paths, and errors.
---

# Core Contracts Reference

This page describes the root `authkit` contracts used by authenticators,
resolvers, authorizers, stores, and HTTP adapters.

## Identity

`authkit.Identity` describes a credential identity after authentication
succeeds.

| Field | Type | Description |
|-------|------|-------------|
| `Provider` | `string` | Authority or credential class that produced the identity. API tokens use `api-token`; OIDC uses the issuer URL. |
| `Subject` | `string` | Provider-scoped subject. |
| `CredentialID` | `string` | Concrete credential identifier when the authenticator exposes one. |
| `Claims` | `map[string]any` | Optional verified metadata forwarded by the authenticator. |

## Principal

`authkit.Principal` describes an internal application actor.

| Field | Type | Description |
|-------|------|-------------|
| `ID` | `string` | Stable application-owned principal identifier. |
| `Kind` | `authkit.PrincipalKind` | Principal category. |
| `DisplayName` | `string` | Human-readable label. |
| `Attributes` | `map[string]any` | Optional application-owned metadata. |

### PrincipalKind

| Constant | Value | Description |
|----------|-------|-------------|
| `authkit.PrincipalKindUser` | `user` | Human user principal. |
| `authkit.PrincipalKindService` | `service` | Non-human service principal. |

## Role

`authkit.Role` describes an admin-managed local role.

| Field | Type | Description |
|-------|------|-------------|
| `ID` | `string` | Stable application-owned role identifier. |
| `DisplayName` | `string` | Human-readable label. |
| `Description` | `string` | Optional role description. |

## ProvisioningRule

`authkit.ProvisioningRule` describes an admin-managed exact-match rule for
initial role assignment during auto-provisioning.

| Field | Type | Description |
|-------|------|-------------|
| `ID` | `string` | Stable application-owned rule identifier. |
| `DisplayName` | `string` | Human-readable label. |
| `Provider` | `string` | Trusted identity provider this rule applies to. |
| `ClaimPath` | `authkit.ClaimPath` | Forwarded identity claim inspected by the rule. |
| `Values` | `[]string` | Exact claim values that satisfy the rule. |
| `AssignRoleIDs` | `[]string` | Local role IDs assigned when the rule matches. |
| `Enabled` | `bool` | Whether the rule participates in runtime provisioning. |

## Resource

`authkit.Resource` describes the authorization target for an action.

| Field | Type | Description |
|-------|------|-------------|
| `Type` | `string` | Resource class in application policy. |
| `ID` | `string` | Resource instance within `Type`. |
| `Attr` | `map[string]any` | Optional durable resource metadata. |

## Decision

`authkit.Decision` describes an authorization result.

| Field | Type | Description |
|-------|------|-------------|
| `Allowed` | `bool` | Whether the action may proceed. |
| `Reason` | `string` | Optional explanation for logs, debugging, or response rendering. |

## AuthorizationRequest

`authkit.AuthorizationRequest` is caller-supplied authorization input.

| Field | Type | Description |
|-------|------|-------------|
| `Action` | `string` | Operation the caller wants to perform. |
| `Resource` | `authkit.Resource` | Authorization target. |
| `Facts` | `authkit.Facts` | Optional decision-time context. |

## AuthorizationCheck

`authkit.AuthorizationCheck` is the complete input passed to an
`authkit.Authorizer`.

| Field | Type | Description |
|-------|------|-------------|
| `Principal` | `authkit.Principal` | Resolved internal actor. |
| `Action` | `string` | Operation the principal wants to perform. |
| `Resource` | `authkit.Resource` | Authorization target. |
| `Facts` | `authkit.Facts` | Optional decision-time context. |

## Facts

`authkit.FactKey` identifies a caller-supplied authorization fact.

`authkit.Facts` is `map[authkit.FactKey]any`.

| Function | Description |
|----------|-------------|
| `Facts.Clone()` | Returns a shallow copy, or `nil` for empty facts. |
| `authkit.MergeFacts(...authkit.Facts)` | Returns a shallow merge. Later fact sets replace earlier values for the same key. |

## ClaimPath

`authkit.ClaimPath` identifies a JWT claim or nested claim value.

| Method | Description |
|--------|-------------|
| `ClaimPath.Lookup(map[string]any)` | Returns the value at the path and whether it was present. |
| `ClaimPath.Valid()` | Reports whether the path contains at least one non-empty segment. |

Example paths:

```go
authkit.ClaimPath{"email"}
authkit.ClaimPath{"realm_access", "roles"}
```

## Request Types

### CreatePrincipalRequest

| Field | Type | Description |
|-------|------|-------------|
| `Kind` | `authkit.PrincipalKind` | Principal category. |
| `DisplayName` | `string` | Human-readable label. |
| `Attributes` | `map[string]any` | Optional application-owned metadata. |

### CreateRoleRequest

| Field | Type | Description |
|-------|------|-------------|
| `ID` | `string` | Stable application-owned role identifier. |
| `DisplayName` | `string` | Human-readable label. |
| `Description` | `string` | Optional role description. |

### GrantRoleActionRequest

| Field | Type | Description |
|-------|------|-------------|
| `RoleID` | `string` | Role receiving the action grant. |
| `Action` | `string` | Authorization action granted to the role. |

### AssignPrincipalRoleRequest

| Field | Type | Description |
|-------|------|-------------|
| `PrincipalID` | `string` | Principal receiving the role. |
| `RoleID` | `string` | Assigned role. |

### LinkIdentityRequest

| Field | Type | Description |
|-------|------|-------------|
| `Provider` | `string` | Authority or credential class for the identity. |
| `Subject` | `string` | Provider-scoped subject. |
| `PrincipalID` | `string` | Internal principal to link. |

### ProvisionIdentityRequest

| Field | Type | Description |
|-------|------|-------------|
| `Identity` | `authkit.Identity` | Authenticated external identity to provision. |
| `Principal` | `authkit.CreatePrincipalRequest` | Principal creation request used when the identity is not linked. |
| `InitialRoleIDs` | `[]string` | Local roles assigned only when a new principal is created. |

### ProvisionIdentityResult

| Field | Type | Description |
|-------|------|-------------|
| `Principal` | `authkit.Principal` | Internal principal linked to the identity. |
| `Link` | `authkit.ExternalIdentity` | External identity link for the principal. |
| `Created` | `bool` | Whether this call created a new principal and identity link. |

### CreateProvisioningRuleRequest

The fields match `authkit.ProvisioningRule`.

### UpdateProvisioningRuleRequest

The fields match `authkit.ProvisioningRule`.

## Errors

| Error | Condition |
|-------|-----------|
| `authkit.ErrUnauthenticated` | No request credential authenticated successfully. |
| `authkit.ErrUnresolvedIdentity` | A valid credential has no linked principal. |
| `authkit.ErrUnauthorized` | A resolved principal is not allowed to perform an action. |
| `authkit.ErrInternal` | An auth pipeline failure should be treated as internal. |
| `authkit.ErrProvisioningRuleNotFound` | A provisioning rule does not exist. |

## Related

- [Extension points reference](extension-points.md)
- [How to configure local roles](../how-to/configure-local-roles.md)
- [How to supply authorization facts](../how-to/supply-authorization-facts.md)
