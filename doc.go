// Package authkit provides core authentication and authorization contracts for
// Go Web API services.
//
// The core pipeline keeps credentials separate from authorization decisions:
// principal authenticators return internal Principal values for authkit-owned
// request credentials, while legacy identity authenticators can still return
// external Identity values that a PrincipalResolver maps to Principal values.
// An Authorizer evaluates authorization checks containing the principal, action,
// application Resource, and caller-supplied Facts. The accessjwt package issues
// and verifies authkit-owned access JWTs, accessjwtauth adapts them to HTTP
// bearer authentication, and roleauth authorizes from local admin-managed roles
// and effective action grants.
package authkit
