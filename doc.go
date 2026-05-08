// Package authkit provides core authentication and authorization contracts for
// Go Web API services.
//
// The core pipeline keeps credentials separate from application principals:
// authenticators return external Identity values, a PrincipalResolver maps
// those identities to internal Principal values, and an Authorizer evaluates
// actions against application Resource values.
package authkit
