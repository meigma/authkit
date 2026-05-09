// Package provisioning resolves existing principals and can auto-provision allowed identities.
//
// Provisioning is an opt-in resolver layer. It does not authenticate credentials.
// Callers decide which verified identities may create principals, and optional
// provisioning rules can assign initial local roles from forwarded claims.
package provisioning
