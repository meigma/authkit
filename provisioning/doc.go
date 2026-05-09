// Package provisioning resolves existing principals and can auto-provision allowed identities.
//
// Provisioning is an opt-in resolver layer. It does not authenticate credentials
// and does not grant authorization policy; callers decide which verified
// identities may create principals.
package provisioning
