// Package onboarding coordinates explicit identity attachment and principal provisioning.
//
// Credential method packages authenticate or verify method-specific material and
// return authkit.Identity values. Package onboarding helps applications bind
// those verified identities to principals without adding side effects to normal
// request authentication.
package onboarding
