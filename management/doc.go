// Package management provides reusable Go services for authkit setup flows.
//
// The package composes the lower-level authkit principal and identity-link
// contracts with the apikey service. It is intended for application-owned
// setup paths such as CLIs, seed scripts, migrations, or admin handlers without
// providing an admin HTTP API itself.
package management
