// Package memory provides in-memory stores for tests, examples, and prototypes.
//
// Store implements the current principal, local role, provisioning rule,
// identity-link, API-token, and OIDC provider-trust contracts. It is
// deterministic and concurrency-safe, but it is not a production persistence
// adapter.
package memory
