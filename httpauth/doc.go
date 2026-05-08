// Package httpauth adapts authkit pipelines to net/http handlers.
//
// The default renderer maps missing or invalid credentials and unresolved
// identities to HTTP 401, denied authorization decisions to HTTP 403, and
// unexpected collaborator failures to HTTP 500. Applications can replace this
// behavior with WithErrorRenderer.
package httpauth
