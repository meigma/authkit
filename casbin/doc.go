// Package casbin adapts Casbin enforcement to authkit authorizer contracts.
//
// By default, the adapter projects authorization checks to classic Casbin
// subject, object, and action values. Use WithRequestBuilder when a Casbin model
// needs caller-supplied authorization facts or a different request shape.
package casbin
