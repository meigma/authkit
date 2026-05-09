package authkit

import "slices"

// ClaimPath identifies a JWT claim or nested claim value.
type ClaimPath []string

// Lookup returns the value at path from claims.
func (p ClaimPath) Lookup(claims map[string]any) (any, bool) {
	if len(p) == 0 || len(claims) == 0 {
		return nil, false
	}

	var current any = claims
	for _, segment := range p {
		if segment == "" {
			return nil, false
		}

		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}

		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}

	return current, true
}

// Valid reports whether path contains at least one non-empty segment.
func (p ClaimPath) Valid() bool {
	return len(p) > 0 && !slices.Contains(p, "")
}
