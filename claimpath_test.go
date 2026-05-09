package authkit_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/meigma/authkit"
)

func TestClaimPathLookup(t *testing.T) {
	claims := map[string]any{
		"email": "ada@example.test",
		"groups": []any{
			"/engineering",
			"/platform",
		},
		"realm_access": map[string]any{
			"roles": []any{
				"admin",
				"writer",
			},
		},
	}

	tests := []struct {
		name  string
		path  authkit.ClaimPath
		want  any
		found bool
	}{
		{
			name:  "top-level scalar",
			path:  authkit.ClaimPath{"email"},
			want:  "ada@example.test",
			found: true,
		},
		{
			name:  "top-level list",
			path:  authkit.ClaimPath{"groups"},
			want:  []any{"/engineering", "/platform"},
			found: true,
		},
		{
			name:  "nested list",
			path:  authkit.ClaimPath{"realm_access", "roles"},
			want:  []any{"admin", "writer"},
			found: true,
		},
		{
			name: "missing nested claim",
			path: authkit.ClaimPath{"realm_access", "groups"},
		},
		{
			name: "cannot traverse scalar",
			path: authkit.ClaimPath{"email", "domain"},
		},
		{
			name: "empty path",
			path: authkit.ClaimPath{},
		},
		{
			name: "empty segment",
			path: authkit.ClaimPath{"realm_access", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found := tt.path.Lookup(claims)

			assert.Equal(t, tt.found, found)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClaimPathValid(t *testing.T) {
	assert.True(t, authkit.ClaimPath{"realm_access", "roles"}.Valid())
	assert.False(t, authkit.ClaimPath{}.Valid())
	assert.False(t, authkit.ClaimPath{"groups", ""}.Valid())
}
