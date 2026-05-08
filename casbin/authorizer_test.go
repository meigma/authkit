package casbin

import (
	"context"
	"errors"
	"testing"

	casbinv3 "github.com/casbin/casbin/v3"
	casbinmodel "github.com/casbin/casbin/v3/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
)

func TestNewAuthorizerValidatesDependencies(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
	}{
		{
			name: "missing enforcer",
			opts: nil,
		},
		{
			name: "missing request builder",
			opts: []Option{
				func(opts *options) {
					opts.requestBuilder = nil
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var enforcer Enforcer = allowEnforcer()
			if tt.name == "missing enforcer" {
				enforcer = nil
			}

			authorizer, err := NewAuthorizer(enforcer, tt.opts...)

			require.Error(t, err)
			assert.Nil(t, authorizer)
		})
	}
}

func TestDefaultRequestBuilderProjectsClassicCasbinRequest(t *testing.T) {
	tests := []struct {
		name     string
		resource authkit.Resource
		want     []any
	}{
		{
			name:     "type and ID",
			resource: testResource("note", "note-1"),
			want:     []any{"principal_1", "note:note-1", "note:update"},
		},
		{
			name:     "type only",
			resource: testResource("system", ""),
			want:     []any{"principal_1", "system", "note:update"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DefaultRequestBuilder(testPrincipal(), "note:update", tt.resource)

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDefaultRequestBuilderValidatesRequiredInputs(t *testing.T) {
	tests := []struct {
		name      string
		principal authkit.Principal
		action    string
		resource  authkit.Resource
		want      string
	}{
		{
			name:      "missing principal ID",
			principal: authkit.Principal{},
			action:    "note:update",
			resource:  testResource("note", "note-1"),
			want:      "principal ID is required",
		},
		{
			name:      "missing action",
			principal: testPrincipal(),
			action:    "",
			resource:  testResource("note", "note-1"),
			want:      "action is required",
		},
		{
			name:      "missing resource type",
			principal: testPrincipal(),
			action:    "note:update",
			resource:  authkit.Resource{},
			want:      "resource type is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DefaultRequestBuilder(tt.principal, tt.action, tt.resource)

			require.ErrorContains(t, err, tt.want)
			assert.Nil(t, got)
		})
	}
}

func TestAuthorizerCanAllowsPolicy(t *testing.T) {
	var gotRequest []any
	authorizer := newAuthorizer(t, testEnforcer{
		enforce: func(rvals ...any) (bool, error) {
			gotRequest = rvals

			return true, nil
		},
	})

	decision, err := authorizer.Can(
		context.Background(),
		testPrincipal(),
		"note:update",
		testResource("note", "note-1"),
	)

	require.NoError(t, err)
	assert.Equal(t, authkit.Decision{Allowed: true}, decision)
	assert.Equal(t, []any{"principal_1", "note:note-1", "note:update"}, gotRequest)
}

func TestAuthorizerCanDeniesPolicy(t *testing.T) {
	authorizer := newAuthorizer(t, denyEnforcer())

	decision, err := authorizer.Can(
		context.Background(),
		testPrincipal(),
		"note:update",
		testResource("note", "note-1"),
	)

	require.NoError(t, err)
	assert.Equal(t, authkit.Decision{Allowed: false, Reason: deniedReason}, decision)
}

func TestAuthorizerCanUsesCustomRequestBuilder(t *testing.T) {
	var gotRequest []any
	authorizer, err := NewAuthorizer(
		testEnforcer{
			enforce: func(rvals ...any) (bool, error) {
				gotRequest = rvals

				return true, nil
			},
		},
		WithRequestBuilder(func(principal authkit.Principal, action string, resource authkit.Resource) ([]any, error) {
			return []any{
				principal.Kind,
				principal.ID,
				resource.Type,
				resource.ID,
				action,
			}, nil
		}),
	)
	require.NoError(t, err)

	decision, err := authorizer.Can(
		context.Background(),
		testPrincipal(),
		"note:update",
		testResource("note", "note-1"),
	)

	require.NoError(t, err)
	assert.Equal(t, authkit.Decision{Allowed: true}, decision)
	assert.Equal(t, []any{
		authkit.PrincipalKindUser,
		"principal_1",
		"note",
		"note-1",
		"note:update",
	}, gotRequest)
}

func TestAuthorizerCanReturnsProjectionErrors(t *testing.T) {
	projectionErr := errors.New("projection failed")
	enforcerCalls := 0
	authorizer, err := NewAuthorizer(
		testEnforcer{
			enforce: func(...any) (bool, error) {
				enforcerCalls++

				return true, nil
			},
		},
		WithRequestBuilder(func(authkit.Principal, string, authkit.Resource) ([]any, error) {
			return nil, projectionErr
		}),
	)
	require.NoError(t, err)

	decision, err := authorizer.Can(
		context.Background(),
		testPrincipal(),
		"note:update",
		testResource("note", "note-1"),
	)

	require.ErrorIs(t, err, projectionErr)
	assert.Empty(t, decision)
	assert.Equal(t, 0, enforcerCalls)
}

func TestAuthorizerCanReturnsDefaultProjectionErrors(t *testing.T) {
	tests := []struct {
		name      string
		principal authkit.Principal
		action    string
		resource  authkit.Resource
		want      string
	}{
		{
			name:      "missing principal ID",
			principal: authkit.Principal{},
			action:    "note:update",
			resource:  testResource("note", "note-1"),
			want:      "principal ID is required",
		},
		{
			name:      "missing action",
			principal: testPrincipal(),
			action:    "",
			resource:  testResource("note", "note-1"),
			want:      "action is required",
		},
		{
			name:      "missing resource type",
			principal: testPrincipal(),
			action:    "note:update",
			resource:  authkit.Resource{},
			want:      "resource type is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enforcerCalls := 0
			authorizer := newAuthorizer(t, testEnforcer{
				enforce: func(...any) (bool, error) {
					enforcerCalls++

					return true, nil
				},
			})

			decision, err := authorizer.Can(context.Background(), tt.principal, tt.action, tt.resource)

			require.ErrorContains(t, err, tt.want)
			assert.Empty(t, decision)
			assert.Equal(t, 0, enforcerCalls)
		})
	}
}

func TestAuthorizerCanReturnsEnforcerErrors(t *testing.T) {
	enforcerErr := errors.New("enforcer failed")
	authorizer := newAuthorizer(t, testEnforcer{
		enforce: func(...any) (bool, error) {
			return false, enforcerErr
		},
	})

	decision, err := authorizer.Can(
		context.Background(),
		testPrincipal(),
		"note:update",
		testResource("note", "note-1"),
	)

	require.ErrorIs(t, err, enforcerErr)
	assert.Empty(t, decision)
}

func TestAuthorizerCanReturnsContextErrorBeforeProjection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	builderCalls := 0
	enforcerCalls := 0
	authorizer, err := NewAuthorizer(
		testEnforcer{
			enforce: func(...any) (bool, error) {
				enforcerCalls++

				return true, nil
			},
		},
		WithRequestBuilder(func(authkit.Principal, string, authkit.Resource) ([]any, error) {
			builderCalls++

			return []any{"principal_1", "note:note-1", "note:update"}, nil
		}),
	)
	require.NoError(t, err)

	decision, err := authorizer.Can(
		ctx,
		testPrincipal(),
		"note:update",
		testResource("note", "note-1"),
	)

	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, decision)
	assert.Equal(t, 0, builderCalls)
	assert.Equal(t, 0, enforcerCalls)
}

func TestAuthorizerCanUsesRealCasbinEnforcer(t *testing.T) {
	enforcer := newCasbinEnforcer(t)
	_, err := enforcer.AddPolicy("principal_1", "note:note-1", "note:update")
	require.NoError(t, err)
	authorizer := newAuthorizer(t, enforcer)

	allowed, err := authorizer.Can(
		context.Background(),
		testPrincipal(),
		"note:update",
		testResource("note", "note-1"),
	)
	require.NoError(t, err)

	denied, err := authorizer.Can(
		context.Background(),
		testPrincipal(),
		"note:delete",
		testResource("note", "note-1"),
	)
	require.NoError(t, err)

	assert.Equal(t, authkit.Decision{Allowed: true}, allowed)
	assert.Equal(t, authkit.Decision{Allowed: false, Reason: deniedReason}, denied)
}

func newAuthorizer(t *testing.T, enforcer Enforcer) *Authorizer {
	t.Helper()

	authorizer, err := NewAuthorizer(enforcer)
	require.NoError(t, err)

	return authorizer
}

func newCasbinEnforcer(t *testing.T) *casbinv3.Enforcer {
	t.Helper()

	model, err := casbinmodel.NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`)
	require.NoError(t, err)

	enforcer, err := casbinv3.NewEnforcer(model)
	require.NoError(t, err)

	return enforcer
}

func testPrincipal() authkit.Principal {
	return authkit.Principal{
		ID:          "principal_1",
		Kind:        authkit.PrincipalKindUser,
		DisplayName: "Ada Lovelace",
	}
}

func testResource(resourceType string, id string) authkit.Resource {
	return authkit.Resource{
		Type: resourceType,
		ID:   id,
	}
}

type testEnforcer struct {
	enforce func(...any) (bool, error)
}

func (e testEnforcer) Enforce(rvals ...any) (bool, error) {
	return e.enforce(rvals...)
}

func allowEnforcer() testEnforcer {
	return testEnforcer{
		enforce: func(...any) (bool, error) {
			return true, nil
		},
	}
}

func denyEnforcer() testEnforcer {
	return testEnforcer{
		enforce: func(...any) (bool, error) {
			return false, nil
		},
	}
}
