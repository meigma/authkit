package exchange_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/accessjwt"
	"github.com/meigma/authkit/exchange"
)

func TestNewIdentityExchangerValidatesDependencies(t *testing.T) {
	resolver := fakeIdentityResolver{}
	accessTokens := fakeAccessTokenIssuer{}

	tests := []struct {
		name string
		opts exchange.IdentityOptions
	}{
		{
			name: "missing resolver",
			opts: exchange.IdentityOptions{
				AccessTokens: accessTokens,
			},
		},
		{
			name: "missing access token issuer",
			opts: exchange.IdentityOptions{
				Resolver: resolver,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exchanger, err := exchange.NewIdentityExchanger(tt.opts)

			require.Error(t, err)
			assert.Nil(t, exchanger)
		})
	}
}

func TestIdentityExchangerExchangesResolvedIdentityForAccessJWT(t *testing.T) {
	identity := testExchangeIdentity()
	principal := testExchangePrincipal()
	accessToken := accessjwt.IssuedToken{
		ID:          testTokenID,
		PrincipalID: principal.ID,
		Plaintext:   "access.jwt",
		ExpiresAt:   fixedTime().Add(time.Hour),
	}
	exchanger := newIdentityExchanger(t, exchange.IdentityOptions{
		Resolver: fakeIdentityResolver{
			principal: principal,
		},
		AccessTokens: fakeAccessTokenIssuer{
			token: accessToken,
		},
	})

	result, err := exchanger.Exchange(context.Background(), exchange.IdentityRequest{
		Identity: identity,
	})

	require.NoError(t, err)
	assert.Equal(t, identity, result.Identity)
	assert.Equal(t, principal, result.Principal)
	assert.Equal(t, accessToken, result.AccessToken)
}

func TestIdentityExchangerPassesThroughUnresolvedIdentity(t *testing.T) {
	exchanger := newIdentityExchanger(t, exchange.IdentityOptions{
		Resolver: fakeIdentityResolver{
			err: authkit.ErrUnresolvedIdentity,
		},
		AccessTokens: fakeAccessTokenIssuer{},
	})

	result, err := exchanger.Exchange(context.Background(), exchange.IdentityRequest{
		Identity: testExchangeIdentity(),
	})

	require.ErrorIs(t, err, authkit.ErrUnresolvedIdentity)
	require.NotErrorIs(t, err, authkit.ErrInternal)
	assert.Empty(t, result)
}

func TestIdentityExchangerWrapsInternalFailures(t *testing.T) {
	resolverErr := errors.New("resolver failed")
	issuerErr := errors.New("issuer failed")

	tests := []struct {
		name string
		opts exchange.IdentityOptions
		want error
	}{
		{
			name: "resolver failure",
			opts: exchange.IdentityOptions{
				Resolver: fakeIdentityResolver{
					err: resolverErr,
				},
				AccessTokens: fakeAccessTokenIssuer{},
			},
			want: resolverErr,
		},
		{
			name: "issuer failure",
			opts: exchange.IdentityOptions{
				Resolver: fakeIdentityResolver{
					principal: testExchangePrincipal(),
				},
				AccessTokens: fakeAccessTokenIssuer{
					err: issuerErr,
				},
			},
			want: issuerErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exchanger := newIdentityExchanger(t, tt.opts)

			result, err := exchanger.Exchange(context.Background(), exchange.IdentityRequest{
				Identity: testExchangeIdentity(),
			})

			require.ErrorIs(t, err, authkit.ErrInternal)
			require.ErrorIs(t, err, tt.want)
			assert.Empty(t, result)
		})
	}
}

func TestIdentityExchangerPassesThroughContextErrors(t *testing.T) {
	exchanger := newIdentityExchanger(t, exchange.IdentityOptions{
		Resolver:     fakeIdentityResolver{},
		AccessTokens: fakeAccessTokenIssuer{},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := exchanger.Exchange(ctx, exchange.IdentityRequest{
		Identity: testExchangeIdentity(),
	})

	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, authkit.ErrInternal)
	assert.Empty(t, result)
}

func newIdentityExchanger(t *testing.T, opts exchange.IdentityOptions) *exchange.IdentityExchanger {
	t.Helper()

	exchanger, err := exchange.NewIdentityExchanger(opts)
	require.NoError(t, err)

	return exchanger
}

func testExchangeIdentity() authkit.Identity {
	return authkit.Identity{
		Provider: "https://issuer.example",
		Subject:  "user-123",
		Claims: map[string]any{
			"email": "ada@example.test",
		},
	}
}

func testExchangePrincipal() authkit.Principal {
	return authkit.Principal{
		ID:          testPrincipalID,
		Kind:        authkit.PrincipalKindUser,
		DisplayName: "Ada Lovelace",
	}
}

type fakeIdentityResolver struct {
	principal authkit.Principal
	err       error
}

func (f fakeIdentityResolver) ResolveIdentity(
	context.Context,
	authkit.Identity,
) (*authkit.Principal, error) {
	if f.err != nil {
		return nil, f.err
	}

	return &f.principal, nil
}
