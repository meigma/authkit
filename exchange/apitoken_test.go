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
	"github.com/meigma/authkit/apikey"
	"github.com/meigma/authkit/exchange"
	"github.com/meigma/authkit/internal/authtest"
	"github.com/meigma/authkit/store/memory"
)

const (
	testPrincipalID = "principal_1"
	testTokenID     = "access-token-123"
)

func TestNewAPITokenExchangerValidatesDependencies(t *testing.T) {
	apiTokens := fakeAPITokenVerifier{}
	principals := fakePrincipalFinder{}
	accessTokens := fakeAccessTokenIssuer{}

	tests := []struct {
		name string
		opts exchange.APITokenOptions
	}{
		{
			name: "missing API token verifier",
			opts: exchange.APITokenOptions{
				Principals:   principals,
				AccessTokens: accessTokens,
			},
		},
		{
			name: "missing principal finder",
			opts: exchange.APITokenOptions{
				APITokens:    apiTokens,
				AccessTokens: accessTokens,
			},
		},
		{
			name: "missing access token issuer",
			opts: exchange.APITokenOptions{
				APITokens:  apiTokens,
				Principals: principals,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exchanger, err := exchange.NewAPITokenExchanger(tt.opts)

			require.Error(t, err)
			assert.Nil(t, exchanger)
		})
	}
}

func TestAPITokenExchangerExchangesTokenForAccessJWT(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	principal, err := store.CreatePrincipal(ctx, authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindService,
		DisplayName: "notes service",
	})
	require.NoError(t, err)
	apiTokens, err := apikey.NewService(store, apikey.WithClock(fixedTime))
	require.NoError(t, err)
	apiToken, err := apiTokens.IssueToken(ctx, apikey.IssueRequest{
		PrincipalID: principal.ID,
		Name:        "bootstrap token",
		ExpiresAt:   fixedTime().Add(time.Hour),
	})
	require.NoError(t, err)
	accessTokens, verifier := newAccessJWTIssuerAndVerifier(t)
	exchanger := newAPITokenExchanger(t, exchange.APITokenOptions{
		APITokens:    apiTokens,
		Principals:   store,
		AccessTokens: accessTokens,
	})

	result, err := exchanger.Exchange(ctx, exchange.APITokenRequest{
		Plaintext: apiToken.Plaintext,
	})

	require.NoError(t, err)
	assert.Equal(t, apikey.VerifiedToken{
		ID:          apiToken.ID,
		PrincipalID: principal.ID,
		ExpiresAt:   apiToken.ExpiresAt,
	}, result.APIToken)
	assert.Equal(t, principal, result.Principal)
	assert.Equal(t, principal.ID, result.AccessToken.PrincipalID)
	verified, err := verifier.VerifyToken(ctx, result.AccessToken.Plaintext)
	require.NoError(t, err)
	assert.Equal(t, principal.ID, verified.PrincipalID)
}

func TestAPITokenExchangerDoesNotRequireIdentityLink(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	principal, err := store.CreatePrincipal(ctx, authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindService,
		DisplayName: "notes service",
	})
	require.NoError(t, err)
	apiTokens, err := apikey.NewService(store, apikey.WithClock(fixedTime))
	require.NoError(t, err)
	apiToken, err := apiTokens.IssueToken(ctx, apikey.IssueRequest{
		PrincipalID: principal.ID,
		Name:        "bootstrap token",
		ExpiresAt:   fixedTime().Add(time.Hour),
	})
	require.NoError(t, err)
	accessTokens, _ := newAccessJWTIssuerAndVerifier(t)
	exchanger := newAPITokenExchanger(t, exchange.APITokenOptions{
		APITokens:    apiTokens,
		Principals:   store,
		AccessTokens: accessTokens,
	})

	result, err := exchanger.Exchange(ctx, exchange.APITokenRequest{
		Plaintext: apiToken.Plaintext,
	})

	require.NoError(t, err)
	assert.Equal(t, principal.ID, result.Principal.ID)
}

func TestAPITokenExchangerRejectsMissingPrincipal(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	accessTokens, _ := newAccessJWTIssuerAndVerifier(t)
	exchanger := newAPITokenExchanger(t, exchange.APITokenOptions{
		APITokens: fakeAPITokenVerifier{
			token: apikey.VerifiedToken{
				ID:          "api-token-1",
				PrincipalID: "missing",
				ExpiresAt:   fixedTime().Add(time.Hour),
			},
		},
		Principals:   store,
		AccessTokens: accessTokens,
	})

	result, err := exchanger.Exchange(ctx, exchange.APITokenRequest{
		Plaintext: "ak_token_secret",
	})

	require.ErrorIs(t, err, authkit.ErrUnauthenticated)
	assert.Empty(t, result)
}

func TestAPITokenExchangerRejectsInvalidAPIToken(t *testing.T) {
	store := memory.NewStore()
	apiTokens, err := apikey.NewService(store, apikey.WithClock(fixedTime))
	require.NoError(t, err)
	accessTokens, _ := newAccessJWTIssuerAndVerifier(t)
	exchanger := newAPITokenExchanger(t, exchange.APITokenOptions{
		APITokens:    apiTokens,
		Principals:   store,
		AccessTokens: accessTokens,
	})

	result, err := exchanger.Exchange(context.Background(), exchange.APITokenRequest{
		Plaintext: "invalid",
	})

	require.ErrorIs(t, err, authkit.ErrUnauthenticated)
	assert.Empty(t, result)
}

func TestAPITokenExchangerWrapsInternalFailures(t *testing.T) {
	issuerErr := errors.New("issuer failed")
	storeErr := errors.New("store failed")
	apiToken := apikey.VerifiedToken{
		ID:          "api-token-1",
		PrincipalID: testPrincipalID,
		ExpiresAt:   fixedTime().Add(time.Hour),
	}
	principal := authkit.Principal{
		ID:          testPrincipalID,
		Kind:        authkit.PrincipalKindService,
		DisplayName: "notes service",
	}

	tests := []struct {
		name string
		opts exchange.APITokenOptions
		want error
	}{
		{
			name: "principal finder failure",
			opts: exchange.APITokenOptions{
				APITokens: fakeAPITokenVerifier{
					token: apiToken,
				},
				Principals: fakePrincipalFinder{
					err: storeErr,
				},
				AccessTokens: fakeAccessTokenIssuer{},
			},
			want: storeErr,
		},
		{
			name: "access token issuer failure",
			opts: exchange.APITokenOptions{
				APITokens: fakeAPITokenVerifier{
					token: apiToken,
				},
				Principals: fakePrincipalFinder{
					principal: principal,
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
			exchanger := newAPITokenExchanger(t, tt.opts)

			result, err := exchanger.Exchange(context.Background(), exchange.APITokenRequest{
				Plaintext: "ak_token_secret",
			})

			require.ErrorIs(t, err, authkit.ErrInternal)
			require.ErrorIs(t, err, tt.want)
			assert.Empty(t, result)
		})
	}
}

func TestAPITokenExchangerPassesThroughContextErrors(t *testing.T) {
	exchanger := newAPITokenExchanger(t, exchange.APITokenOptions{
		APITokens:    fakeAPITokenVerifier{},
		Principals:   fakePrincipalFinder{},
		AccessTokens: fakeAccessTokenIssuer{},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := exchanger.Exchange(ctx, exchange.APITokenRequest{
		Plaintext: "ak_token_secret",
	})

	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, authkit.ErrInternal)
	assert.Empty(t, result)
}

func newAPITokenExchanger(t *testing.T, opts exchange.APITokenOptions) *exchange.APITokenExchanger {
	t.Helper()

	exchanger, err := exchange.NewAPITokenExchanger(opts)
	require.NoError(t, err)

	return exchanger
}

func newAccessJWTIssuerAndVerifier(t *testing.T) (*accessjwt.Issuer, *accessjwt.Verifier) {
	t.Helper()

	return authtest.NewAccessJWTIssuerAndVerifier(
		t,
		authtest.WithAccessJWTTokenID(func() (string, error) {
			return testTokenID, nil
		}),
	)
}

type fakeAPITokenVerifier struct {
	token apikey.VerifiedToken
	err   error
}

func (f fakeAPITokenVerifier) VerifyAPIToken(
	context.Context,
	string,
) (apikey.VerifiedToken, error) {
	return f.token, f.err
}

type fakePrincipalFinder struct {
	principal authkit.Principal
	err       error
}

func (f fakePrincipalFinder) FindPrincipal(
	context.Context,
	string,
) (authkit.Principal, error) {
	return f.principal, f.err
}

type fakeAccessTokenIssuer struct {
	token accessjwt.IssuedToken
	err   error
}

func (f fakeAccessTokenIssuer) IssueToken(
	context.Context,
	accessjwt.IssueRequest,
) (accessjwt.IssuedToken, error) {
	return f.token, f.err
}

func fixedTime() time.Time {
	return authtest.FixedTime()
}
