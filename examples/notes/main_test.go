package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/apikey"
	"github.com/meigma/authkit/oidc"
)

const (
	linkedOIDCSubject   = "oidc-user-123"
	unlinkedOIDCSubject = "oidc-user-456"
	testAudience        = "notes-api"
)

func TestNotesAppAuthorizesRequests(t *testing.T) {
	tc := newMixedTestContext(t)

	tests := []struct {
		name          string
		path          string
		authorization string
		wantStatus    int
		wantBody      string
	}{
		{
			name:          "allows seeded API token to read allowed note",
			path:          "/notes/allowed",
			authorization: bearer(tc.app.seedToken),
			wantStatus:    http.StatusOK,
			wantBody:      "This note is readable by the seeded service principal.\n",
		},
		{
			name:          "allows linked OIDC token to read allowed note",
			path:          "/notes/allowed",
			authorization: bearer(tc.linkedOIDCToken),
			wantStatus:    http.StatusOK,
			wantBody:      "This note is readable by the seeded service principal.\n",
		},
		{
			name:          "denies seeded API token for note outside policy",
			path:          "/notes/denied",
			authorization: bearer(tc.app.seedToken),
			wantStatus:    http.StatusForbidden,
			wantBody:      "Forbidden\n",
		},
		{
			name:          "denies linked OIDC token for note outside policy",
			path:          "/notes/denied",
			authorization: bearer(tc.linkedOIDCToken),
			wantStatus:    http.StatusForbidden,
			wantBody:      "Forbidden\n",
		},
		{
			name:       "requires bearer token",
			path:       "/notes/allowed",
			wantStatus: http.StatusUnauthorized,
			wantBody:   "Unauthorized\n",
		},
		{
			name:          "rejects malformed bearer token",
			path:          "/notes/allowed",
			authorization: bearer("invalid"),
			wantStatus:    http.StatusUnauthorized,
			wantBody:      "Unauthorized\n",
		},
		{
			name:          "rejects valid API token without identity link",
			path:          "/notes/allowed",
			authorization: bearer(tc.unlinkedAPIToken),
			wantStatus:    http.StatusUnauthorized,
			wantBody:      "Unauthorized\n",
		},
		{
			name:          "rejects OIDC token with wrong audience",
			path:          "/notes/allowed",
			authorization: bearer(tc.wrongAudienceOIDCToken),
			wantStatus:    http.StatusUnauthorized,
			wantBody:      "Unauthorized\n",
		},
		{
			name:          "rejects OIDC token from untrusted issuer",
			path:          "/notes/allowed",
			authorization: bearer(tc.untrustedIssuerOIDCToken),
			wantStatus:    http.StatusUnauthorized,
			wantBody:      "Unauthorized\n",
		},
		{
			name:          "rejects valid OIDC token without identity link",
			path:          "/notes/allowed",
			authorization: bearer(tc.unlinkedOIDCToken),
			wantStatus:    http.StatusUnauthorized,
			wantBody:      "Unauthorized\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}

			recorder := httptest.NewRecorder()
			tc.app.ServeHTTP(recorder, req)

			assert.Equal(t, tt.wantStatus, recorder.Code)
			assert.Equal(t, tt.wantBody, recorder.Body.String())
		})
	}
}

func TestNotesAppLinksAPIAndOIDCIdentitiesToSamePrincipal(t *testing.T) {
	tc := newMixedTestContext(t)
	apiPrincipal := resolveIdentity(t, tc.app, authkit.Identity{
		Provider: tc.app.seedIdentity.Provider,
		Subject:  tc.app.seedIdentity.Subject,
	})
	oidcPrincipal := resolveIdentity(t, tc.app, authkit.Identity{
		Provider: tc.issuer.issuer,
		Subject:  linkedOIDCSubject,
	})

	assert.Equal(t, tc.app.principal.ID, apiPrincipal.ID)
	assert.Equal(t, tc.app.principal.ID, oidcPrincipal.ID)
	assert.Equal(t, apiPrincipal, oidcPrincipal)
}

type mixedTestContext struct {
	app                      *notesApp
	issuer                   *testIssuer
	linkedOIDCToken          string
	wrongAudienceOIDCToken   string
	untrustedIssuerOIDCToken string
	unlinkedOIDCToken        string
	unlinkedAPIToken         string
}

func newMixedTestContext(t *testing.T) mixedTestContext {
	t.Helper()

	ctx := context.Background()
	now := fixedTestTime()
	issuer := newTestIssuer(t)
	untrustedIssuer := newTestIssuer(t)
	app, err := newNotesApp(
		ctx,
		withClock(func() time.Time {
			return now
		}),
		withOIDCHTTPClient(issuer.server.Client()),
	)
	require.NoError(t, err)

	_, err = app.store.TrustProvider(ctx, issuer.provider(testAudience))
	require.NoError(t, err)
	_, err = app.store.LinkIdentity(ctx, authkit.LinkIdentityRequest{
		Provider:    issuer.issuer,
		Subject:     linkedOIDCSubject,
		PrincipalID: app.principal.ID,
	})
	require.NoError(t, err)

	return mixedTestContext{
		app:    app,
		issuer: issuer,
		linkedOIDCToken: issuer.sign(
			t,
			tokenRequest{subject: linkedOIDCSubject, audiences: []string{testAudience}},
		),
		wrongAudienceOIDCToken: issuer.sign(
			t,
			tokenRequest{subject: linkedOIDCSubject, audiences: []string{"other-api"}},
		),
		untrustedIssuerOIDCToken: untrustedIssuer.sign(
			t,
			tokenRequest{subject: linkedOIDCSubject, audiences: []string{testAudience}},
		),
		unlinkedOIDCToken: issuer.sign(
			t,
			tokenRequest{subject: unlinkedOIDCSubject, audiences: []string{testAudience}},
		),
		unlinkedAPIToken: issueUnlinkedToken(t, app),
	}
}

func issueUnlinkedToken(t *testing.T, app *notesApp) string {
	t.Helper()

	issued, err := app.tokenService.IssueToken(context.Background(), apikey.IssueRequest{
		PrincipalID: app.principal.ID,
		Name:        "unlinked token",
		ExpiresAt:   app.tokenExpiresAt,
	})
	require.NoError(t, err)

	return issued.Plaintext
}

func resolveIdentity(t *testing.T, app *notesApp, identity authkit.Identity) authkit.Principal {
	t.Helper()

	principal, err := app.store.ResolveIdentity(context.Background(), identity)
	require.NoError(t, err)
	require.NotNil(t, principal)

	return *principal
}

type testIssuer struct {
	server     *httptest.Server
	issuer     string
	jwksURL    string
	signingKey jwk.Key
	publicSet  jwk.Set
}

type tokenRequest struct {
	subject   string
	audiences []string
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()

	rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signingKey, err := jwk.Import(rawKey)
	require.NoError(t, err)
	require.NoError(t, signingKey.Set(jwk.KeyIDKey, "test-key"))
	require.NoError(t, signingKey.Set(jwk.AlgorithmKey, jwa.RS256()))

	privateSet := jwk.NewSet()
	require.NoError(t, privateSet.AddKey(signingKey))
	publicSet, err := jwk.PublicSetOf(privateSet)
	require.NoError(t, err)

	issuer := &testIssuer{
		signingKey: signingKey,
		publicSet:  publicSet,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(issuer.publicSet); err != nil {
			t.Errorf("encode JWKS: %v", err)
		}
	})
	issuer.server = httptest.NewTLSServer(mux)
	t.Cleanup(issuer.server.Close)
	issuer.issuer = issuer.server.URL
	issuer.jwksURL = issuer.server.URL + "/jwks"

	return issuer
}

func (i *testIssuer) provider(audience string) oidc.Provider {
	return oidc.Provider{
		Issuer:    i.issuer,
		Audiences: []string{audience},
		JWKSURL:   i.jwksURL,
	}
}

func (i *testIssuer) sign(t *testing.T, req tokenRequest) string {
	t.Helper()

	token, err := jwt.NewBuilder().
		Issuer(i.issuer).
		Subject(req.subject).
		Audience(req.audiences).
		IssuedAt(fixedTestTime().Add(-time.Minute)).
		Expiration(fixedTestTime().Add(time.Hour)).
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), i.signingKey))
	require.NoError(t, err)

	return string(signed)
}

func bearer(token string) string {
	return "Bearer " + token
}

func fixedTestTime() time.Time {
	return time.Date(2026, time.May, 7, 20, 45, 0, 0, time.UTC)
}
