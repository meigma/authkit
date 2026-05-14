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

	"github.com/meigma/authkit/apikey"
)

const (
	linkedOIDCSubject = "oidc-user-123"
	testAudience      = "notes-api"
)

func TestNotesAppAuthorizesRequests(t *testing.T) {
	tc := newMixedTestContext(t)
	accessToken := exchangeAccessToken(t, tc.app, tc.app.seedToken)

	tests := []struct {
		name          string
		path          string
		authorization string
		wantStatus    int
		wantBody      string
	}{
		{
			name:          "allows access JWT to read allowed note",
			path:          "/notes/allowed",
			authorization: bearer(accessToken),
			wantStatus:    http.StatusOK,
			wantBody:      "This note is readable by the seeded service principal.\n",
		},
		{
			name:          "denies access JWT for note outside policy",
			path:          "/notes/denied",
			authorization: bearer(accessToken),
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
			name:          "rejects direct seed API token",
			path:          "/notes/allowed",
			authorization: bearer(tc.app.seedToken),
			wantStatus:    http.StatusUnauthorized,
			wantBody:      "Unauthorized\n",
		},
		{
			name:          "rejects direct unlinked API token",
			path:          "/notes/allowed",
			authorization: bearer(tc.unlinkedAPIToken),
			wantStatus:    http.StatusUnauthorized,
			wantBody:      "Unauthorized\n",
		},
		{
			name:          "rejects direct OIDC bearer token",
			path:          "/notes/allowed",
			authorization: bearer(tc.linkedOIDCToken),
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

func TestNotesAppExchangesAPITokenForAccessJWT(t *testing.T) {
	tc := newMixedTestContext(t)
	accessToken := exchangeAccessToken(t, tc.app, tc.app.seedToken)
	req := httptest.NewRequest(http.MethodGet, "/notes/allowed", nil)
	req.Header.Set("Authorization", bearer(accessToken))

	recorder := httptest.NewRecorder()
	tc.app.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "This note is readable by the seeded service principal.\n", recorder.Body.String())
}

func TestNotesAppRejectsInvalidExchangeCredential(t *testing.T) {
	tc := newMixedTestContext(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	req.Header.Set("Authorization", bearer("invalid"))

	recorder := httptest.NewRecorder()
	tc.app.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Equal(t, "Unauthorized\n", recorder.Body.String())
}

type mixedTestContext struct {
	app              *notesApp
	linkedOIDCToken  string
	unlinkedAPIToken string
}

func newMixedTestContext(t *testing.T) mixedTestContext {
	t.Helper()

	ctx := context.Background()
	now := fixedTestTime()
	issuer := newTestIssuer(t)
	app, err := newNotesApp(
		ctx,
		withClock(func() time.Time {
			return now
		}),
	)
	require.NoError(t, err)

	return mixedTestContext{
		app: app,
		linkedOIDCToken: issuer.sign(
			t,
			tokenRequest{subject: linkedOIDCSubject, audiences: []string{testAudience}},
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

func exchangeAccessToken(t *testing.T, app *notesApp, apiToken string) string {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	req.Header.Set("Authorization", bearer(apiToken))

	recorder := httptest.NewRecorder()
	app.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)
	var response exchangeResponse
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&response))
	require.NotEmpty(t, response.Value)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, fixedTestTime().Add(accessJWTTTL), response.ExpiresAt)

	return response.Value
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
