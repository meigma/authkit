package httpui

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/oidc"
	authmemory "github.com/meigma/authkit/store/memory"
	"github.com/meigma/authkit/testkit/internal/authflow"
	"github.com/meigma/authkit/testkit/internal/paste"
	testkitmemory "github.com/meigma/authkit/testkit/internal/store/memory"
)

const testPasteID = "paste-1"

func TestServerRendersPublicPages(t *testing.T) {
	server := newTestServer(t, testPasteID)

	tests := []struct {
		name       string
		path       string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "index",
			path:       "/",
			wantStatus: http.StatusOK,
			wantBody:   "No pastes yet.",
		},
		{
			name:       "login form",
			path:       "/login",
			wantStatus: http.StatusOK,
			wantBody:   "Sign in",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tt.path, nil))

			assert.Equal(t, tt.wantStatus, recorder.Code)
			assert.Contains(t, recorder.Body.String(), tt.wantBody)
			assert.Equal(t, htmlContentType, recorder.Header().Get(contentTypeHeader))
		})
	}

	loginRecorder := httptest.NewRecorder()
	server.ServeHTTP(loginRecorder, httptest.NewRequest(http.MethodGet, "/login", nil))
	assert.Contains(t, loginRecorder.Body.String(), `name="csrf_token"`)
	assert.NotEmpty(t, findCookie(t, loginRecorder, csrfCookieName).Value)
}

func TestServerRequiresAuthenticationForPasteCreation(t *testing.T) {
	server := newTestServer(t, testPasteID)

	tests := []struct {
		name string
		req  *http.Request
	}{
		{
			name: "new paste form",
			req:  httptest.NewRequest(http.MethodGet, "/new", nil),
		},
		{
			name: "create paste",
			req: newPostFormRequest(t, "/pastes", url.Values{
				"body": {"hello"},
			}),
		},
		{
			name: "edit paste",
			req:  httptest.NewRequest(http.MethodGet, "/p/"+testPasteID+"/edit", nil),
		},
		{
			name: "update paste",
			req: newPostFormRequest(t, "/p/"+testPasteID+"/edit", url.Values{
				"body": {"updated"},
			}),
		},
		{
			name: "delete paste",
			req:  newPostFormRequest(t, "/p/"+testPasteID+"/delete", nil),
		},
		{
			name: "API token is not a runtime bearer token",
			req: newAuthorizedRequest(
				httptest.NewRequest(http.MethodGet, "/new", nil),
				bearer(server.auth.SeedAPIToken),
			),
		},
		{
			name: "API token is not an edit bearer token",
			req: newAuthorizedRequest(
				httptest.NewRequest(http.MethodGet, "/p/"+testPasteID+"/edit", nil),
				bearer(server.auth.SeedAPIToken),
			),
		},
		{
			name: "API token is not an access cookie",
			req: newCookieRequest(
				httptest.NewRequest(http.MethodGet, "/new", nil),
				&http.Cookie{Name: authflow.CookieName, Value: server.auth.SeedAPIToken},
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, tt.req)

			assert.Equal(t, http.StatusSeeOther, recorder.Code)
			assert.Equal(t, authflow.LoginPath, recorder.Header().Get("Location"))
		})
	}
}

func TestServerRejectsDirectOIDCTokensForPasteRoutes(t *testing.T) {
	server, token := newOIDCTestServer(t, testPasteID)
	csrfCookie := csrfFromLogin(t, server)

	tests := []struct {
		name string
		req  *http.Request
	}{
		{
			name: "new paste bearer",
			req: newAuthorizedRequest(
				httptest.NewRequest(http.MethodGet, "/new", nil),
				bearer(token),
			),
		},
		{
			name: "new paste cookie",
			req: newCookieRequest(
				httptest.NewRequest(http.MethodGet, "/new", nil),
				&http.Cookie{Name: authflow.CookieName, Value: token},
			),
		},
		{
			name: "edit paste bearer",
			req: newAuthorizedRequest(
				httptest.NewRequest(http.MethodGet, "/p/"+testPasteID+"/edit", nil),
				bearer(token),
			),
		},
		{
			name: "create paste bearer",
			req: func() *http.Request {
				req := newAuthorizedRequest(
					newPostFormRequest(t, "/pastes", url.Values{
						"body":        {"hello"},
						csrfFieldName: {csrfCookie.Value},
					}),
					bearer(token),
				)
				req.AddCookie(csrfCookie)

				return req
			}(),
		},
		{
			name: "create paste cookie",
			req: func() *http.Request {
				req := newPostFormRequest(t, "/pastes", url.Values{
					"body":        {"hello"},
					csrfFieldName: {csrfCookie.Value},
				})
				req.AddCookie(csrfCookie)
				req.AddCookie(&http.Cookie{Name: authflow.CookieName, Value: token})

				return req
			}(),
		},
		{
			name: "delete paste bearer",
			req: func() *http.Request {
				req := newAuthorizedRequest(
					newPostFormRequest(t, "/p/"+testPasteID+"/delete", url.Values{
						csrfFieldName: {csrfCookie.Value},
					}),
					bearer(token),
				)
				req.AddCookie(csrfCookie)

				return req
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, tt.req)

			assert.Equal(t, http.StatusSeeOther, recorder.Code)
			assert.Equal(t, authflow.LoginPath, recorder.Header().Get("Location"))
		})
	}
}

func TestServerExchangesAPITokenAndCreatesPaste(t *testing.T) {
	server := newTestServer(t, testPasteID)
	browser := exchangeAccessCookie(t, server)

	newRecorder := httptest.NewRecorder()
	newReq := httptest.NewRequest(http.MethodGet, "/new", nil)
	newReq.AddCookie(browser.access)
	newReq.AddCookie(browser.csrf)
	server.ServeHTTP(newRecorder, newReq)

	require.Equal(t, http.StatusOK, newRecorder.Code)
	assert.Contains(t, newRecorder.Body.String(), "Create paste")
	assert.Contains(t, newRecorder.Body.String(), `name="csrf_token"`)

	createRecorder := httptest.NewRecorder()
	createReq := newPostFormRequest(t, "/pastes", url.Values{
		"title":       {"Example title"},
		"body":        {"hello from the paste"},
		"syntax":      {"text"},
		csrfFieldName: {browser.csrf.Value},
	})
	createReq.AddCookie(browser.access)
	createReq.AddCookie(browser.csrf)
	server.ServeHTTP(createRecorder, createReq)

	require.Equal(t, http.StatusSeeOther, createRecorder.Code)
	assert.Equal(t, "/p/"+testPasteID, createRecorder.Header().Get("Location"))

	pasteRecorder := httptest.NewRecorder()
	server.ServeHTTP(pasteRecorder, httptest.NewRequest(http.MethodGet, "/p/"+testPasteID, nil))

	assert.Equal(t, http.StatusOK, pasteRecorder.Code)
	assert.Contains(t, pasteRecorder.Body.String(), "Example title")
	assert.Contains(t, pasteRecorder.Body.String(), "hello from the paste")
	assert.Contains(t, pasteRecorder.Body.String(), "text")
	created, err := server.pastes.Read(context.Background(), testPasteID)
	require.NoError(t, err)
	assert.Equal(t, server.auth.Principal.ID, created.OwnerPrincipalID)

	rawRecorder := httptest.NewRecorder()
	server.ServeHTTP(rawRecorder, httptest.NewRequest(http.MethodGet, "/raw/"+testPasteID, nil))

	assert.Equal(t, http.StatusOK, rawRecorder.Code)
	assert.Equal(t, plainContentType, rawRecorder.Header().Get(contentTypeHeader))
	assert.Equal(t, "hello from the paste", rawRecorder.Body.String())

	indexRecorder := httptest.NewRecorder()
	server.ServeHTTP(indexRecorder, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusOK, indexRecorder.Code)
	assert.Contains(t, indexRecorder.Body.String(), "Example title")
	assert.Contains(t, indexRecorder.Body.String(), "/p/"+testPasteID)
}

func TestServerExchangesOIDCTokenAndCreatesPaste(t *testing.T) {
	server, token := newOIDCTestServer(t, testPasteID)
	csrfCookie := csrfFromLogin(t, server)
	req := newPostFormRequest(t, "/auth/oidc-token", url.Values{
		"oidc_token":  {token},
		csrfFieldName: {csrfCookie.Value},
	})
	req.AddCookie(csrfCookie)
	exchangeRecorder := httptest.NewRecorder()
	server.ServeHTTP(exchangeRecorder, req)

	require.Equal(t, http.StatusSeeOther, exchangeRecorder.Code)
	assert.Equal(t, "/new", exchangeRecorder.Header().Get("Location"))
	accessCookie := findCookie(t, exchangeRecorder, authflow.CookieName)
	assert.NotEmpty(t, accessCookie.Value)

	createRecorder := httptest.NewRecorder()
	createReq := newPostFormRequest(t, "/pastes", url.Values{
		"title":       {"OIDC paste"},
		"body":        {"created with OIDC exchange"},
		"syntax":      {"text"},
		csrfFieldName: {csrfCookie.Value},
	})
	createReq.AddCookie(accessCookie)
	createReq.AddCookie(csrfCookie)
	server.ServeHTTP(createRecorder, createReq)

	require.Equal(t, http.StatusSeeOther, createRecorder.Code)
	assert.Equal(t, "/p/"+testPasteID, createRecorder.Header().Get("Location"))

	pasteRecorder := httptest.NewRecorder()
	server.ServeHTTP(pasteRecorder, httptest.NewRequest(http.MethodGet, "/p/"+testPasteID, nil))

	assert.Equal(t, http.StatusOK, pasteRecorder.Code)
	assert.Contains(t, pasteRecorder.Body.String(), "OIDC paste")
	assert.Contains(t, pasteRecorder.Body.String(), "created with OIDC exchange")
	created, err := server.pastes.Read(context.Background(), testPasteID)
	require.NoError(t, err)
	assert.Equal(t, principalByDisplayName(t, server, "Ada Lovelace").ID, created.OwnerPrincipalID)
}

func TestServerOwnerEditsAndDeletesPaste(t *testing.T) {
	server := newTestServer(t, testPasteID)
	browser := exchangeAccessCookie(t, server)
	createPaste(t, server, browser, url.Values{
		"title":  {"Original"},
		"body":   {"original body"},
		"syntax": {"text"},
	})

	editRecorder := httptest.NewRecorder()
	editReq := httptest.NewRequest(http.MethodGet, "/p/"+testPasteID+"/edit", nil)
	editReq.AddCookie(browser.access)
	server.ServeHTTP(editRecorder, editReq)

	require.Equal(t, http.StatusOK, editRecorder.Code)
	assert.Contains(t, editRecorder.Body.String(), "Edit paste")
	assert.Contains(t, editRecorder.Body.String(), "original body")
	assert.Contains(t, editRecorder.Body.String(), `name="csrf_token"`)

	updateRecorder := httptest.NewRecorder()
	updateReq := newPostFormRequest(t, "/p/"+testPasteID+"/edit", url.Values{
		"title":       {"Updated"},
		"body":        {"updated body"},
		"syntax":      {"markdown"},
		csrfFieldName: {browser.csrf.Value},
	})
	updateReq.AddCookie(browser.access)
	updateReq.AddCookie(browser.csrf)
	server.ServeHTTP(updateRecorder, updateReq)

	require.Equal(t, http.StatusSeeOther, updateRecorder.Code)
	assert.Equal(t, "/p/"+testPasteID, updateRecorder.Header().Get("Location"))
	updated, err := server.pastes.Read(context.Background(), testPasteID)
	require.NoError(t, err)
	assert.Equal(t, "Updated", updated.Title)
	assert.Equal(t, "updated body", updated.Body)
	assert.Equal(t, "markdown", updated.Syntax)
	assert.Equal(t, server.auth.Principal.ID, updated.OwnerPrincipalID)

	deleteRecorder := httptest.NewRecorder()
	deleteReq := newPostFormRequest(t, "/p/"+testPasteID+"/delete", url.Values{
		csrfFieldName: {browser.csrf.Value},
	})
	deleteReq.AddCookie(browser.access)
	deleteReq.AddCookie(browser.csrf)
	server.ServeHTTP(deleteRecorder, deleteReq)

	require.Equal(t, http.StatusSeeOther, deleteRecorder.Code)
	assert.Equal(t, "/", deleteRecorder.Header().Get("Location"))
	_, err = server.pastes.Read(context.Background(), testPasteID)
	require.ErrorIs(t, err, paste.ErrPasteNotFound)
}

func TestServerRejectsNonOwnerEditAndDelete(t *testing.T) {
	server, oidcToken := newOIDCTestServer(t, testPasteID)
	ownerBrowser := exchangeAccessCookie(t, server)
	createPaste(t, server, ownerBrowser, url.Values{
		"title": {"Owner paste"},
		"body":  {"owned body"},
	})
	nonOwnerBrowser := exchangeOIDCAccessCookie(t, server, oidcToken)

	tests := []struct {
		name string
		req  *http.Request
	}{
		{
			name: "edit page",
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/p/"+testPasteID+"/edit", nil)
				req.AddCookie(nonOwnerBrowser.access)

				return req
			}(),
		},
		{
			name: "update",
			req: func() *http.Request {
				req := newPostFormRequest(t, "/p/"+testPasteID+"/edit", url.Values{
					"title":       {"Stolen"},
					"body":        {"changed"},
					csrfFieldName: {nonOwnerBrowser.csrf.Value},
				})
				req.AddCookie(nonOwnerBrowser.access)
				req.AddCookie(nonOwnerBrowser.csrf)

				return req
			}(),
		},
		{
			name: "delete",
			req: func() *http.Request {
				req := newPostFormRequest(t, "/p/"+testPasteID+"/delete", url.Values{
					csrfFieldName: {nonOwnerBrowser.csrf.Value},
				})
				req.AddCookie(nonOwnerBrowser.access)
				req.AddCookie(nonOwnerBrowser.csrf)

				return req
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, tt.req)

			assert.Equal(t, http.StatusForbidden, recorder.Code)
		})
	}

	found, err := server.pastes.Read(context.Background(), testPasteID)
	require.NoError(t, err)
	assert.Equal(t, "Owner paste", found.Title)
	assert.Equal(t, "owned body", found.Body)
	assert.Equal(t, server.auth.Principal.ID, found.OwnerPrincipalID)
}

func TestServerRejectsInvalidAPITokenExchange(t *testing.T) {
	server := newTestServer(t, testPasteID)
	csrfCookie := csrfFromLogin(t, server)

	recorder := httptest.NewRecorder()
	req := newPostFormRequest(t, "/auth/token", url.Values{
		"api_token":   {"invalid"},
		csrfFieldName: {csrfCookie.Value},
	})
	req.AddCookie(csrfCookie)
	server.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "API token is invalid.")
	assert.NotContains(t, recorder.Body.String(), `value="invalid"`)
}

func TestServerRejectsEmptyPasteBody(t *testing.T) {
	server := newTestServer(t, testPasteID)
	browser := exchangeAccessCookie(t, server)

	req := newPostFormRequest(t, "/pastes", url.Values{
		"title":       {"Empty paste"},
		"body":        {" \n\t "},
		csrfFieldName: {browser.csrf.Value},
	})
	req.AddCookie(browser.access)
	req.AddCookie(browser.csrf)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "Paste body is required.")
	assert.Contains(t, recorder.Body.String(), "Empty paste")
}

func TestServerLogoutClearsAccessCookie(t *testing.T) {
	server := newTestServer(t, testPasteID)
	browser := exchangeAccessCookie(t, server)

	req := newPostFormRequest(t, "/logout", url.Values{
		csrfFieldName: {browser.csrf.Value},
	})
	req.AddCookie(browser.access)
	req.AddCookie(browser.csrf)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusSeeOther, recorder.Code)
	assert.Equal(t, "/", recorder.Header().Get("Location"))
	cleared := findCookie(t, recorder, authflow.CookieName)
	assert.Equal(t, -1, cleared.MaxAge)
	assert.Empty(t, cleared.Value)
}

func TestServerReturnsNotFoundForMissingPaste(t *testing.T) {
	server := newTestServer(t, testPasteID)

	tests := []struct {
		name string
		path string
	}{
		{name: "paste page", path: "/p/missing"},
		{name: "raw paste", path: "/raw/missing"},
		{name: "unknown route", path: "/missing"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tt.path, nil))

			assert.Equal(t, http.StatusNotFound, recorder.Code)
		})
	}
}

func TestServerReturnsNotFoundForMissingProtectedPasteActions(t *testing.T) {
	server := newTestServer(t, testPasteID)
	browser := exchangeAccessCookie(t, server)

	tests := []struct {
		name string
		req  *http.Request
	}{
		{
			name: "edit",
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/p/missing/edit", nil)
				req.AddCookie(browser.access)

				return req
			}(),
		},
		{
			name: "update",
			req: func() *http.Request {
				req := newPostFormRequest(t, "/p/missing/edit", url.Values{
					"body":        {"updated"},
					csrfFieldName: {browser.csrf.Value},
				})
				req.AddCookie(browser.access)
				req.AddCookie(browser.csrf)

				return req
			}(),
		},
		{
			name: "delete",
			req: func() *http.Request {
				req := newPostFormRequest(t, "/p/missing/delete", url.Values{
					csrfFieldName: {browser.csrf.Value},
				})
				req.AddCookie(browser.access)
				req.AddCookie(browser.csrf)

				return req
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, tt.req)

			assert.Equal(t, http.StatusNotFound, recorder.Code)
		})
	}
}

func TestServerRejectsMissingCSRFToken(t *testing.T) {
	server := newTestServer(t, testPasteID)
	browser := exchangeAccessCookie(t, server)
	createPaste(t, server, browser, url.Values{
		"body": {"hello"},
	})

	tests := []struct {
		name string
		req  *http.Request
	}{
		{
			name: "API-token exchange",
			req: newPostFormRequest(t, "/auth/token", url.Values{
				"api_token": {server.auth.SeedAPIToken},
			}),
		},
		{
			name: "OIDC-token exchange",
			req: newPostFormRequest(t, "/auth/oidc-token", url.Values{
				"oidc_token": {"not-a-token"},
			}),
		},
		{
			name: "paste create",
			req: func() *http.Request {
				req := newPostFormRequest(t, "/pastes", url.Values{
					"body": {"hello"},
				})
				req.AddCookie(browser.access)

				return req
			}(),
		},
		{
			name: "paste update",
			req: func() *http.Request {
				req := newPostFormRequest(t, "/p/"+testPasteID+"/edit", url.Values{
					"body": {"updated"},
				})
				req.AddCookie(browser.access)

				return req
			}(),
		},
		{
			name: "paste delete",
			req: func() *http.Request {
				req := newPostFormRequest(t, "/p/"+testPasteID+"/delete", nil)
				req.AddCookie(browser.access)

				return req
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, tt.req)

			assert.Equal(t, http.StatusForbidden, recorder.Code)
			assert.Contains(t, recorder.Body.String(), "Could not validate form.")
		})
	}
}

type testServer struct {
	*Server

	auth      *authflow.Runtime
	authStore *authmemory.Store
}

func newTestServer(t *testing.T, ids ...string) *testServer {
	t.Helper()

	return newTestServerWithAuth(t, ids, nil)
}

func newTestServerWithAuth(
	t *testing.T,
	ids []string,
	setupAuthStore func(*testing.T, *authmemory.Store),
	authOptions ...authflow.Option,
) *testServer {
	t.Helper()

	sequence := sequentialIDs(ids...)
	service, err := paste.NewService(
		testkitmemory.NewStore(),
		paste.WithIDGenerator(sequence.next),
		paste.WithClock(fixedTime),
	)
	require.NoError(t, err)

	authStore := authmemory.NewStore()
	if setupAuthStore != nil {
		setupAuthStore(t, authStore)
	}
	runtimeOptions := []authflow.Option{
		authflow.WithClock(fixedTime),
	}
	runtimeOptions = append(runtimeOptions, authOptions...)
	authRuntime, err := authflow.NewRuntime(
		context.Background(),
		authStore,
		runtimeOptions...,
	)
	require.NoError(t, err)
	server, err := NewServer(service, authRuntime)
	require.NoError(t, err)

	return &testServer{
		Server:    server,
		auth:      authRuntime,
		authStore: authStore,
	}
}

func newOIDCTestServer(t *testing.T, ids ...string) (*testServer, string) {
	t.Helper()

	issuer := newTestIssuer(t)
	provider := issuer.provider()
	provider.ForwardedClaims = []authkit.ClaimPath{{"email"}, {"name"}}
	server := newTestServerWithAuth(
		t,
		ids,
		func(t *testing.T, store *authmemory.Store) {
			t.Helper()

			_, err := store.TrustProvider(context.Background(), provider)
			require.NoError(t, err)
		},
		authflow.WithOIDCOptions(oidc.WithHTTPClient(issuer.server.Client())),
	)
	token := issuer.sign(t, oidcTokenRequest{
		subject:   "user-123",
		audiences: []string{testAudience},
		expiresAt: fixedTime().Add(time.Hour),
		claims: map[string]any{
			"email": "ada@example.test",
			"name":  "Ada Lovelace",
		},
	})

	return server, token
}

type browserCookies struct {
	access *http.Cookie
	csrf   *http.Cookie
}

func exchangeAccessCookie(t *testing.T, server *testServer) browserCookies {
	t.Helper()

	csrfCookie := csrfFromLogin(t, server)
	req := newPostFormRequest(t, "/auth/token", url.Values{
		"api_token":   {server.auth.SeedAPIToken},
		csrfFieldName: {csrfCookie.Value},
	})
	req.AddCookie(csrfCookie)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusSeeOther, recorder.Code)
	assert.Equal(t, "/new", recorder.Header().Get("Location"))

	return browserCookies{
		access: findCookie(t, recorder, authflow.CookieName),
		csrf:   csrfCookie,
	}
}

func exchangeOIDCAccessCookie(t *testing.T, server *testServer, token string) browserCookies {
	t.Helper()

	csrfCookie := csrfFromLogin(t, server)
	req := newPostFormRequest(t, "/auth/oidc-token", url.Values{
		"oidc_token":  {token},
		csrfFieldName: {csrfCookie.Value},
	})
	req.AddCookie(csrfCookie)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusSeeOther, recorder.Code)
	assert.Equal(t, "/new", recorder.Header().Get("Location"))

	return browserCookies{
		access: findCookie(t, recorder, authflow.CookieName),
		csrf:   csrfCookie,
	}
}

func createPaste(t *testing.T, server *testServer, browser browserCookies, values url.Values) {
	t.Helper()

	form := maps.Clone(values)
	if form == nil {
		form = url.Values{}
	}
	form[csrfFieldName] = []string{browser.csrf.Value}
	req := newPostFormRequest(t, "/pastes", form)
	req.AddCookie(browser.access)
	req.AddCookie(browser.csrf)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusSeeOther, recorder.Code)
	assert.Equal(t, "/p/"+testPasteID, recorder.Header().Get("Location"))
}

func principalByDisplayName(t *testing.T, server *testServer, displayName string) authkit.Principal {
	t.Helper()

	principals, err := server.authStore.ListPrincipals(context.Background())
	require.NoError(t, err)
	for _, principal := range principals {
		if principal.DisplayName == displayName {
			return principal
		}
	}
	require.Failf(t, "missing principal", "principal %q was not found", displayName)

	return authkit.Principal{}
}

func csrfFromLogin(t *testing.T, server *testServer) *http.Cookie {
	t.Helper()

	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/login", nil))
	require.Equal(t, http.StatusOK, recorder.Code)

	return findCookie(t, recorder, csrfCookieName)
}

func findCookie(t *testing.T, recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()

	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	require.Failf(t, "missing cookie", "cookie %q was not set", name)

	return nil
}

func newPostFormRequest(t *testing.T, path string, values url.Values) *http.Request {
	t.Helper()

	body := ""
	if values != nil {
		body = values.Encode()
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set(contentTypeHeader, "application/x-www-form-urlencoded")

	return req
}

func newAuthorizedRequest(req *http.Request, authorization string) *http.Request {
	req.Header.Set("Authorization", authorization)

	return req
}

func newCookieRequest(req *http.Request, cookie *http.Cookie) *http.Request {
	req.AddCookie(cookie)

	return req
}

func bearer(token string) string {
	return "Bearer " + token
}

type idSequence struct {
	values []string
	nextID int
}

func sequentialIDs(ids ...string) *idSequence {
	return &idSequence{values: ids}
}

func (s *idSequence) next() (string, error) {
	if s.nextID >= len(s.values) {
		return "", errors.New("test: no more IDs")
	}

	id := s.values[s.nextID]
	s.nextID++

	return id, nil
}

func fixedTime() time.Time {
	return time.Date(2026, time.May, 14, 10, 0, 0, 0, time.UTC)
}

const testAudience = "testkit"

type testIssuer struct {
	server     *httptest.Server
	issuer     string
	jwksURL    string
	signingKey jwk.Key
	publicSet  jwk.Set
}

type oidcTokenRequest struct {
	subject   string
	audiences []string
	expiresAt time.Time
	claims    map[string]any
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
		w.Header().Set(contentTypeHeader, "application/json")
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

func (i *testIssuer) provider() oidc.Provider {
	return oidc.Provider{
		Issuer:    i.issuer,
		Audiences: []string{testAudience},
		JWKSURL:   i.jwksURL,
	}
}

func (i *testIssuer) sign(t *testing.T, req oidcTokenRequest) string {
	t.Helper()

	builder := jwt.NewBuilder().
		Issuer(i.issuer).
		Subject(req.subject).
		Audience(req.audiences).
		IssuedAt(fixedTime().Add(-time.Minute)).
		Expiration(req.expiresAt)
	for name, value := range req.claims {
		builder.Claim(name, value)
	}

	token, err := builder.Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), i.signingKey))
	require.NoError(t, err)

	return string(signed)
}
