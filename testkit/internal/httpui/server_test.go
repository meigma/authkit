package httpui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			wantBody:   "API token login",
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
			name: "API token is not a runtime bearer token",
			req: newAuthorizedRequest(
				httptest.NewRequest(http.MethodGet, "/new", nil),
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

func TestServerRejectsMissingCSRFToken(t *testing.T) {
	server := newTestServer(t, testPasteID)
	browser := exchangeAccessCookie(t, server)

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
			name: "paste create",
			req: func() *http.Request {
				req := newPostFormRequest(t, "/pastes", url.Values{
					"body": {"hello"},
				})
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

	auth *authflow.Runtime
}

func newTestServer(t *testing.T, ids ...string) *testServer {
	t.Helper()

	sequence := sequentialIDs(ids...)
	service, err := paste.NewService(
		testkitmemory.NewStore(),
		paste.WithIDGenerator(sequence.next),
		paste.WithClock(fixedTime),
	)
	require.NoError(t, err)

	authRuntime, err := authflow.NewRuntime(
		context.Background(),
		authmemory.NewStore(),
		authflow.WithClock(fixedTime),
	)
	require.NoError(t, err)
	server, err := NewServer(service, authRuntime)
	require.NoError(t, err)

	return &testServer{
		Server: server,
		auth:   authRuntime,
	}
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
