package authflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/httpauth"
	"github.com/meigma/authkit/store/memory"
)

func TestRuntimeExchangesSeedAPITokenForAccessJWT(t *testing.T) {
	runtime := newTestRuntime(t)

	result, err := runtime.ExchangeAPIToken(context.Background(), runtime.SeedAPIToken)
	require.NoError(t, err)

	assert.Equal(t, runtime.Principal.ID, result.Principal.ID)
	assert.Equal(t, runtime.Principal.ID, result.AccessToken.PrincipalID)
	assert.Equal(t, fixedTime().Add(AccessTokenTTL), result.AccessToken.ExpiresAt)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", bearer(result.AccessToken.Plaintext))
	runtime.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		principal, ok := httpauth.PrincipalFromContext(req.Context())
		assert.True(t, ok)
		if ok {
			assert.Equal(t, runtime.Principal.ID, principal.ID)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusNoContent, recorder.Code)
}

func TestRuntimeRejectsDirectAPITokenAsProtectedBearer(t *testing.T) {
	runtime := newTestRuntime(t)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", bearer(runtime.SeedAPIToken))
	runtime.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusSeeOther, recorder.Code)
	assert.Equal(t, LoginPath, recorder.Header().Get("Location"))
	assert.Equal(t, -1, findSetCookie(t, recorder, CookieName).MaxAge)
}

func TestRuntimeRejectsInvalidAPITokenExchange(t *testing.T) {
	runtime := newTestRuntime(t)

	_, err := runtime.ExchangeAPIToken(context.Background(), "invalid")

	require.ErrorIs(t, err, authkit.ErrUnauthenticated)
}

func TestRuntimeReusesBootstrapPrincipal(t *testing.T) {
	store := memory.NewStore()
	first, err := NewRuntime(context.Background(), store, WithClock(fixedTime))
	require.NoError(t, err)
	second, err := NewRuntime(context.Background(), store, WithClock(fixedTime))
	require.NoError(t, err)

	assert.Equal(t, first.Principal.ID, second.Principal.ID)
	principals, err := store.ListPrincipals(context.Background())
	require.NoError(t, err)
	assert.Len(t, principals, 1)
}

func newTestRuntime(t *testing.T) *Runtime {
	t.Helper()

	runtime, err := NewRuntime(context.Background(), memory.NewStore(), WithClock(fixedTime))
	require.NoError(t, err)

	return runtime
}

func findSetCookie(t *testing.T, recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()

	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	require.Failf(t, "missing cookie", "cookie %q was not set", name)

	return nil
}

func bearer(token string) string {
	return "Bearer " + token
}

func fixedTime() time.Time {
	return time.Date(2026, time.May, 14, 10, 0, 0, 0, time.UTC)
}
