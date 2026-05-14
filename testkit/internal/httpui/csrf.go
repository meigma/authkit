package httpui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

const (
	csrfCookieName = "testkit_csrf"
	csrfFieldName  = "csrf_token"
	csrfTokenBytes = 32
)

var errInvalidCSRFToken = errors.New("httpui: invalid CSRF token")

type csrfProtector struct{}

func newCSRFProtector() csrfProtector {
	return csrfProtector{}
}

func (csrfProtector) token(w http.ResponseWriter, req *http.Request) (string, error) {
	if cookie, err := req.Cookie(csrfCookieName); err == nil && strings.TrimSpace(cookie.Value) != "" {
		return cookie.Value, nil
	}

	raw := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	return token, nil
}

func (csrfProtector) validate(req *http.Request) error {
	cookie, err := req.Cookie(csrfCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return errInvalidCSRFToken
	}

	formToken := req.PostFormValue(csrfFieldName)
	if formToken == "" {
		return errInvalidCSRFToken
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(formToken)) != 1 {
		return errInvalidCSRFToken
	}

	return nil
}
