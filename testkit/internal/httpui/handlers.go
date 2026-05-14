package httpui

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/testkit/internal/authflow"
	"github.com/meigma/authkit/testkit/internal/paste"
)

const (
	contentTypeHeader = "Content-Type"
	htmlContentType   = "text/html; charset=utf-8"
	plainContentType  = "text/plain; charset=utf-8"
	formBodyOverhead  = 8 * 1024
	loginFormMaxBytes = 16 * 1024
	pageError         = "error"
	pageIndex         = "index"
	pageLogin         = "login"
	pageNew           = "new"
	pagePaste         = "paste"
	pasteIDPathValue  = "id"
)

type pageData struct {
	Title     string
	Pastes    []paste.Paste
	Paste     paste.Paste
	Form      pasteForm
	CSRFToken string
	Error     string
}

type pasteForm struct {
	Title  string
	Body   string
	Syntax string
}

func (s *Server) handleIndex(w http.ResponseWriter, req *http.Request) {
	pastes, err := s.pastes.ListRecent(req.Context(), paste.DefaultRecentLimit)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, "Could not load recent pastes.")

		return
	}

	s.render(w, http.StatusOK, pageIndex, pageData{
		Title:  "Recent pastes",
		Pastes: pastes,
	})
}

func (s *Server) handleNew(w http.ResponseWriter, req *http.Request) {
	s.renderNew(w, req, http.StatusOK, pasteForm{}, "")
}

func (s *Server) handleLogin(w http.ResponseWriter, req *http.Request) {
	s.renderLogin(w, req, http.StatusOK, "")
}

func (s *Server) handleExchangeAPIToken(w http.ResponseWriter, req *http.Request) {
	rawToken, ok := s.exchangeTokenInput(
		w,
		req,
		"api_token",
		"Could not read API token.",
		"API token is required.",
	)
	if !ok {
		return
	}

	result, err := s.auth.ExchangeAPIToken(req.Context(), rawToken)
	if err != nil {
		s.renderExchangeError(w, req, err)

		return
	}

	authflow.SetAccessCookie(w, result.AccessToken)
	http.Redirect(w, req, "/new", http.StatusSeeOther)
}

func (s *Server) handleExchangeOIDCToken(w http.ResponseWriter, req *http.Request) {
	rawToken, ok := s.exchangeTokenInput(
		w,
		req,
		"oidc_token",
		"Could not read OIDC token.",
		"OIDC token is required.",
	)
	if !ok {
		return
	}

	result, err := s.auth.ExchangeOIDCToken(req.Context(), rawToken)
	if err != nil {
		s.renderOIDCExchangeError(w, req, err)

		return
	}

	authflow.SetAccessCookie(w, result.AccessToken)
	http.Redirect(w, req, "/new", http.StatusSeeOther)
}

func (s *Server) exchangeTokenInput(
	w http.ResponseWriter,
	req *http.Request,
	field string,
	readError string,
	requiredError string,
) (string, bool) {
	req.Body = http.MaxBytesReader(w, req.Body, loginFormMaxBytes)
	if err := req.ParseForm(); err != nil {
		s.renderLogin(w, req, http.StatusBadRequest, readError)

		return "", false
	}
	if err := s.csrf.validate(req); err != nil {
		s.renderLogin(w, req, http.StatusForbidden, "Could not validate form.")

		return "", false
	}

	rawToken := strings.TrimSpace(req.PostFormValue(field))
	if rawToken == "" {
		rawToken = bearerToken(req)
	}
	if rawToken == "" {
		s.renderLogin(w, req, http.StatusUnauthorized, requiredError)

		return "", false
	}

	return rawToken, true
}

func (s *Server) handleLogout(w http.ResponseWriter, req *http.Request) {
	req.Body = http.MaxBytesReader(w, req.Body, loginFormMaxBytes)
	if err := req.ParseForm(); err != nil {
		s.renderError(w, http.StatusBadRequest, "Could not read logout form.")

		return
	}
	if err := s.csrf.validate(req); err != nil {
		s.renderError(w, http.StatusForbidden, "Could not validate form.")

		return
	}

	authflow.ClearAccessCookie(w)
	http.Redirect(w, req, "/", http.StatusSeeOther)
}

func (s *Server) handleCreate(w http.ResponseWriter, req *http.Request) {
	req.Body = http.MaxBytesReader(w, req.Body, int64(paste.DefaultMaxBodyBytes+formBodyOverhead))
	if err := req.ParseForm(); err != nil {
		s.renderNew(w, req, http.StatusBadRequest, pasteForm{}, "Could not read paste form.")

		return
	}
	if err := s.csrf.validate(req); err != nil {
		s.renderNew(w, req, http.StatusForbidden, pasteForm{}, "Could not validate form.")

		return
	}

	form := pasteForm{
		Title:  req.PostFormValue("title"),
		Body:   req.PostFormValue("body"),
		Syntax: req.PostFormValue("syntax"),
	}
	created, err := s.pastes.Create(req.Context(), paste.CreatePasteRequest{
		Title:  form.Title,
		Body:   form.Body,
		Syntax: form.Syntax,
	})
	if err != nil {
		s.renderCreateError(w, req, form, err)

		return
	}

	http.Redirect(w, req, pastePath(created.ID), http.StatusSeeOther)
}

func (s *Server) handlePaste(w http.ResponseWriter, req *http.Request) {
	found, err := s.pastes.Read(req.Context(), req.PathValue(pasteIDPathValue))
	if err != nil {
		s.renderReadError(w, err)

		return
	}

	s.render(w, http.StatusOK, pagePaste, pageData{
		Title: found.Title,
		Paste: found,
	})
}

func (s *Server) handleRaw(w http.ResponseWriter, req *http.Request) {
	found, err := s.pastes.Read(req.Context(), req.PathValue(pasteIDPathValue))
	if err != nil {
		if errors.Is(err, paste.ErrPasteNotFound) {
			http.NotFound(w, req)

			return
		}
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	w.Header().Set(contentTypeHeader, plainContentType)
	if _, err := w.Write([]byte(found.Body)); err != nil {
		return
	}
}

func (s *Server) withAccessCookie(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "" {
			next.ServeHTTP(w, req)

			return
		}

		cookie, err := req.Cookie(authflow.CookieName)
		if err != nil || strings.TrimSpace(cookie.Value) == "" {
			next.ServeHTTP(w, req)

			return
		}

		authedReq := req.Clone(req.Context())
		authedReq.Header = req.Header.Clone()
		authedReq.Header.Set("Authorization", "Bearer "+cookie.Value)
		next.ServeHTTP(w, authedReq)
	})
}

func (s *Server) renderCreateError(w http.ResponseWriter, req *http.Request, form pasteForm, err error) {
	switch {
	case errors.Is(err, paste.ErrEmptyBody):
		s.renderNew(w, req, http.StatusBadRequest, form, "Paste body is required.")
	case isBodyTooLarge(err):
		s.renderNew(w, req, http.StatusRequestEntityTooLarge, form, "Paste body is too large.")
	default:
		s.renderError(w, http.StatusInternalServerError, "Could not create paste.")
	}
}

func (s *Server) renderExchangeError(w http.ResponseWriter, req *http.Request, err error) {
	if errors.Is(err, authkit.ErrUnauthenticated) {
		s.renderLogin(w, req, http.StatusUnauthorized, "API token is invalid.")

		return
	}

	s.renderError(w, http.StatusInternalServerError, "Could not exchange API token.")
}

func (s *Server) renderOIDCExchangeError(w http.ResponseWriter, req *http.Request, err error) {
	if errors.Is(err, authkit.ErrUnauthenticated) || errors.Is(err, authkit.ErrUnresolvedIdentity) {
		s.renderLogin(w, req, http.StatusUnauthorized, "OIDC token is invalid.")

		return
	}

	s.renderError(w, http.StatusInternalServerError, "Could not exchange OIDC token.")
}

func (s *Server) renderReadError(w http.ResponseWriter, err error) {
	if errors.Is(err, paste.ErrPasteNotFound) {
		s.renderError(w, http.StatusNotFound, "Paste not found.")

		return
	}

	s.renderError(w, http.StatusInternalServerError, "Could not load paste.")
}

func (s *Server) renderNew(
	w http.ResponseWriter,
	req *http.Request,
	status int,
	form pasteForm,
	message string,
) {
	token, err := s.csrf.token(w, req)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, "Could not prepare form.")

		return
	}

	s.render(w, status, pageNew, pageData{
		Title:     "New paste",
		Form:      form,
		CSRFToken: token,
		Error:     message,
	})
}

func (s *Server) renderLogin(w http.ResponseWriter, req *http.Request, status int, message string) {
	token, err := s.csrf.token(w, req)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, "Could not prepare form.")

		return
	}

	s.render(w, status, pageLogin, pageData{
		Title:     "Sign in",
		CSRFToken: token,
		Error:     message,
	})
}

func (s *Server) renderError(w http.ResponseWriter, status int, message string) {
	s.render(w, status, pageError, pageData{
		Title: http.StatusText(status),
		Error: message,
	})
}

func (s *Server) render(w http.ResponseWriter, status int, page string, data pageData) {
	var buf bytes.Buffer
	if err := s.templates.execute(&buf, page, data); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	w.Header().Set(contentTypeHeader, htmlContentType)
	w.WriteHeader(status)
	if _, err := w.Write(buf.Bytes()); err != nil {
		return
	}
}

func isBodyTooLarge(err error) bool {
	var bodyErr paste.BodyTooLargeError

	return errors.As(err, &bodyErr)
}

func pastePath(id string) string {
	return fmt.Sprintf("/p/%s", url.PathEscape(id))
}

func bearerToken(req *http.Request) string {
	header := req.Header.Get("Authorization")
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}

	return parts[1]
}
