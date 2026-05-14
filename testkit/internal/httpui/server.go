package httpui

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"

	"github.com/meigma/authkit/testkit/internal/authflow"
	"github.com/meigma/authkit/testkit/internal/paste"
)

const (
	staticDir = "static"
	staticURL = "/static/"
)

// Server serves the testkit pastebin UI.
type Server struct {
	handler   http.Handler
	auth      *authflow.Runtime
	csrf      csrfProtector
	pastes    *paste.Service
	templates *templateSet
}

// NewServer constructs a testkit HTTP UI server.
func NewServer(pastes *paste.Service, auth *authflow.Runtime) (*Server, error) {
	if pastes == nil {
		return nil, errors.New("httpui: paste service is required")
	}
	if auth == nil {
		return nil, errors.New("httpui: auth runtime is required")
	}

	templates, err := newTemplateSet()
	if err != nil {
		return nil, err
	}

	staticFiles, err := fs.Sub(content, staticDir)
	if err != nil {
		return nil, fmt.Errorf("httpui: prepare static assets: %w", err)
	}

	server := &Server{
		auth:      auth,
		csrf:      newCSRFProtector(),
		pastes:    pastes,
		templates: templates,
	}
	mux := http.NewServeMux()
	mux.Handle("GET "+staticURL, http.StripPrefix(staticURL, http.FileServer(http.FS(staticFiles))))
	mux.HandleFunc("GET /{$}", server.handleIndex)
	mux.HandleFunc("GET /login", server.handleLogin)
	mux.HandleFunc("POST /auth/token", server.handleExchangeAPIToken)
	mux.HandleFunc("POST /auth/oidc-token", server.handleExchangeOIDCToken)
	mux.HandleFunc("POST /logout", server.handleLogout)
	mux.Handle("GET /new", server.withAccessCookie(auth.Authenticate(http.HandlerFunc(server.handleNew))))
	mux.Handle("POST /pastes", server.withAccessCookie(auth.Authenticate(http.HandlerFunc(server.handleCreate))))
	mux.HandleFunc("GET /p/{id}", server.handlePaste)
	mux.HandleFunc("GET /raw/{id}", server.handleRaw)
	server.handler = mux

	return server, nil
}

// ServeHTTP serves an HTTP request.
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.handler.ServeHTTP(w, req)
}
