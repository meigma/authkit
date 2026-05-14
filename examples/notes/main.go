package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	casbinv3 "github.com/casbin/casbin/v3"
	casbinmodel "github.com/casbin/casbin/v3/model"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/accessjwt"
	"github.com/meigma/authkit/apikey"
	authkitcasbin "github.com/meigma/authkit/casbin"
	"github.com/meigma/authkit/compose"
	"github.com/meigma/authkit/httpauth"
	"github.com/meigma/authkit/store/memory"
)

const (
	defaultAddr             = ":8080"
	readNoteAction          = "note:read"
	noteType                = "note"
	noteIDPathValue         = "noteID"
	allowedNoteID           = "allowed"
	seedTokenTTL            = time.Hour
	accessJWTTTL            = 15 * time.Minute
	accessJWTIssuer         = "https://notes.example.local/authkit"
	accessJWTAudience       = "notes-api"
	accessJWTKeyID          = "notes-example-key"
	rsaKeyBits              = 2048
	serverReadHeaderTimeout = 5 * time.Second
	serverReadTimeout       = 10 * time.Second
	serverWriteTimeout      = 10 * time.Second
	serverIdleTimeout       = 60 * time.Second
)

const casbinModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`

type notesApp struct {
	handler        http.Handler
	store          *memory.Store
	tokenService   *apikey.Service
	accessIssuer   *accessjwt.Issuer
	principal      authkit.Principal
	seedToken      string
	tokenExpiresAt time.Time
	notes          map[string]string
}

type notesAppOptions struct {
	clock func() time.Time
}

type notesAppOption func(*notesAppOptions)

func withClock(clock func() time.Time) notesAppOption {
	return func(opts *notesAppOptions) {
		opts.clock = clock
	}
}

func main() {
	if err := run(context.Background(), os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, out io.Writer) error {
	app, err := newNotesApp(ctx)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "seed API token: %s\n", app.seedToken)
	_, _ = fmt.Fprintf(out, "listening on http://localhost%s\n", defaultAddr)

	server := &http.Server{
		Addr:              defaultAddr,
		Handler:           app,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
	}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

func newNotesApp(ctx context.Context, opts ...notesAppOption) (*notesApp, error) {
	cfg := notesAppOptions{
		clock: time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.clock == nil {
		cfg.clock = time.Now
	}

	store := memory.NewStore()
	tokenService, err := apikey.NewService(store, apikey.WithClock(cfg.clock))
	if err != nil {
		return nil, err
	}

	principal, err := store.CreatePrincipal(ctx, authkit.CreatePrincipalRequest{
		Kind:        authkit.PrincipalKindService,
		DisplayName: "notes service",
	})
	if err != nil {
		return nil, err
	}

	issued, err := tokenService.IssueToken(ctx, apikey.IssueRequest{
		PrincipalID: principal.ID,
		Name:        "notes example token",
		ExpiresAt:   cfg.clock().Add(seedTokenTTL),
	})
	if err != nil {
		return nil, err
	}

	accessIssuer, accessVerifier, err := newAccessJWTIssuerAndVerifier(cfg.clock)
	if err != nil {
		return nil, err
	}

	middleware, err := newNotesMiddleware(store, accessVerifier, principal.ID)
	if err != nil {
		return nil, err
	}

	app := &notesApp{
		store:          store,
		tokenService:   tokenService,
		accessIssuer:   accessIssuer,
		principal:      principal,
		seedToken:      issued.Plaintext,
		tokenExpiresAt: issued.ExpiresAt,
		notes: map[string]string{
			allowedNoteID: "This note is readable by the seeded service principal.",
			"denied":      "The seeded Casbin policy does not grant access to this note.",
		},
	}

	mux := http.NewServeMux()
	mux.Handle("POST /auth/token", http.HandlerFunc(app.exchangeAPIToken))
	mux.Handle(
		"GET /notes/{noteID}",
		middleware.RequireFunc(readNoteAction, func(req *http.Request) (authkit.Resource, error) {
			return authkit.Resource{
				Type: noteType,
				ID:   req.PathValue(noteIDPathValue),
			}, nil
		})(http.HandlerFunc(app.serveNote)),
	)
	app.handler = mux

	return app, nil
}

func newNotesMiddleware(
	store *memory.Store,
	verifier *accessjwt.Verifier,
	principalID string,
) (*httpauth.Middleware, error) {
	enforcer, err := newCasbinEnforcer()
	if err != nil {
		return nil, err
	}
	policyAdded, err := enforcer.AddPolicy(principalID, noteObject(allowedNoteID), readNoteAction)
	if err != nil {
		return nil, err
	}
	if !policyAdded {
		return nil, errors.New("notes: seed policy already exists")
	}

	authorizer, err := authkitcasbin.NewAuthorizer(enforcer)
	if err != nil {
		return nil, err
	}
	auth, err := compose.NewHTTP(compose.HTTPOptions{
		PrincipalAuthenticators: []compose.PrincipalAuthenticatorSpec{
			compose.AccessJWT(verifier, store),
		},
		Authorizer: authorizer,
	})
	if err != nil {
		return nil, err
	}

	return auth.Middleware, nil
}

func (a *notesApp) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	a.handler.ServeHTTP(w, req)
}

func (a *notesApp) exchangeAPIToken(w http.ResponseWriter, req *http.Request) {
	rawToken, err := bearerToken(req)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)

		return
	}

	identity, err := a.tokenService.VerifyToken(req.Context(), rawToken)
	if err != nil {
		writeAuthExchangeError(w, err)

		return
	}

	stored, err := a.store.FindToken(req.Context(), identity.CredentialID)
	if errors.Is(err, apikey.ErrTokenNotFound) {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)

		return
	}
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	principal, err := a.store.FindPrincipal(req.Context(), stored.PrincipalID)
	if errors.Is(err, authkit.ErrPrincipalNotFound) {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)

		return
	}
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	issued, err := a.accessIssuer.IssueToken(req.Context(), accessjwt.IssueRequest{
		PrincipalID: principal.ID,
	})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	//nolint:gosec // The exchange endpoint intentionally returns the newly issued access JWT once.
	if err := json.NewEncoder(w).Encode(exchangeResponse{
		Value:     issued.Plaintext,
		TokenType: "Bearer",
		ExpiresAt: issued.ExpiresAt,
	}); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (a *notesApp) serveNote(w http.ResponseWriter, req *http.Request) {
	principal, ok := httpauth.PrincipalFromContext(req.Context())
	if !ok || principal.ID == "" {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	body, ok := a.notes[req.PathValue(noteIDPathValue)]
	if !ok {
		http.NotFound(w, req)

		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintln(w, body)
}

type exchangeResponse struct {
	Value     string    `json:"access_token"`
	TokenType string    `json:"token_type"`
	ExpiresAt time.Time `json:"expires_at"`
}

func bearerToken(req *http.Request) (string, error) {
	header := req.Header.Get("Authorization")
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("%w: bearer token is required", authkit.ErrUnauthenticated)
	}

	return parts[1], nil
}

func writeAuthExchangeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	if errors.Is(err, authkit.ErrUnauthenticated) {
		status = http.StatusUnauthorized
	}

	http.Error(w, http.StatusText(status), status)
}

func newCasbinEnforcer() (*casbinv3.Enforcer, error) {
	model, err := casbinmodel.NewModelFromString(casbinModel)
	if err != nil {
		return nil, err
	}

	enforcer, err := casbinv3.NewEnforcer(model)
	if err != nil {
		return nil, err
	}

	return enforcer, nil
}

func newAccessJWTIssuerAndVerifier(
	clock func() time.Time,
) (*accessjwt.Issuer, *accessjwt.Verifier, error) {
	rawKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("notes: generate access JWT key: %w", err)
	}
	signingKey, err := jwk.Import(rawKey)
	if err != nil {
		return nil, nil, fmt.Errorf("notes: import access JWT key: %w", err)
	}
	if setErr := signingKey.Set(jwk.KeyIDKey, accessJWTKeyID); setErr != nil {
		return nil, nil, fmt.Errorf("notes: set access JWT key ID: %w", setErr)
	}
	if setErr := signingKey.Set(jwk.AlgorithmKey, jwa.RS256()); setErr != nil {
		return nil, nil, fmt.Errorf("notes: set access JWT key algorithm: %w", setErr)
	}
	publicKey, err := jwk.PublicKeyOf(signingKey)
	if err != nil {
		return nil, nil, fmt.Errorf("notes: derive access JWT public key: %w", err)
	}
	keySet := jwk.NewSet()
	if addErr := keySet.AddKey(publicKey); addErr != nil {
		return nil, nil, fmt.Errorf("notes: build access JWT key set: %w", addErr)
	}

	issuer, err := accessjwt.NewIssuer(accessjwt.IssuerOptions{
		Issuer:     accessJWTIssuer,
		Audience:   accessJWTAudience,
		TTL:        accessJWTTTL,
		SigningKey: signingKey,
		Clock:      clock,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("notes: create access JWT issuer: %w", err)
	}
	verifier, err := accessjwt.NewVerifier(accessjwt.VerifierOptions{
		Issuer:   accessJWTIssuer,
		Audience: accessJWTAudience,
		KeySet:   keySet,
		Clock:    clock,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("notes: create access JWT verifier: %w", err)
	}

	return issuer, verifier, nil
}

func noteObject(noteID string) string {
	return noteType + ":" + noteID
}
