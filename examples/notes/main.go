package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	casbinv3 "github.com/casbin/casbin/v3"
	casbinmodel "github.com/casbin/casbin/v3/model"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/apikey"
	authkitcasbin "github.com/meigma/authkit/casbin"
	"github.com/meigma/authkit/compose"
	"github.com/meigma/authkit/httpauth"
	"github.com/meigma/authkit/oidc"
	"github.com/meigma/authkit/store/memory"
)

const (
	defaultAddr             = ":8080"
	readNoteAction          = "note:read"
	noteType                = "note"
	noteIDPathValue         = "noteID"
	allowedNoteID           = "allowed"
	seedTokenTTL            = time.Hour
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
	principal      authkit.Principal
	seedIdentity   authkit.ExternalIdentity
	seedToken      string
	tokenExpiresAt time.Time
	notes          map[string]string
}

type notesAppOptions struct {
	clock          func() time.Time
	oidcHTTPClient *http.Client
}

type notesAppOption func(*notesAppOptions)

func withClock(clock func() time.Time) notesAppOption {
	return func(opts *notesAppOptions) {
		opts.clock = clock
	}
}

func withOIDCHTTPClient(client *http.Client) notesAppOption {
	return func(opts *notesAppOptions) {
		opts.oidcHTTPClient = client
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

	seedIdentity, err := store.LinkIdentity(ctx, issued.IdentityLink)
	if err != nil {
		return nil, err
	}

	middleware, err := newNotesMiddleware(store, tokenService, cfg, principal.ID)
	if err != nil {
		return nil, err
	}

	app := &notesApp{
		store:          store,
		tokenService:   tokenService,
		principal:      principal,
		seedIdentity:   seedIdentity,
		seedToken:      issued.Plaintext,
		tokenExpiresAt: issued.ExpiresAt,
		notes: map[string]string{
			allowedNoteID: "This note is readable by the seeded service principal.",
			"denied":      "The seeded Casbin policy does not grant access to this note.",
		},
	}

	mux := http.NewServeMux()
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
	tokenService *apikey.Service,
	cfg notesAppOptions,
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
	oidcOptions := []oidc.Option{
		oidc.WithClock(cfg.clock),
	}
	if cfg.oidcHTTPClient != nil {
		oidcOptions = append(oidcOptions, oidc.WithHTTPClient(cfg.oidcHTTPClient))
	}
	auth, err := compose.NewHTTP(compose.HTTPOptions{
		Authenticators: []compose.AuthenticatorSpec{
			compose.APIToken(tokenService),
			compose.OIDC(store, oidcOptions...),
		},
		Resolver:   store,
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

func noteObject(noteID string) string {
	return noteType + ":" + noteID
}
