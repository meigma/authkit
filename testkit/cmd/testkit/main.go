package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	authmemory "github.com/meigma/authkit/store/memory"
	authpostgres "github.com/meigma/authkit/store/postgres"
	"github.com/meigma/authkit/testkit/internal/authflow"
	"github.com/meigma/authkit/testkit/internal/httpui"
	"github.com/meigma/authkit/testkit/internal/paste"
	testkitmemory "github.com/meigma/authkit/testkit/internal/store/memory"
	testkitpostgres "github.com/meigma/authkit/testkit/internal/store/postgres"
)

const (
	defaultAddr             = ":8080"
	addrEnv                 = "TESTKIT_ADDR"
	databaseURLEnv          = "TESTKIT_DATABASE_URL"
	serverReadHeaderTimeout = 5 * time.Second
	serverReadTimeout       = 10 * time.Second
	serverWriteTimeout      = 10 * time.Second
	serverIdleTimeout       = 60 * time.Second
	shutdownTimeout         = 5 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	err := run(ctx, os.Stdout)
	stop()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, out io.Writer) error {
	addr := os.Getenv(addrEnv)
	if addr == "" {
		addr = defaultAddr
	}

	stores, cleanup, err := newStores(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	pasteService, err := paste.NewService(stores.pastes)
	if err != nil {
		return err
	}
	authRuntime, err := authflow.NewRuntime(ctx, stores.auth)
	if err != nil {
		return err
	}
	handler, err := httpui.NewServer(pasteService, authRuntime)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
	}
	serverErr := make(chan error, 1)
	go func() {
		_, _ = fmt.Fprintf(out, "testkit seed API token: %s\n", authRuntime.SeedAPIToken)
		_, _ = fmt.Fprintf(out, "testkit listening on http://localhost%s\n", addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err

			return
		}
		serverErr <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("testkit: shutdown server: %w", err)
		}

		return nil
	case err := <-serverErr:
		return err
	}
}

type stores struct {
	pastes paste.Repository
	auth   authflow.Store
}

func newStores(ctx context.Context) (stores, func(), error) {
	databaseURL := os.Getenv(databaseURLEnv)
	if databaseURL == "" {
		authStore := authmemory.NewStore()
		if err := configureOIDCProvider(ctx, authStore, os.Getenv); err != nil {
			return stores{}, nil, err
		}

		return stores{
			pastes: testkitmemory.NewStore(),
			auth:   authStore,
		}, func() {}, nil
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return stores{}, nil, fmt.Errorf("testkit: open postgres pool: %w", err)
	}
	if migrateErr := testkitpostgres.Migrate(ctx, pool); migrateErr != nil {
		pool.Close()

		return stores{}, nil, fmt.Errorf("testkit: migrate postgres: %w", migrateErr)
	}
	if migrateErr := authpostgres.Migrate(ctx, pool); migrateErr != nil {
		pool.Close()

		return stores{}, nil, fmt.Errorf("testkit: migrate authkit postgres: %w", migrateErr)
	}

	pasteStore, err := testkitpostgres.NewStore(pool)
	if err != nil {
		pool.Close()

		return stores{}, nil, err
	}
	authStore, err := authpostgres.NewStore(pool)
	if err != nil {
		pool.Close()

		return stores{}, nil, err
	}
	if err := configureOIDCProvider(ctx, authStore, os.Getenv); err != nil {
		pool.Close()

		return stores{}, nil, err
	}

	return stores{
		pastes: pasteStore,
		auth:   authStore,
	}, pool.Close, nil
}
