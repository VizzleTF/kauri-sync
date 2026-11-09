//go:build integration

// Package testpg starts a throwaway PostgreSQL for tests.
package testpg

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/VizzleTF/kauri-sync/internal/store"
)

// Start starts Postgres with the server's schema. stop ends it.
func Start(ctx context.Context) (pool *pgxpool.Pool, stop func(), err error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	dir, err := os.MkdirTemp("", "kauri-sync-pg")
	if err != nil {
		return nil, nil, err
	}
	db := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Port(uint32(port)).
		RuntimePath(filepath.Join(dir, "runtime")).
		DataPath(filepath.Join(dir, "data")).
		Logger(io.Discard))
	if err := db.Start(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, nil, fmt.Errorf("start postgres: %w", err)
	}
	stop = func() {
		if pool != nil {
			pool.Close()
		}
		_ = db.Stop()
		_ = os.RemoveAll(dir)
	}
	pool, err = pgxpool.New(ctx, fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port))
	if err != nil {
		stop()
		return nil, nil, err
	}
	for range 2 { // migrating twice must be harmless
		if err := store.New(pool).Migrate(ctx); err != nil {
			stop()
			return nil, nil, fmt.Errorf("migrate: %w", err)
		}
	}
	return pool, stop, nil
}
