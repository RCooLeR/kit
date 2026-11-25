// Package testpg gives an integration test a real PostgreSQL to run against: a fresh schema per
// test in a disposable database, dropped when the test ends.
//
// Tests opt in through an environment variable holding the DSN and are skipped without it, so
// `go test ./...` passes on a clean checkout. Because every test creates and drops a schema, the
// DSN must name a database whose name starts with a prefix the project chose for its throwaway
// databases; a DSN pointing at anything else is refused before a single statement runs. Both the
// variable and the prefix are the project's: this package knows neither.
package testpg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Config names where the disposable database comes from.
type Config struct {
	// DSNEnv is the environment variable holding a postgres:// URL, for example
	// "HERALD_TEST_DB_DSN".
	DSNEnv string
	// DatabasePrefix is what the database name must start with, for example "herald_test".
	DatabasePrefix string
}

// Open returns a pool whose connections work in a new, empty schema. The schema and the pool are
// removed when the test ends. The test is skipped when the variable is unset and fails when the
// DSN is not a postgres:// URL of a database named with the prefix.
//
// The schema starts empty: the caller applies its migrations, usually with dbmigrate.Up. Tests
// that use Open can run in parallel, each in its own schema.
func Open(t testing.TB, cfg Config) *pgxpool.Pool {
	t.Helper()
	if cfg.DSNEnv == "" || cfg.DatabasePrefix == "" {
		t.Fatal("testpg: Config needs DSNEnv and DatabasePrefix")
	}
	dsn := os.Getenv(cfg.DSNEnv)
	if dsn == "" {
		t.Skipf("%s is not set; start the disposable test database first", cfg.DSNEnv)
	}
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") ||
		!strings.HasPrefix(strings.TrimPrefix(parsed.Path, "/"), cfg.DatabasePrefix) ||
		!strings.HasPrefix(databaseOf(dsn), cfg.DatabasePrefix) {
		// The DSN holds a password, so the message names the variable and never its value.
		t.Fatalf("%s must be a postgres:// URL of a database named %s*", cfg.DSNEnv, cfg.DatabasePrefix)
	}

	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("read random schema name: %v", err)
	}
	schema := "t_" + hex.EncodeToString(suffix)

	// The cleanup runs after the test's own context has ended, so it needs one that outlives it.
	ctx := context.WithoutCancel(t.Context())
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to the test database: %v", err)
	}
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		_ = admin.Close(ctx) // the create error is the one worth reporting
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		if err := admin.Close(ctx); err != nil {
			t.Errorf("close admin connection: %v", err)
		}
	})

	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	pool, err := pgxpool.New(ctx, parsed.String())
	if err != nil {
		t.Fatalf("open pool on the test schema: %v", err)
	}
	// Registered after the schema cleanup, so it runs first: the pool is closed before the schema goes.
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping the test database: %v", err)
	}
	return pool
}

// databaseOf is the database pgx connects to for dsn, after a dbname query parameter and the like
// overrode the URL's path; empty when pgx cannot read the DSN.
func databaseOf(dsn string) string {
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return ""
	}
	return config.Database
}
