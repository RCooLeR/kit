// Package dbpg opens the PostgreSQL connection pool of a service: parse the DSN, connect, and
// prove with a ping that the database answers before anything else starts.
//
// The DSN usually holds a password, so no error of this package quotes it. Queries, transactions
// and the schema stay in the service's storage package; migrations are in dbmigrate.
package dbpg

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/RCooLeR/kit/retry"
)

// DefaultConnectTimeout bounds the first connection and the startup ping when
// Options.ConnectTimeout is zero.
const DefaultConnectTimeout = 10 * time.Second

// Options describe the pool. Pool settings left at zero keep what the DSN says (pool_max_conns,
// pool_max_conn_lifetime) or, without that, the pgx defaults: the larger of 4 and the CPU count
// connections, each replaced after an hour.
type Options struct {
	// DSN is a postgres:// URL or a keyword/value connection string.
	DSN string
	// ConnectTimeout bounds the startup ping; zero means DefaultConnectTimeout.
	ConnectTimeout time.Duration
	// MaxConnLifetime is the age at which a connection is replaced.
	MaxConnLifetime time.Duration
	// MaxConns limits the pool.
	MaxConns int32
	// WaitFor keeps trying the startup ping for this long when the database does not answer yet,
	// once a second. A service started together with its database (Compose) needs this: the
	// database can pass its own health check while it restarts at the end of its first start.
	// Zero tries once.
	WaitFor time.Duration
}

// Open connects to PostgreSQL and checks that it answers. The caller closes the returned pool.
func Open(ctx context.Context, opts Options) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(opts.DSN)
	if err != nil {
		// The parse error may quote the DSN, password included, so it is not passed on.
		return nil, errors.New("parse database DSN: malformed connection string")
	}
	if opts.MaxConnLifetime > 0 {
		config.MaxConnLifetime = opts.MaxConnLifetime
	}
	if opts.MaxConns > 0 {
		config.MaxConns = opts.MaxConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}
	timeout := opts.ConnectTimeout
	if timeout <= 0 {
		timeout = DefaultConnectTimeout
	}
	deadline := time.Now().Add(opts.WaitFor)
	for {
		err := ping(ctx, pool, timeout)
		if err == nil {
			return pool, nil
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			pool.Close()
			return nil, fmt.Errorf("ping database: %w", err)
		}
		if err := retry.Sleep(ctx, time.Second); err != nil {
			pool.Close()
			return nil, fmt.Errorf("ping database: %w", err)
		}
	}
}

func ping(ctx context.Context, pool *pgxpool.Pool, timeout time.Duration) error {
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return pool.Ping(pingCtx)
}

// WithPassword puts password into a postgres:// DSN that names a user but no password. The DSN
// itself can then sit in plain configuration while the password comes from a secret file. A DSN
// that already has a password is refused: two sources for one secret hide which one is used.
// Errors never quote the DSN or the password.
func WithPassword(dsn, password string) (string, error) {
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.User == nil || parsed.User.Username() == "" {
		return "", errors.New("database DSN must be a postgres://user@host/database URL to take a separate password")
	}
	if _, hasPassword := parsed.User.Password(); hasPassword {
		return "", errors.New("database DSN already holds a password; configure it in one place only")
	}
	parsed.User = url.UserPassword(parsed.User.Username(), password)
	return parsed.String(), nil
}
