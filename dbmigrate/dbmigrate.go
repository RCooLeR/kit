// Package dbmigrate runs a service's SQL migrations with golang-migrate, read from a file system
// the binary embeds, so an image carries its own schema.
//
// The migrations are numbered files in golang-migrate's naming (000001_init_schema.up.sql and
// .down.sql) at the root of the file system passed in. The service decides when to migrate: on
// start, or only through a `migrate` subcommand with Check guarding the start.
package dbmigrate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/golang-migrate/migrate/v4"
	migratepgx "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// ErrSchemaMismatch means the database is behind or ahead of the migrations this binary carries,
// or a migration failed half way and left the schema marked dirty.
var ErrSchemaMismatch = errors.New("database schema does not match this build")

// Up applies every pending migration. A database that is already current is not an error.
func Up(ctx context.Context, pool *pgxpool.Pool, migrations fs.FS) error {
	return withMigrator(ctx, pool, migrations, func(m *migrate.Migrate) error {
		if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("apply migrations: %w", err)
		}
		return nil
	})
}

// Down rolls back the latest migration only. It destroys what that migration created, so it is
// for disposable databases and for an operator who asked for it.
func Down(ctx context.Context, pool *pgxpool.Pool, migrations fs.FS) error {
	return withMigrator(ctx, pool, migrations, func(m *migrate.Migrate) error {
		if err := m.Steps(-1); err != nil {
			return fmt.Errorf("roll back one migration: %w", err)
		}
		return nil
	})
}

// Check fails with ErrSchemaMismatch unless the database is exactly at the newest migration in
// migrations and not dirty. It applies nothing; on a database without golang-migrate's version
// table it creates that table, which needs a role allowed to create tables.
func Check(ctx context.Context, pool *pgxpool.Pool, migrations fs.FS) error {
	latest, err := Latest(migrations)
	if err != nil {
		return err
	}
	return withMigrator(ctx, pool, migrations, func(m *migrate.Migrate) error {
		current, dirty, err := m.Version()
		if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
			return fmt.Errorf("read schema version: %w", err)
		}
		if dirty || current != latest {
			return fmt.Errorf("%w: database at %d (dirty=%t), build expects %d", ErrSchemaMismatch, current, dirty, latest)
		}
		return nil
	})
}

// Latest returns the version of the newest migration in migrations.
func Latest(migrations fs.FS) (uint, error) {
	source, err := iofs.New(migrations, ".")
	if err != nil {
		return 0, fmt.Errorf("open embedded migrations: %w", err)
	}
	defer func() { _ = source.Close() }() // an embedded file system has nothing to flush
	version, err := source.First()
	if err != nil {
		return 0, fmt.Errorf("read first migration: %w", err)
	}
	for {
		next, err := source.Next(version)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// The source reports the end of the list as a missing file.
				return version, nil
			}
			return 0, fmt.Errorf("read migration after %d: %w", version, err)
		}
		version = next
	}
}

// withMigrator runs fn with a migrator on a connection of its own. golang-migrate holds an
// advisory lock on that connection, so two instances starting together do not migrate at once.
// The library takes no context: ctx is only checked before the start.
func withMigrator(ctx context.Context, pool *pgxpool.Pool, migrations fs.FS, fn func(m *migrate.Migrate) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	source, err := iofs.New(migrations, ".")
	if err != nil {
		return fmt.Errorf("open embedded migrations: %w", err)
	}
	// Closing this wrapper (through the migrator) returns its connection; the pool stays open.
	db := stdlib.OpenDBFromPool(pool)
	driver, err := migratepgx.WithInstance(db, &migratepgx.Config{})
	if err != nil {
		_ = db.Close()     // nothing was taken from the pool yet
		_ = source.Close() // the driver error is the one worth reporting
		return fmt.Errorf("prepare migration driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", source, "pgx5", driver)
	if err != nil {
		_ = driver.Close() // as above
		_ = source.Close()
		return fmt.Errorf("create migrator: %w", err)
	}
	defer func() { _, _ = m.Close() }() // releases the lock connection; fn's error is the one worth reporting
	return fn(m)
}
