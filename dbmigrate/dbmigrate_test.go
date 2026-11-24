package dbmigrate_test

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/RCooLeR/kit/dbmigrate"
	"github.com/RCooLeR/kit/testpg"
)

//go:embed testdata/migrations/*.sql testdata/newer/*.sql
var fixtures embed.FS

// migrations is the schema "this build" carries: two migrations. newer is the same schema one
// release later, with a third.
func migrations(t *testing.T) fs.FS { return sub(t, "testdata/migrations") }
func newer(t *testing.T) fs.FS      { return sub(t, "testdata/newer") }

func sub(t *testing.T, dir string) fs.FS {
	t.Helper()
	fsys, err := fs.Sub(fixtures, dir)
	if err != nil {
		t.Fatalf("open %s: %v", dir, err)
	}
	return fsys
}

var kitDatabase = testpg.Config{DSNEnv: "KIT_TEST_DB_DSN", DatabasePrefix: "kit_test"}

func columns(t *testing.T, pool *pgxpool.Pool, table string) []string {
	t.Helper()
	rows, err := pool.Query(t.Context(),
		"SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 ORDER BY ordinal_position", table)
	if err != nil {
		t.Fatalf("list columns of %s: %v", table, err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan column name: %v", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("list columns of %s: %v", table, err)
	}
	return names
}

func TestLatest(t *testing.T) {
	if got, err := dbmigrate.Latest(migrations(t)); err != nil || got != 2 {
		t.Fatalf("Latest = %d, %v; want 2", got, err)
	}
	if got, err := dbmigrate.Latest(newer(t)); err != nil || got != 3 {
		t.Fatalf("Latest of the newer set = %d, %v; want 3", got, err)
	}
	if _, err := dbmigrate.Latest(fstest.MapFS{}); err == nil {
		t.Fatal("Latest of a file system without migrations returned no error")
	}
}

func TestUpAppliesEverythingAndIsRepeatable(t *testing.T) {
	pool := testpg.Open(t, kitDatabase)
	ctx := t.Context()

	if err := dbmigrate.Check(ctx, pool, migrations(t)); !errors.Is(err, dbmigrate.ErrSchemaMismatch) {
		t.Fatalf("Check on an empty schema = %v, want ErrSchemaMismatch", err)
	}
	if err := dbmigrate.Up(ctx, pool, migrations(t)); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if got := columns(t, pool, "notes"); !slices.Equal(got, []string{"id", "body", "created_at"}) {
		t.Fatalf("columns after Up = %v", got)
	}
	if err := dbmigrate.Check(ctx, pool, migrations(t)); err != nil {
		t.Fatalf("Check after Up: %v", err)
	}
	if err := dbmigrate.Up(ctx, pool, migrations(t)); err != nil {
		t.Fatalf("second Up on a current schema: %v", err)
	}
	// The migrator borrowed connections from the pool and must have given them back.
	var one int
	if err := pool.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("the pool is unusable after migrating: %v", err)
	}
}

func TestDownRollsBackOneStepAndUpRestoresIt(t *testing.T) {
	pool := testpg.Open(t, kitDatabase)
	ctx := t.Context()
	if err := dbmigrate.Up(ctx, pool, migrations(t)); err != nil {
		t.Fatalf("Up: %v", err)
	}

	if err := dbmigrate.Down(ctx, pool, migrations(t)); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if got := columns(t, pool, "notes"); !slices.Equal(got, []string{"id", "body"}) {
		t.Fatalf("columns after one step down = %v, want the first migration only", got)
	}
	if err := dbmigrate.Check(ctx, pool, migrations(t)); !errors.Is(err, dbmigrate.ErrSchemaMismatch) {
		t.Fatalf("Check one step behind = %v, want ErrSchemaMismatch", err)
	}

	if err := dbmigrate.Up(ctx, pool, migrations(t)); err != nil {
		t.Fatalf("Up after Down: %v", err)
	}
	if got := columns(t, pool, "notes"); !slices.Equal(got, []string{"id", "body", "created_at"}) {
		t.Fatalf("columns after up, down, up = %v", got)
	}
}

func TestCheckRefusesASchemaBehindOrAheadOfTheBuild(t *testing.T) {
	pool := testpg.Open(t, kitDatabase)
	ctx := t.Context()
	if err := dbmigrate.Up(ctx, pool, migrations(t)); err != nil {
		t.Fatalf("Up: %v", err)
	}

	// A newer build starts against the old schema: the database is behind.
	if err := dbmigrate.Check(ctx, pool, newer(t)); !errors.Is(err, dbmigrate.ErrSchemaMismatch) {
		t.Fatalf("Check with a newer build = %v, want ErrSchemaMismatch", err)
	}
	if err := dbmigrate.Up(ctx, pool, newer(t)); err != nil {
		t.Fatalf("Up with the newer build: %v", err)
	}
	if err := dbmigrate.Check(ctx, pool, newer(t)); err != nil {
		t.Fatalf("Check with the newer build after its Up: %v", err)
	}
	// The old build starts against the new schema (a rollback of the image): the database is ahead.
	if err := dbmigrate.Check(ctx, pool, migrations(t)); !errors.Is(err, dbmigrate.ErrSchemaMismatch) {
		t.Fatalf("Check with an older build = %v, want ErrSchemaMismatch", err)
	}
}

func TestAFailedMigrationLeavesTheSchemaDirty(t *testing.T) {
	pool := testpg.Open(t, kitDatabase)
	ctx := t.Context()
	broken := fstest.MapFS{
		"000001_create_notes.up.sql":   {Data: []byte("CREATE TABLE notes (body text NOT NULL);")},
		"000001_create_notes.down.sql": {Data: []byte("DROP TABLE notes;")},
		"000002_break.up.sql":          {Data: []byte("ALTER TABLE no_such_table ADD COLUMN x int;")},
		"000002_break.down.sql":        {Data: []byte("SELECT 1;")},
	}

	if err := dbmigrate.Up(ctx, pool, broken); err == nil {
		t.Fatal("Up reported success for a migration that cannot run")
	}
	if err := dbmigrate.Check(ctx, pool, broken); !errors.Is(err, dbmigrate.ErrSchemaMismatch) {
		t.Fatalf("Check after a failed migration = %v, want ErrSchemaMismatch", err)
	}
}

func TestACancelledContextStopsBeforeAnythingRuns(t *testing.T) {
	pool := testpg.Open(t, kitDatabase)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := dbmigrate.Up(ctx, pool, migrations(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Up with a cancelled context = %v, want context.Canceled", err)
	}
	if got := columns(t, pool, "notes"); len(got) != 0 {
		t.Fatalf("a cancelled Up still created columns %v", got)
	}
}
