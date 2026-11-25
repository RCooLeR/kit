package testpg

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The kit's own disposable database, started from compose.test.yaml.
var kitDatabase = Config{DSNEnv: "KIT_TEST_DB_DSN", DatabasePrefix: "kit_test"}

// outcome records how Open ended a test when it did not return a pool.
type outcome struct {
	skipped bool
	failed  bool
	message string
}

// recordingTB stands in for the *testing.T that Open would skip or fail. Skipf and Fatalf record
// the verdict and unwind the call with a panic the helper below recovers, so the real test keeps
// running and can judge it.
type recordingTB struct {
	testing.TB
	outcome *outcome
}

type stopped struct{}

func (r recordingTB) Skipf(format string, args ...any) {
	r.outcome.skipped, r.outcome.message = true, fmt.Sprintf(format, args...)
	panic(stopped{})
}

func (r recordingTB) Fatalf(format string, args ...any) {
	r.outcome.failed, r.outcome.message = true, fmt.Sprintf(format, args...)
	panic(stopped{})
}

func (r recordingTB) Fatal(args ...any) {
	r.outcome.failed, r.outcome.message = true, fmt.Sprint(args...)
	panic(stopped{})
}

func openRecorded(t *testing.T, cfg Config) (result outcome) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			if _, ok := recovered.(stopped); !ok {
				panic(recovered)
			}
		}
	}()
	Open(recordingTB{TB: t, outcome: &result}, cfg)
	return result
}

func TestOpenSkipsWithoutADatabase(t *testing.T) {
	t.Setenv("KIT_TESTPG_UNSET", "")
	got := openRecorded(t, Config{DSNEnv: "KIT_TESTPG_UNSET", DatabasePrefix: "kit_test"})
	if !got.skipped || !strings.Contains(got.message, "KIT_TESTPG_UNSET") {
		t.Fatalf("Open without a DSN: %+v, want a skip that names the variable", got)
	}
}

func TestOpenRefusesADatabaseOutsideThePrefix(t *testing.T) {
	// Port 1 answers nothing: reaching it would fail differently, so a refusal proves that no
	// connection was attempted.
	tests := map[string]string{
		"another database":      "postgres://app:not-for-logs@127.0.0.1:1/production",
		"prefix later in name":  "postgres://app:not-for-logs@127.0.0.1:1/copy_of_kit_test",
		"dbname in the query":   "postgres://app:not-for-logs@127.0.0.1:1/kit_test?dbname=production",
		"not a postgres URL":    "mysql://app:not-for-logs@127.0.0.1:1/kit_test",
		"keyword/value DSN":     "host=127.0.0.1 port=1 dbname=kit_test password=not-for-logs",
		"URL that cannot parse": "postgres://app:not-for-logs@[::1/kit_test",
	}
	for name, dsn := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv("KIT_TESTPG_GUARD", dsn)
			got := openRecorded(t, Config{DSNEnv: "KIT_TESTPG_GUARD", DatabasePrefix: "kit_test"})
			if !got.failed || !strings.Contains(got.message, "KIT_TESTPG_GUARD must be a postgres:// URL of a database named kit_test*") {
				t.Fatalf("Open with %s: %+v, want the prefix refusal", name, got)
			}
			if strings.Contains(got.message, "not-for-logs") {
				t.Fatalf("the refusal prints the password: %s", got.message)
			}
		})
	}
}

func TestOpenNeedsBothSettings(t *testing.T) {
	for _, cfg := range []Config{{DSNEnv: "KIT_TEST_DB_DSN"}, {DatabasePrefix: "kit_test"}} {
		if got := openRecorded(t, cfg); !got.failed {
			t.Fatalf("Open(%+v) = %+v, want a failure", cfg, got)
		}
	}
}

func schemaExists(t *testing.T, schema string) bool {
	t.Helper()
	conn, err := pgx.Connect(t.Context(), os.Getenv(kitDatabase.DSNEnv))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(t.Context()) }()
	var exists bool
	err = conn.QueryRow(t.Context(), "SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = $1)", schema).Scan(&exists)
	if err != nil {
		t.Fatalf("look up schema: %v", err)
	}
	return exists
}

func TestOpenGivesEveryTestItsOwnSchemaAndDropsIt(t *testing.T) {
	var first, second string
	t.Run("inside", func(t *testing.T) {
		poolA := Open(t, kitDatabase)
		poolB := Open(t, kitDatabase)
		ctx := t.Context()

		if err := poolA.QueryRow(ctx, "SELECT current_schema()").Scan(&first); err != nil {
			t.Fatalf("read schema of the first pool: %v", err)
		}
		if err := poolB.QueryRow(ctx, "SELECT current_schema()").Scan(&second); err != nil {
			t.Fatalf("read schema of the second pool: %v", err)
		}
		if first == second || !strings.HasPrefix(first, "t_") || !strings.HasPrefix(second, "t_") {
			t.Fatalf("schemas %q and %q: want two different t_* schemas", first, second)
		}

		// The same table name in both schemas, with different rows, proves the isolation.
		if _, err := poolA.Exec(ctx, "CREATE TABLE notes (body text NOT NULL)"); err != nil {
			t.Fatalf("create table in the first schema: %v", err)
		}
		if _, err := poolB.Exec(ctx, "CREATE TABLE notes (body text NOT NULL)"); err != nil {
			t.Fatalf("create the same table in the second schema: %v", err)
		}
		if _, err := poolA.Exec(ctx, "INSERT INTO notes (body) VALUES ($1)", "only in the first"); err != nil {
			t.Fatalf("insert: %v", err)
		}
		var count int
		if err := poolB.QueryRow(ctx, "SELECT count(*) FROM notes").Scan(&count); err != nil {
			t.Fatalf("count rows in the second schema: %v", err)
		}
		if count != 0 {
			t.Fatalf("the second schema sees %d rows of the first", count)
		}
		if !schemaExists(t, first) || !schemaExists(t, second) {
			t.Fatal("a schema is missing while its test still runs")
		}
	})
	if first == "" {
		t.Skip("no test database configured")
	}
	if schemaExists(t, first) || schemaExists(t, second) {
		t.Fatalf("schemas %q and %q survived their test", first, second)
	}
}
