package dbpg

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWithPassword(t *testing.T) {
	tests := []struct {
		name     string
		dsn      string
		password string
		want     string
		wantErr  bool
	}{
		{name: "adds the password", dsn: "postgres://herald@postgres:5432/herald", password: "s3cret", want: "postgres://herald:s3cret@postgres:5432/herald"},
		{name: "keeps the query", dsn: "postgresql://herald@db/herald?sslmode=disable", password: "s3cret", want: "postgresql://herald:s3cret@db/herald?sslmode=disable"},
		{name: "escapes reserved characters", dsn: "postgres://herald@db/herald", password: "p@ss/w:rd?#", want: "postgres://herald:p%40ss%2Fw%3Ard%3F%23@db/herald"},
		{name: "refuses a DSN that already has one", dsn: "postgres://herald:other@db/herald", password: "s3cret", wantErr: true},
		{name: "refuses a DSN without user", dsn: "postgres://db/herald", password: "s3cret", wantErr: true},
		{name: "refuses a keyword/value DSN", dsn: "host=db user=herald dbname=herald", password: "s3cret", wantErr: true},
		{name: "refuses another scheme", dsn: "mysql://herald@db/herald", password: "s3cret", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := WithPassword(tc.dsn, tc.password)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("WithPassword = %q, want an error", got)
				}
				if strings.Contains(err.Error(), tc.password) || strings.Contains(err.Error(), "other") || strings.Contains(err.Error(), tc.dsn) {
					t.Fatalf("error %q quotes the DSN or a password", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("WithPassword: %v", err)
			}
			if got != tc.want {
				t.Fatalf("WithPassword = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOpenDoesNotQuoteAMalformedDSN(t *testing.T) {
	const dsn = "postgres://herald:do-not-print-me@db:not-a-port/herald"
	_, err := Open(t.Context(), Options{DSN: dsn})
	if err == nil {
		t.Fatal("Open accepted a DSN with a port that is not a number")
	}
	if strings.Contains(err.Error(), "do-not-print-me") || strings.Contains(err.Error(), "herald") {
		t.Fatalf("error %q quotes the DSN", err)
	}
}

func TestOpenFailsFastWhenNothingAnswers(t *testing.T) {
	// Port 1 on loopback refuses the connection at once.
	start := time.Now()
	_, err := Open(t.Context(), Options{DSN: "postgres://herald:do-not-print-me@127.0.0.1:1/herald", ConnectTimeout: 5 * time.Second})
	if err == nil {
		t.Fatal("Open succeeded although nothing listens")
	}
	if !strings.Contains(err.Error(), "ping database") {
		t.Fatalf("error %q does not say which step failed", err)
	}
	if strings.Contains(err.Error(), "do-not-print-me") {
		t.Fatalf("error %q contains the password", err)
	}
	if waited := time.Since(start); waited > 20*time.Second {
		t.Fatalf("Open took %v to give up", waited)
	}
}

func TestOpenConnectsAndAppliesThePoolOptions(t *testing.T) {
	dsn := os.Getenv("KIT_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("KIT_TEST_DB_DSN is not set; start the database from compose.test.yaml")
	}
	pool, err := Open(t.Context(), Options{DSN: dsn, MaxConns: 3, MaxConnLifetime: 10 * time.Minute})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer pool.Close()

	var one int
	if err := pool.QueryRow(t.Context(), "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("SELECT 1 = %d, %v", one, err)
	}
	if got := pool.Config().MaxConns; got != 3 {
		t.Fatalf("MaxConns = %d, want 3", got)
	}
	if got := pool.Config().MaxConnLifetime; got != 10*time.Minute {
		t.Fatalf("MaxConnLifetime = %v, want 10m", got)
	}
}

func TestOpenKeepsThePoolSettingsOfTheDSN(t *testing.T) {
	dsn := os.Getenv("KIT_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("KIT_TEST_DB_DSN is not set; start the database from compose.test.yaml")
	}
	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	pool, err := Open(t.Context(), Options{DSN: dsn + separator + "pool_max_conns=7&pool_max_conn_lifetime=20m"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer pool.Close()
	if got := pool.Config().MaxConns; got != 7 {
		t.Fatalf("MaxConns = %d, want the DSN's 7", got)
	}
	if got := pool.Config().MaxConnLifetime; got != 20*time.Minute {
		t.Fatalf("MaxConnLifetime = %v, want the DSN's 20m", got)
	}
}

func TestOpenWaitsForADatabaseThatComesUpLate(t *testing.T) {
	// Nothing listens on port 1, so every ping fails; WaitFor decides how long Open keeps trying.
	start := time.Now()
	_, err := Open(t.Context(), Options{DSN: "postgres://herald@127.0.0.1:1/herald", WaitFor: 2500 * time.Millisecond})
	if err == nil {
		t.Fatal("Open succeeded although nothing listens")
	}
	if waited := time.Since(start); waited < 2*time.Second || waited > 15*time.Second {
		t.Fatalf("Open gave up after %v, want about the 2.5 s it was told to wait", waited)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Open(ctx, Options{DSN: "postgres://herald@127.0.0.1:1/herald", WaitFor: time.Minute}); err == nil {
		t.Fatal("Open with a cancelled context succeeded")
	}
}
