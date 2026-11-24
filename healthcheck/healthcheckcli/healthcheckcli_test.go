package healthcheckcli

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/urfave/cli/v3"
)

// newProgram is a root command shaped like a service: one global listen flag and the subcommand.
func newProgram(path string) *cli.Command {
	return &cli.Command{
		Name:  "service",
		Flags: []cli.Flag{&cli.StringFlag{Name: "http-addr", Value: ":8080", Sources: cli.EnvVars("KIT_TEST_HTTP_ADDR")}},
		Commands: []*cli.Command{
			Command(Options{
				Addr: func(command *cli.Command) string { return command.String("http-addr") },
				Path: path,
			}),
		},
	}
}

// probeTarget serves status on /readyz and counts how often each path was asked.
func probeTarget(t *testing.T, status int) (server *httptest.Server, hits func(path string) int64) {
	t.Helper()
	var ready, other atomic.Int64
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" {
			ready.Add(1)
			w.WriteHeader(status)
			return
		}
		other.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	return server, func(path string) int64 {
		if path == "/readyz" {
			return ready.Load()
		}
		return other.Load()
	}
}

func listenAddrOf(t *testing.T, server *httptest.Server) string {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	_, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatalf("split test server address: %v", err)
	}
	// As a container configures it: every interface, which the probe must turn into loopback.
	return "0.0.0.0:" + port
}

func TestCommandProbesTheListenAddressOfTheParentFlag(t *testing.T) {
	server, hits := probeTarget(t, http.StatusNoContent)

	err := newProgram("/readyz").Run(t.Context(), []string{"service", "--http-addr", listenAddrOf(t, server), "healthcheck"})
	if err != nil {
		t.Fatalf("healthcheck against a ready server: %v", err)
	}
	if hits("/readyz") != 1 || hits("other") != 0 {
		t.Fatalf("probe asked /readyz %d times and other paths %d times, want 1 and 0", hits("/readyz"), hits("other"))
	}
}

func TestCommandReadsTheListenAddressFromTheEnvironment(t *testing.T) {
	server, hits := probeTarget(t, http.StatusNoContent)
	t.Setenv("KIT_TEST_HTTP_ADDR", listenAddrOf(t, server))

	if err := newProgram("/readyz").Run(t.Context(), []string{"service", "healthcheck"}); err != nil {
		t.Fatalf("healthcheck with the address from the environment: %v", err)
	}
	if hits("/readyz") != 1 {
		t.Fatalf("probe asked /readyz %d times, want 1", hits("/readyz"))
	}
}

func TestCommandFailsWhenTheServerIsNotReady(t *testing.T) {
	server, _ := probeTarget(t, http.StatusServiceUnavailable)

	err := newProgram("/readyz").Run(t.Context(), []string{"service", "--http-addr", listenAddrOf(t, server), "healthcheck"})
	if err == nil {
		t.Fatal("healthcheck succeeded against a server answering 503")
	}
}

func TestCommandFlagsOverrideAddressAndPath(t *testing.T) {
	server, hits := probeTarget(t, http.StatusNoContent)

	// The configured path does not exist on the server; --url must replace the whole address.
	err := newProgram("/missing").Run(t.Context(), []string{"service", "healthcheck", "--url", server.URL + "/readyz"})
	if err != nil {
		t.Fatalf("healthcheck --url: %v", err)
	}
	// --path replaces only the endpoint.
	err = newProgram("/missing").Run(t.Context(), []string{
		"service", "--http-addr", listenAddrOf(t, server), "healthcheck", "--path", "/readyz", "--timeout", "2s",
	})
	if err != nil {
		t.Fatalf("healthcheck --path: %v", err)
	}
	if hits("/readyz") != 2 || hits("other") != 0 {
		t.Fatalf("probe asked /readyz %d times and other paths %d times, want 2 and 0", hits("/readyz"), hits("other"))
	}
}

func TestCommandNeedsAPath(t *testing.T) {
	if err := newProgram("").Run(t.Context(), []string{"service", "healthcheck"}); err == nil {
		t.Fatal("healthcheck ran without a path to probe")
	}
}
