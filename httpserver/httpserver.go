// Package httpserver holds what every service repeats around net/http: a server with all four
// timeouts set, a run loop that shuts down gracefully, and the liveness and readiness handlers.
//
// The router is the caller's: any http.Handler works, and this package depends on no router. It
// also decides no path and no response body. The caller mounts the health handlers where its
// contract says (new services: /healthz and /readyz) and passes the exact answers.
package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Timeouts used when the matching Options field is zero. They suit an API that answers quickly;
// a service that streams or serves large bodies raises WriteTimeout.
const (
	DefaultReadHeaderTimeout = 5 * time.Second
	DefaultReadTimeout       = 10 * time.Second
	DefaultWriteTimeout      = 30 * time.Second
	DefaultIdleTimeout       = 60 * time.Second
	// DefaultShutdownTimeout is how long Run and Serve wait for requests in flight.
	DefaultShutdownTimeout = 10 * time.Second
)

// Options describe one HTTP server.
type Options struct {
	// Addr is the listen address, such as ":8080".
	Addr string
	// Handler is the service's router.
	Handler http.Handler
	// A zero timeout means the default above; none can be switched off, because a server without
	// them is open to slow-client attacks.
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

// New returns a server with every timeout set.
func New(opts Options) *http.Server {
	return &http.Server{
		Addr:              opts.Addr,
		Handler:           opts.Handler,
		ReadHeaderTimeout: orDefault(opts.ReadHeaderTimeout, DefaultReadHeaderTimeout),
		ReadTimeout:       orDefault(opts.ReadTimeout, DefaultReadTimeout),
		WriteTimeout:      orDefault(opts.WriteTimeout, DefaultWriteTimeout),
		IdleTimeout:       orDefault(opts.IdleTimeout, DefaultIdleTimeout),
	}
}

func orDefault(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

// Run listens on server.Addr and serves until ctx ends, then shuts down as Serve does. An address
// that cannot be bound is reported at once, before anything is served.
func Run(ctx context.Context, server *http.Server, shutdownTimeout time.Duration) error {
	var config net.ListenConfig
	listener, err := config.Listen(ctx, "tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", server.Addr, err)
	}
	return Serve(ctx, server, listener, shutdownTimeout)
}

// Serve serves on listener until ctx ends, then stops accepting connections and waits up to
// shutdownTimeout (zero or less: DefaultShutdownTimeout) for requests in flight. It returns nil
// after a clean shutdown, and an error when serving failed or the wait ran out; in the latter case
// the remaining connections are closed. Serve closes the listener.
func Serve(ctx context.Context, server *http.Server, listener net.Listener, shutdownTimeout time.Duration) error {
	if shutdownTimeout <= 0 {
		shutdownTimeout = DefaultShutdownTimeout
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()

	select {
	case err := <-served:
		// Serve only returns on its own when the listener failed.
		return fmt.Errorf("serve HTTP: %w", err)
	case <-ctx.Done():
	}

	// The parent context is already cancelled, so the wait gets one of its own.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	shutdownErr := server.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		_ = server.Close() // the timeout is the error worth reporting
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP: %w", err)
	}
	if shutdownErr != nil {
		return fmt.Errorf("shut down HTTP server: %w", shutdownErr)
	}
	return nil
}
