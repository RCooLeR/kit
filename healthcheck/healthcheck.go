// Package healthcheck is the probe behind a service's `healthcheck` subcommand: the container
// asks its own HTTP endpoint whether it is ready, so the image needs no curl or wget.
//
// The package depends on the standard library only and knows no path: the caller says which
// endpoint to ask (new services: /readyz). The urfave/cli adapter lives in the healthcheckcli
// subpackage, so a program with another command line pays nothing for it.
package healthcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultTimeout is a probe timeout that fits a container health check with a 5 second limit.
const DefaultTimeout = 3 * time.Second

// URL returns the address to probe. A non-empty rawURL is used as given once it has a scheme and a
// host. Otherwise the address is built from the server's listen address and the path: a missing
// host and the wildcard addresses 0.0.0.0 and :: become 127.0.0.1, because the probe runs next to
// the server. The path is required in that case; there is no default endpoint.
func URL(rawURL, listenAddr, path string) (string, error) {
	if rawURL != "" {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return "", fmt.Errorf("parse healthcheck URL: %w", err)
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return "", fmt.Errorf("healthcheck URL must include scheme and host: %q", rawURL)
		}
		return parsed.String(), nil
	}
	if path == "" {
		return "", errors.New("healthcheck path is empty")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	host, port, err := splitListenAddr(listenAddr)
	if err != nil {
		return "", err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return (&url.URL{Scheme: "http", Host: net.JoinHostPort(host, port), Path: path}).String(), nil
}

func splitListenAddr(addr string) (host, port string, err error) {
	if addr == "" {
		return "", "", errors.New("listen address is empty")
	}
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", "", fmt.Errorf("listen address %q: %w", addr, err)
	}
	if port == "" {
		return "", "", fmt.Errorf("listen address %q has no port", addr)
	}
	return host, port, nil
}

// Probe sends one GET to probeURL and returns nil when the answer is a 2xx status. A redirect is
// not followed and counts as a failure: a health endpoint answers itself. A timeout of zero or
// less means DefaultTimeout.
func Probe(ctx context.Context, probeURL string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return fmt.Errorf("build healthcheck request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("healthcheck %s: %w", probeURL, err)
	}
	defer func() { _ = response.Body.Close() }() // nothing was read; a close error changes nothing
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("healthcheck %s returned HTTP %d", probeURL, response.StatusCode)
	}
	return nil
}
