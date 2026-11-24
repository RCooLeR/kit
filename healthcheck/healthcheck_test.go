package healthcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestURL(t *testing.T) {
	tests := []struct {
		name       string
		rawURL     string
		listenAddr string
		path       string
		want       string
		wantErr    bool
	}{
		{name: "explicit URL wins", rawURL: "http://example.internal:9000/readyz", listenAddr: ":8080", path: "/healthz", want: "http://example.internal:9000/readyz"},
		{name: "explicit URL without scheme", rawURL: "example.internal/readyz", wantErr: true},
		{name: "explicit URL that does not parse", rawURL: "http://[::1", wantErr: true},
		{name: "port only", listenAddr: ":8080", path: "/readyz", want: "http://127.0.0.1:8080/readyz"},
		{name: "IPv4 wildcard", listenAddr: "0.0.0.0:8080", path: "/readyz", want: "http://127.0.0.1:8080/readyz"},
		{name: "IPv6 wildcard", listenAddr: "[::]:8080", path: "/readyz", want: "http://127.0.0.1:8080/readyz"},
		{name: "specific host", listenAddr: "192.0.2.5:9100", path: "/readyz", want: "http://192.0.2.5:9100/readyz"},
		{name: "IPv6 loopback", listenAddr: "[::1]:9100", path: "/readyz", want: "http://[::1]:9100/readyz"},
		{name: "path without slash", listenAddr: ":8080", path: "readyz", want: "http://127.0.0.1:8080/readyz"},
		{name: "path is required", listenAddr: ":8080", wantErr: true},
		{name: "empty listen address", path: "/readyz", wantErr: true},
		{name: "listen address without port", listenAddr: "localhost", path: "/readyz", wantErr: true},
		{name: "listen address with empty port", listenAddr: "localhost:", path: "/readyz", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := URL(tc.rawURL, tc.listenAddr, tc.path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("URL = %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("URL: %v", err)
			}
			if got != tc.want {
				t.Fatalf("URL = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestProbe(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{name: "204 is healthy", handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }},
		{name: "200 is healthy", handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }},
		{
			name:    "503 is unhealthy",
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
			wantErr: "returned HTTP 503",
		},
		{
			name:    "a redirect is not followed",
			handler: func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) },
			wantErr: "returned HTTP 302",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var requests int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodGet {
					t.Errorf("probe used %s, want GET", r.Method)
				}
				tc.handler(w, r)
			}))
			defer server.Close()

			err := Probe(t.Context(), server.URL+"/readyz", time.Second)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Probe error = %v, want one containing %q", err, tc.wantErr)
			}
			if requests != 1 {
				t.Fatalf("server saw %d requests, want exactly 1", requests)
			}
		})
	}
}

func TestProbeFailsWhenNothingListens(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	address := server.URL
	server.Close()

	if err := Probe(t.Context(), address+"/readyz", time.Second); err == nil {
		t.Fatal("Probe succeeded against a closed port")
	}
}

func TestProbeHonoursACancelledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := Probe(ctx, server.URL, time.Second); err == nil {
		t.Fatal("Probe succeeded with a cancelled context")
	}
}
