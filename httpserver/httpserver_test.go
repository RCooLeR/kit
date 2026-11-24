package httpserver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewSetsEveryTimeout(t *testing.T) {
	server := New(Options{Addr: ":8080", Handler: http.NotFoundHandler()})
	if server.Addr != ":8080" || server.Handler == nil {
		t.Fatalf("New dropped the address or the handler: %+v", server)
	}
	if server.ReadHeaderTimeout != DefaultReadHeaderTimeout || server.ReadTimeout != DefaultReadTimeout ||
		server.WriteTimeout != DefaultWriteTimeout || server.IdleTimeout != DefaultIdleTimeout {
		t.Fatalf("defaults not applied: %v %v %v %v", server.ReadHeaderTimeout, server.ReadTimeout, server.WriteTimeout, server.IdleTimeout)
	}

	server = New(Options{WriteTimeout: 2 * time.Minute, IdleTimeout: -1})
	if server.WriteTimeout != 2*time.Minute {
		t.Fatalf("WriteTimeout = %v, want the caller's 2m", server.WriteTimeout)
	}
	if server.IdleTimeout != DefaultIdleTimeout {
		t.Fatalf("a negative timeout must fall back to the default, got %v", server.IdleTimeout)
	}
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return listener
}

func TestServeAnswersUntilTheContextEndsThenFinishesRequestsInFlight(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /fast", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("fast")) })
	mux.HandleFunc("GET /slow", func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = w.Write([]byte("slow"))
	})

	listener := listen(t)
	base := "http://" + listener.Addr().String()
	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, New(Options{Handler: mux}), listener, 5*time.Second) }()

	if body := get(t, base+"/fast"); body != "fast" {
		t.Fatalf("GET /fast = %q", body)
	}

	slow := make(chan string, 1)
	go func() { slow <- get(t, base+"/slow") }()
	<-started
	cancel()
	// Shutdown has begun but the slow request is still running: Serve must not return yet.
	select {
	case err := <-served:
		t.Fatalf("Serve returned (%v) while a request was in flight", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)

	if body := <-slow; body != "slow" {
		t.Fatalf("request in flight got %q, want its full answer", body)
	}
	if err := <-served; err != nil {
		t.Fatalf("Serve after a clean shutdown: %v", err)
	}
	if _, err := http.Get(base + "/fast"); err == nil { //nolint:bodyclose // the request must fail, there is no body
		t.Fatal("the server still accepts connections after shutdown")
	}
}

func get(t *testing.T, url string) string {
	t.Helper()
	response, err := http.Get(url)
	if err != nil {
		t.Errorf("GET %s: %v", url, err)
		return ""
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Errorf("read %s: %v", url, err)
	}
	return string(body)
}

func TestServeReportsAShutdownThatRunsOutOfTime(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-release
	})

	listener := listen(t)
	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, New(Options{Handler: handler}), listener, 20*time.Millisecond) }()

	go func() {
		response, err := http.Get("http://" + listener.Addr().String() + "/")
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	<-started
	cancel()

	err := <-served
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Serve = %v, want the shutdown deadline", err)
	}
}

func TestRunReportsAnAddressItCannotBind(t *testing.T) {
	taken := listen(t)
	defer func() { _ = taken.Close() }()

	err := Run(t.Context(), New(Options{Addr: taken.Addr().String()}), time.Second)
	if err == nil || !strings.Contains(err.Error(), "listen on") {
		t.Fatalf("Run on a taken port = %v, want a listen error", err)
	}
}

func TestRunServesOnItsAddress(t *testing.T) {
	// Find a free port, release it, and let Run bind it.
	probe := listen(t)
	addr := probe.Addr().String()
	_ = probe.Close()

	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan error, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("up")) })
	go func() { served <- Run(ctx, New(Options{Addr: addr, Handler: handler}), time.Second) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err := http.Get("http://" + addr + "/")
		if err == nil {
			_ = response.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not come up: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-served; err != nil {
		t.Fatalf("Run after cancel: %v", err)
	}
}

func TestLiveSendsExactlyTheConfiguredAnswer(t *testing.T) {
	tests := []struct {
		name     string
		response Response
		wantType string
	}{
		{"no content", Response{Status: http.StatusNoContent}, ""},
		{"json body", Response{Status: http.StatusOK, ContentType: "application/json", Body: `{"status":"ok"}` + "\n"}, "application/json"},
		{"plain body", Response{Status: http.StatusOK, ContentType: "text/plain; charset=utf-8", Body: "ok"}, "text/plain; charset=utf-8"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			Live(tc.response).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))

			if recorder.Code != tc.response.Status {
				t.Fatalf("status = %d, want %d", recorder.Code, tc.response.Status)
			}
			if recorder.Body.String() != tc.response.Body {
				t.Fatalf("body = %q, want %q byte for byte", recorder.Body.String(), tc.response.Body)
			}
			if got := recorder.Header().Get("Content-Type"); got != tc.wantType {
				t.Fatalf("Content-Type = %q, want %q", got, tc.wantType)
			}
			if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", got)
			}
		})
	}
}

func TestReadyFollowsTheCheck(t *testing.T) {
	ready := Response{Status: http.StatusNoContent}
	notReady := Response{Status: http.StatusServiceUnavailable, ContentType: "application/json", Body: `{"status":"not_ready"}`}
	failure := errors.New("ping database: connection refused to 192.0.2.7")
	var reported error
	var checkErr error
	handler := Ready(func(context.Context) error { return checkErr }, ready, notReady, func(err error) { reported = err })

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusNoContent || recorder.Body.Len() != 0 || reported != nil {
		t.Fatalf("ready answer: status %d, body %q, reported %v", recorder.Code, recorder.Body.String(), reported)
	}

	checkErr = failure
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable || recorder.Body.String() != notReady.Body {
		t.Fatalf("not-ready answer: status %d, body %q", recorder.Code, recorder.Body.String())
	}
	if !errors.Is(reported, failure) {
		t.Fatalf("onFailure got %v, want the check's error", reported)
	}
	if strings.Contains(recorder.Body.String(), "192.0.2.7") {
		t.Fatal("the response leaks the internal error")
	}
}

func TestReadyPassesTheRequestContextToTheCheck(t *testing.T) {
	type key struct{}
	var seen any
	handler := Ready(func(ctx context.Context) error {
		seen = ctx.Value(key{})
		return nil
	}, Response{Status: http.StatusNoContent}, Response{Status: http.StatusServiceUnavailable}, nil)

	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	request = request.WithContext(context.WithValue(request.Context(), key{}, "probe"))
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if seen != "probe" {
		t.Fatalf("check saw %v, want the request's context", seen)
	}
}

func TestHealthHandlersRefuseAResponseWithoutStatus(t *testing.T) {
	ok := Response{Status: http.StatusNoContent}
	check := func(context.Context) error { return nil }
	tests := map[string]func(){
		"live":             func() { Live(Response{}) },
		"ready":            func() { Ready(check, Response{}, ok, nil) },
		"not ready":        func() { Ready(check, ok, Response{Status: 42}, nil) },
		"ready, nil check": func() { Ready(nil, ok, ok, nil) },
	}
	for name, construct := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("constructor accepted an incomplete answer")
				}
			}()
			construct()
		})
	}
}
