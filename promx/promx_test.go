package promx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func scrape(t *testing.T, handler http.Handler, accept string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("scrape status = %d, body %s", recorder.Code, recorder.Body.String())
	}
	return recorder
}

func familyNames(t *testing.T, registry *prometheus.Registry) []string {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	names := make([]string, 0, len(families))
	for _, family := range families {
		names = append(names, family.GetName())
	}
	return names
}

func TestNewRegistryIsEmptyUnlessCollectorsAreAskedFor(t *testing.T) {
	registry, err := NewRegistry(RegistryOptions{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if names := familyNames(t, registry); len(names) != 0 {
		t.Fatalf("a registry without options exports %v, want nothing", names)
	}
	if body := scrape(t, Handler(registry, HandlerOptions{}), "").Body.String(); strings.TrimSpace(body) != "" {
		t.Fatalf("an empty registry scraped as %q, want no metrics at all", body)
	}
}

func TestNewRegistryAddsRuntimeCollectors(t *testing.T) {
	registry, err := NewRegistry(RegistryOptions{GoCollector: true, ProcessCollector: true})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	var hasGo bool
	for _, name := range familyNames(t, registry) {
		hasGo = hasGo || name == "go_goroutines"
		if !strings.HasPrefix(name, "go_") && !strings.HasPrefix(name, "process_") {
			t.Fatalf("unexpected metric family %q from the runtime collectors", name)
		}
	}
	if !hasGo {
		t.Fatal("go_goroutines is missing although the Go collector was asked for")
	}
}

func TestNewRegistryStaysPrivate(t *testing.T) {
	registry, err := NewRegistry(RegistryOptions{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	global := prometheus.NewCounter(prometheus.CounterOpts{Name: "kit_test_global_only_total", Help: "Registered globally by the test."})
	prometheus.MustRegister(global)
	t.Cleanup(func() { prometheus.Unregister(global) })

	for _, name := range familyNames(t, registry) {
		if name == "kit_test_global_only_total" {
			t.Fatal("a globally registered metric leaked into the private registry")
		}
	}
}

func TestRegisterBuildInfoUsesTheCallersNameAndLabels(t *testing.T) {
	registry, err := NewRegistry(RegistryOptions{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	labels := prometheus.Labels{"version": "1.4.0", "commit": "3f2a9c1", "build_date": "2026-11-24T10:00:00Z"}
	if err := RegisterBuildInfo(registry, "example_bridge_build_info", "Static build information.", labels); err != nil {
		t.Fatalf("RegisterBuildInfo: %v", err)
	}

	want := "# HELP example_bridge_build_info Static build information.\n" +
		"# TYPE example_bridge_build_info gauge\n" +
		`example_bridge_build_info{build_date="2026-11-24T10:00:00Z",commit="3f2a9c1",version="1.4.0"} 1` + "\n"
	if got := scrape(t, Handler(registry, HandlerOptions{}), "").Body.String(); got != want {
		t.Fatalf("scrape:\n%s\nwant:\n%s", got, want)
	}
}

func TestRegisterBuildInfoErrors(t *testing.T) {
	registry, err := NewRegistry(RegistryOptions{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := RegisterBuildInfo(registry, "", "help", nil); err == nil {
		t.Fatal("a build info metric without a name was accepted")
	}
	if err := RegisterBuildInfo(registry, "example_build_info", "help", nil); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if err := RegisterBuildInfo(registry, "example_build_info", "help", nil); err == nil {
		t.Fatal("registering the same metric twice was accepted")
	}
}

func TestHandlerNegotiatesOpenMetricsOnlyWhenEnabled(t *testing.T) {
	registry, err := NewRegistry(RegistryOptions{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := RegisterBuildInfo(registry, "example_build_info", "Static build information.", nil); err != nil {
		t.Fatalf("RegisterBuildInfo: %v", err)
	}
	const openMetrics = "application/openmetrics-text; version=1.0.0"

	classic := scrape(t, Handler(registry, HandlerOptions{}), openMetrics)
	if got := classic.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Fatalf("OpenMetrics off: Content-Type = %q, want the classic text format", got)
	}
	if strings.Contains(classic.Body.String(), "# EOF") {
		t.Fatal("OpenMetrics off: the body ends with the OpenMetrics marker")
	}

	negotiated := scrape(t, Handler(registry, HandlerOptions{OpenMetrics: true}), openMetrics)
	if got := negotiated.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/openmetrics-text") {
		t.Fatalf("OpenMetrics on: Content-Type = %q", got)
	}
	if !strings.HasSuffix(negotiated.Body.String(), "# EOF\n") {
		t.Fatalf("OpenMetrics on: the body does not end with # EOF: %q", negotiated.Body.String())
	}
}

func TestHandlerErrorCounterIsOptIn(t *testing.T) {
	registry, err := NewRegistry(RegistryOptions{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	body := scrape(t, Handler(registry, HandlerOptions{ErrorCounter: true}), "").Body.String()
	for _, cause := range []string{"encoding", "gathering"} {
		if want := `promhttp_metric_handler_errors_total{cause="` + cause + `"} 0`; !strings.Contains(body, want) {
			t.Fatalf("scrape lacks %q:\n%s", want, body)
		}
	}
}

func TestHandlerSendsTheProcessStartTime(t *testing.T) {
	registry, err := NewRegistry(RegistryOptions{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	started := time.Unix(1795600000, 0)

	with := scrape(t, Handler(registry, HandlerOptions{ProcessStartTime: started}), "")
	if got := with.Header().Get("Process-Start-Time-Unix"); got != "1795600000" {
		t.Fatalf("Process-Start-Time-Unix = %q, want 1795600000", got)
	}
	without := scrape(t, Handler(registry, HandlerOptions{}), "")
	if got := without.Header().Get("Process-Start-Time-Unix"); got != "" {
		t.Fatalf("Process-Start-Time-Unix = %q although no start time was given", got)
	}
}
