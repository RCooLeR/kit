// Package promx sets up Prometheus for a service: a registry of its own, the /metrics handler and a
// build-info gauge.
//
// It composes no metric name and no label. The service supplies the full name of its build-info
// metric, and every option that changes the /metrics output (runtime collectors, OpenMetrics) is
// off unless asked for, so an existing exporter that adopts the package scrapes byte for byte as
// before. New services switch them on.
package promx

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// RegistryOptions select the collectors a new registry starts with.
type RegistryOptions struct {
	// GoCollector adds the go_* runtime metrics.
	GoCollector bool
	// ProcessCollector adds the process_* metrics (CPU, memory, file descriptors).
	ProcessCollector bool
}

// NewRegistry returns a registry that belongs to the service alone. Nothing is registered with
// prometheus.DefaultRegisterer, so a library that registers metrics globally cannot leak into
// the service's /metrics.
func NewRegistry(opts RegistryOptions) (*prometheus.Registry, error) {
	registry := prometheus.NewRegistry()
	if opts.GoCollector {
		if err := registry.Register(collectors.NewGoCollector()); err != nil {
			return nil, fmt.Errorf("register Go collector: %w", err)
		}
	}
	if opts.ProcessCollector {
		if err := registry.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})); err != nil {
			return nil, fmt.Errorf("register process collector: %w", err)
		}
	}
	return registry, nil
}

// HandlerOptions tune the /metrics handler.
type HandlerOptions struct {
	// OpenMetrics lets a scraper negotiate the OpenMetrics format. Prometheus then receives that
	// format instead of the classic text one.
	OpenMetrics bool
	// Timeout bounds one scrape; zero means no limit.
	Timeout time.Duration
	// MaxRequestsInFlight limits concurrent scrapes; zero means no limit. Useful when collecting
	// calls a slow device.
	MaxRequestsInFlight int
	// ProcessStartTime, when set, is sent in the Process-Start-Time-Unix header so scrapers can
	// detect a restart.
	ProcessStartTime time.Time
	// ErrorCounter registers promhttp_metric_handler_errors_total with the registry, which counts
	// scrapes that failed while gathering or encoding. It adds that metric family to the output.
	ErrorCounter bool
}

// Handler returns the /metrics handler for registry.
func Handler(registry *prometheus.Registry, opts HandlerOptions) http.Handler {
	var errorCounterRegistry prometheus.Registerer
	if opts.ErrorCounter {
		errorCounterRegistry = registry
	}
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		Registry:            errorCounterRegistry,
		EnableOpenMetrics:   opts.OpenMetrics,
		Timeout:             opts.Timeout,
		MaxRequestsInFlight: opts.MaxRequestsInFlight,
		ProcessStartTime:    opts.ProcessStartTime,
	})
}

// RegisterBuildInfo registers a gauge that is always 1 and carries the build as labels, the usual
// `<service>_build_info` metric. The full metric name, the help text and the label names are the
// caller's: existing exporters differ (labels `date` or `build_date`) and dashboards match on them.
func RegisterBuildInfo(registerer prometheus.Registerer, name, help string, labels prometheus.Labels) error {
	if name == "" {
		return errors.New("build info metric needs a name")
	}
	gauge := prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: help, ConstLabels: labels}, func() float64 { return 1 })
	if err := registerer.Register(gauge); err != nil {
		return fmt.Errorf("register %s: %w", name, err)
	}
	return nil
}
