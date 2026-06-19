// Package metrics defines and registers the Prometheus metrics for the ASN
// proxy and provides an HTTP server exposing the /metrics endpoint.
package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Status label values for DNSRequests.
const (
	StatusHit          = "hit"           // answered from the in-memory Netbox cache
	StatusMissPrivate  = "miss_private"  // private ASN, not found, not forwarded
	StatusUpstreamHit  = "upstream_hit"  // answered by the upstream resolver
	StatusUpstreamMiss = "upstream_miss" // upstream returned no answer
	StatusError        = "error"         // processing error
)

// Metrics bundles every Prometheus collector used by the application.
type Metrics struct {
	DNSRequests       *prometheus.CounterVec
	CachedASNs        prometheus.Gauge
	NetboxSyncSuccess prometheus.Counter
	NetboxSyncErrors  prometheus.Counter

	registry *prometheus.Registry
}

// New constructs the metrics and registers them on a private registry.
func New() *Metrics {
	m := &Metrics{
		DNSRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "asn_proxy_dns_requests_total",
			Help: "Total DNS queries handled, labelled by resolution status.",
		}, []string{"status"}),
		CachedASNs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "asn_proxy_cached_asns",
			Help: "Number of ASNs currently loaded in the in-memory cache.",
		}),
		NetboxSyncSuccess: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "asn_proxy_netbox_sync_success_total",
			Help: "Total successful Netbox API syncs.",
		}),
		NetboxSyncErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "asn_proxy_netbox_sync_errors_total",
			Help: "Total failed Netbox API syncs.",
		}),
		registry: prometheus.NewRegistry(),
	}

	m.registry.MustRegister(
		m.DNSRequests,
		m.CachedASNs,
		m.NetboxSyncSuccess,
		m.NetboxSyncErrors,
	)

	// Pre-initialise the known status label values so they are exported as 0
	// rather than being absent until first observed.
	for _, s := range []string{
		StatusHit, StatusMissPrivate, StatusUpstreamHit, StatusUpstreamMiss, StatusError,
	} {
		m.DNSRequests.WithLabelValues(s)
	}

	return m
}

// Server wraps an http.Server exposing /metrics.
type Server struct {
	http *http.Server
}

// NewServer builds an HTTP server serving the metrics registry at /metrics.
func (m *Metrics) NewServer(addr string) *Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))
	return &Server{
		http: &http.Server{
			Addr:    addr,
			Handler: mux,
		},
	}
}

// ListenAndServe blocks serving metrics until the server is shut down.
// http.ErrServerClosed is returned on a clean shutdown.
func (s *Server) ListenAndServe() error {
	return s.http.ListenAndServe()
}

// Shutdown gracefully stops the metrics server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// shutdownTimeout is a small convenience for callers that don't supply a ctx.
const shutdownTimeout = 5 * time.Second

// DefaultShutdownTimeout returns the recommended grace period for shutdown.
func DefaultShutdownTimeout() time.Duration { return shutdownTimeout }
