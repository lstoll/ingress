package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	routesConfigured = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ingress",
		Name:      "routes_configured",
		Help:      "Number of configured routes by mode.",
	}, []string{"mode"})

	connectionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ingress",
		Name:      "connections_total",
		Help:      "Total TLS connections handled by mode.",
	}, []string{"mode"})

	connectionsActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ingress",
		Name:      "connections_active",
		Help:      "Currently active connections by mode.",
	}, []string{"mode"})

	tlsHandshakeErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "ingress",
		Name:      "tls_handshake_errors_total",
		Help:      "Total TLS handshake failures for terminated connections.",
	})

	httpRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ingress",
		Name:      "http_requests_total",
		Help:      "Total HTTP requests handled in HTTPS mode by status code class.",
	}, []string{"host", "status_class"})

	httpRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "ingress",
		Name:      "http_request_duration_seconds",
		Help:      "HTTP request latency in HTTPS mode.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"host"})

	reconcileTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ingress",
		Name:      "reconcile_total",
		Help:      "Total reconciliation events by result.",
	}, []string{"result"})
)

func init() {
	metrics.Registry.MustRegister(
		routesConfigured,
		connectionsTotal,
		connectionsActive,
		tlsHandshakeErrors,
		httpRequestsTotal,
		httpRequestDuration,
		reconcileTotal,
	)
}

func statusClass(code int) string {
	switch {
	case code < 200:
		return "1xx"
	case code < 300:
		return "2xx"
	case code < 400:
		return "3xx"
	case code < 500:
		return "4xx"
	default:
		return "5xx"
	}
}
