package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metricMTLSConnectionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "backendsidecar",
		Name:      "mtls_connections_total",
		Help:      "Total verified mTLS connections accepted and proxied to the backend.",
	})

	metricMTLSHandshakeErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "backendsidecar",
		Name:      "mtls_handshake_errors_total",
		Help:      "Total mTLS handshake failures on the main listener.",
	})

	metricProbeRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "backendsidecar",
		Name:      "probe_requests_total",
		Help:      "Total plain HTTP probe requests handled on the main or probe listener.",
	}, []string{"result"})

	metricUnsupportedConnectionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "backendsidecar",
		Name:      "unsupported_connections_total",
		Help:      "Total connections rejected because the first byte was neither TLS nor allowed HTTP.",
	})
)
