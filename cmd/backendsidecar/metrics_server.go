package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func validateMetricsListen(addr string) error {
	if addr == "" {
		return nil
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return fmt.Errorf("invalid --metrics-listen %q: %w", addr, err)
	}
	return nil
}

func newMetricsServer(logger *slog.Logger, tlsConfig *tls.Config) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if err := sidecarReady(tlsConfig); err != nil {
			if logger != nil {
				logger.Warn("sidecar readiness check failed", "error", err)
			}
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	return &http.Server{
		Handler: mux,
	}
}

func sidecarReady(tlsConfig *tls.Config) error {
	if tlsConfig == nil {
		return fmt.Errorf("tls not configured")
	}
	if tlsConfig.GetCertificate != nil {
		if _, err := tlsConfig.GetCertificate(nil); err != nil {
			return fmt.Errorf("loading server certificate: %w", err)
		}
		return nil
	}
	if len(tlsConfig.Certificates) == 0 {
		return fmt.Errorf("server certificate not configured")
	}
	return nil
}

func startMetricsServer(ctx context.Context, logger *slog.Logger, addr string, srv *http.Server) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening for metrics: %w", err)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Warn("shutting down metrics server", "error", err)
		}
	}()

	logger.Info("metrics server listening", "addr", addr)
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serving metrics: %w", err)
	}
	return nil
}
