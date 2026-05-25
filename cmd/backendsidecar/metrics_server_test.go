package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lstoll/ingress/internal/mtls"
)

func TestMetricsServerHealthEndpoints(t *testing.T) {
	fix := mtls.NewTestFixture(t)
	serverCfg, err := mtls.ServerConfig(fix.ServerIdentity(), fix.CAFile, fix.IngressSVID)
	if err != nil {
		t.Fatal(err)
	}

	srv := newMetricsServer(nil, serverCfg)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	for _, path := range []string{"/healthz", "/readyz"} {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d", resp.StatusCode)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != "OK" {
				t.Fatalf("body %q", string(body))
			}
		})
	}
}

func TestMetricsServerMetricsEndpoint(t *testing.T) {
	metricMTLSConnectionsTotal.Add(1)

	srv := newMetricsServer(nil, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &tls.Certificate{}, nil
		},
	})
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "backendsidecar_mtls_connections_total") {
		t.Fatalf("metrics body missing sidecar counter: %q", string(body))
	}
}

func TestSidecarReady(t *testing.T) {
	if err := sidecarReady(nil); err == nil {
		t.Fatal("expected error for nil tls config")
	}

	cfg := &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &tls.Certificate{}, nil
		},
	}
	if err := sidecarReady(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestValidateMetricsListen(t *testing.T) {
	if err := validateMetricsListen(""); err != nil {
		t.Fatal(err)
	}
	if err := validateMetricsListen("127.0.0.1:8081"); err != nil {
		t.Fatal(err)
	}
	if err := validateMetricsListen("bad"); err == nil {
		t.Fatal("expected error")
	}
}
