package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeHandlerForwardsPath(t *testing.T) {
	var gotPath, gotHost string
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(app.Close)

	probe, err := newProbeHandler(slog.New(slog.DiscardHandler), app.Listener.Addr().String(), []string{"/healthz"})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	probe.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %q", rr.Code, rr.Body.String())
	}
	if gotPath != "/healthz" {
		t.Fatalf("upstream path %q", gotPath)
	}
	if gotHost == "" {
		t.Fatal("expected host header on upstream request")
	}
}

func TestProbeHandlerUpstream404(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	t.Cleanup(app.Close)

	probe, err := newProbeHandler(slog.New(slog.DiscardHandler), app.Listener.Addr().String(), []string{"/healthz"})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	probe.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status %d, want upstream 404 passthrough", rr.Code)
	}
}

func TestProbeHandlerDeniedVsUpstream404(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Path)
	}))
	t.Cleanup(app.Close)

	probe, err := newProbeHandler(slog.New(slog.DiscardHandler), app.Listener.Addr().String(), []string{"/healthz"})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	probe.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("sidecar deny status %d", rr.Code)
	}
	if rr.Body.Len() != 0 && rr.Body.String() == "/metrics" {
		t.Fatal("unexpected upstream body on denied path")
	}
}
