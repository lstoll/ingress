package main

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeHandlerPathAllowlist(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.Path))
	}))
	t.Cleanup(app.Close)

	probe, err := newProbeHandler(slog.New(slog.DiscardHandler), app.Listener.Addr().String(), []string{"/healthz", "/readyz"})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		{"/healthz", http.StatusOK, "/healthz"},
		{"/healthz/", http.StatusOK, "/healthz/"},
		{"/readyz", http.StatusOK, "/readyz"},
		{"/metrics", http.StatusNotFound, ""},
		{"/health", http.StatusNotFound, ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rr := httptest.NewRecorder()
			probe.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status %d, want %d", rr.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusOK && rr.Body.String() != tt.wantBody {
				t.Fatalf("body %q, want %q", rr.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestNormalizePathPrefixes(t *testing.T) {
	got := normalizePathPrefixes([]string{"healthz", "/readyz/"})
	want := []string{"/healthz", "/readyz"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestNewProbeHandlerRequiresPrefixes(t *testing.T) {
	probe, err := newProbeHandler(slog.New(slog.DiscardHandler), "127.0.0.1:8080", nil)
	if err != nil {
		t.Fatal(err)
	}
	if probe != nil {
		t.Fatal("expected nil probe handler without path prefixes")
	}
}

func TestValidateProbeForward(t *testing.T) {
	if err := validateProbeForward("", nil); err != nil {
		t.Fatal(err)
	}
	if err := validateProbeForward("127.0.0.1:8080", []string{"/healthz"}); err != nil {
		t.Fatal(err)
	}
}
