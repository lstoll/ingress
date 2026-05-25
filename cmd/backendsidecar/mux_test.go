package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lstoll/ingress/internal/mtls"
)

func TestPeekConnKind(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want connKind
	}{
		{"tls", "\x16\x03\x01", connKindTLS},
		{"get", "GET /healthz HTTP/1.1\r\n", connKindHTTP},
		{"post", "POST /readyz HTTP/1.1\r\n", connKindHTTP},
		{"unknown", "\x00\x01", connKindUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := bufio.NewReader(bytes.NewReader([]byte(tt.in)))
			got, err := peekConnKind(br)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSidecarMuxHTTPProbe(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(app.Close)

	mux, err := newSidecarMux(
		slog.New(slog.DiscardHandler),
		nil,
		app.Listener.Addr().String(),
		app.Listener.Addr().String(),
		"",
		[]string{"/healthz"},
	)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go acceptLoop(ln, mux.handle)

	resp, err := http.Get("http://" + ln.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}

	resp, err = http.Get("http://" + ln.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
}

func TestSidecarMuxRejectsHTTPWithoutProbePrefixes(t *testing.T) {
	mux, err := newSidecarMux(
		slog.New(slog.DiscardHandler),
		nil,
		"127.0.0.1:9",
		"127.0.0.1:9",
		"",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go acceptLoop(ln, mux.handle)

	client := &http.Client{Timeout: 2 * time.Second}
	_, err = client.Get("http://" + ln.Addr().String() + "/healthz")
	if err == nil {
		t.Fatal("expected connection to fail when probe prefixes are not configured")
	}
}

func TestSidecarMuxSeparateProbeListen(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(app.Close)

	mux, err := newSidecarMux(
		slog.New(slog.DiscardHandler),
		nil,
		app.Listener.Addr().String(),
		app.Listener.Addr().String(),
		"127.0.0.1:0",
		[]string{"/healthz", "/readyz"},
	)
	if err != nil {
		t.Fatal(err)
	}

	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = probeLn.Close() })

	// Simulate binding to the configured probe-listen address.
	go acceptLoop(probeLn, func(conn net.Conn) { handleProbeConn(mux.probe, conn) })

	resp, err := http.Get("http://" + probeLn.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}

	mainLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mainLn.Close() })
	go acceptLoop(mainLn, mux.handle)

	_, err = http.Get("http://" + mainLn.Addr().String() + "/healthz")
	if err == nil {
		t.Fatal("expected plain HTTP on mTLS listen port to fail when --probe-listen is configured")
	}
}

func TestSidecarMuxTLS(t *testing.T) {
	fix := mtls.NewTestFixture(t)

	appLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = appLn.Close() })
	go acceptLoop(appLn, func(conn net.Conn) {
		_, _ = io.WriteString(conn, "tls-ok")
		_ = conn.Close()
	})

	serverCfg, err := mtls.ServerConfig(fix.ServerIdentity(), fix.CAFile, fix.IngressSVID)
	if err != nil {
		t.Fatal(err)
	}

	mux, err := newSidecarMux(
		slog.New(slog.DiscardHandler),
		serverCfg,
		appLn.Addr().String(),
		appLn.Addr().String(),
		"",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go acceptLoop(ln, mux.handle)

	clientCfg, err := mtls.ClientConfig(fix.ClientIdentity(), fix.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg.ServerName = "backend-sidecar"

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "tls-ok" {
		t.Fatalf("body %q", string(body))
	}
}

func acceptLoop(ln net.Listener, handle func(net.Conn)) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(conn)
	}
}
