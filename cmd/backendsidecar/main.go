package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/lstoll/ingress/internal/mtls"
	"github.com/oklog/run"
)

func main() {
	fs := flag.NewFlagSet("backendsidecar", flag.ExitOnError)
	listen := fs.String("listen", "0.0.0.0:9443", "mTLS listen address")
	forward := fs.String("forward", "127.0.0.1:8080", "Address to forward verified connections to")
	expectedClientSVID := fs.String("expected-client-svid", "", "Required SPIFFE URI SAN on ingress client certificate")
	serverCert := fs.String("server-cert", "", "Server certificate file")
	serverKey := fs.String("server-key", "", "Server private key file")
	clientCA := fs.String("client-ca", "", "CA bundle for verifying client certificates")
	certReloadInterval := fs.Duration("cert-reload-interval", mtls.DefaultReloadInterval, "How often to reload certificate files from disk")
	logLevel := fs.String("log-level", envOrDefault("BACKEND_SIDECAR_LOG_LEVEL", "info"), "Log level: debug, info, warn, error")

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	logger, err := setupSidecarLogger(*logLevel, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid log level %q: %v\n", *logLevel, err)
		os.Exit(2)
	}

	if *expectedClientSVID == "" {
		logger.Error("missing required flag", "flag", "expected-client-svid")
		os.Exit(2)
	}

	reloader, err := mtls.NewServerReloader(
		logger.With("component", "cert-reloader"),
		*serverCert,
		*serverKey,
		*clientCA,
		*expectedClientSVID,
		*certReloadInterval,
	)
	if err != nil {
		logger.Error("loading server TLS config", "error", err)
		os.Exit(1)
	}

	ln, err := tls.Listen("tcp", *listen, reloader.ServerTLSConfig())
	if err != nil {
		logger.Error("listening", "addr", *listen, "error", err)
		os.Exit(1)
	}

	logger.Info("backendsidecar listening",
		"listen", *listen,
		"forward", *forward,
		"expected_client_svid", *expectedClientSVID,
		"cert_reload_interval", certReloadInterval.String(),
	)

	var g run.Group
	ctx, cancel := context.WithCancel(context.Background())
	reloader.Start(ctx)
	g.Add(run.SignalHandler(ctx, os.Interrupt))

	g.Add(func() error {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return nil
				default:
				}
				return fmt.Errorf("accept: %w", err)
			}
			go handleSidecarConn(logger, conn, *forward)
		}
	}, func(error) {
		cancel()
		_ = ln.Close()
	})

	if err := g.Run(); err != nil {
		logger.Error("running", "error", err)
		os.Exit(1)
	}
}

func handleSidecarConn(logger *slog.Logger, client net.Conn, forwardAddr string) {
	defer func() { _ = client.Close() }()

	upstream, err := net.DialTimeout("tcp", forwardAddr, 10*time.Second)
	if err != nil {
		logger.Warn("dialing forward target", "forward", forwardAddr, "error", err)
		return
	}
	defer func() { _ = upstream.Close() }()

	logger.Debug("proxying connection", "forward", forwardAddr, "client", client.RemoteAddr().String())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, client)
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
	}()
	wg.Wait()
}

func setupSidecarLogger(level string, out io.Writer) (*slog.Logger, error) {
	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info", "":
		slogLevel = slog.LevelInfo
	case "warn", "warning":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		return nil, fmt.Errorf("unsupported log level")
	}
	return slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: slogLevel})), nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
