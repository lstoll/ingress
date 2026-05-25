package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"

	"github.com/lstoll/ingress/internal/mtls"
	"github.com/oklog/run"
)

func main() {
	fs := flag.NewFlagSet("backendsidecar", flag.ExitOnError)
	listen, forward, expectedClientSVID, serverCert, serverKey, serverBundle, clientCA, probeForward, probePathPrefixes, certReloadInterval, logLevel, err := parseSidecarFlags(fs)
	if err != nil {
		os.Exit(2)
	}

	logger, err := setupSidecarLogger(*logLevel, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid log level %q: %v\n", *logLevel, err)
		os.Exit(2)
	}

	identity := serverIdentityFromFlags(serverCert, serverKey, serverBundle)
	if err := validateSidecarStartup(*expectedClientSVID, identity); err != nil {
		logger.Error("invalid startup configuration", "error", err)
		os.Exit(2)
	}

	probeForwardAddr := *probeForward
	if probeForwardAddr == "" {
		probeForwardAddr = *forward
	}
	if err := validateProbeForward(probeForwardAddr, *probePathPrefixes); err != nil {
		logger.Error("invalid probe configuration", "error", err)
		os.Exit(2)
	}

	reloader, err := mtls.NewServerReloader(
		logger.With("component", "cert-reloader"),
		identity,
		*clientCA,
		*expectedClientSVID,
		*certReloadInterval,
	)
	if err != nil {
		logger.Error("loading server TLS config", "error", err)
		os.Exit(1)
	}

	mux, err := newSidecarMux(
		logger,
		reloader.ServerTLSConfig(),
		*forward,
		probeForwardAddr,
		*probePathPrefixes,
	)
	if err != nil {
		logger.Error("creating connection mux", "error", err)
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		logger.Error("listening", "addr", *listen, "error", err)
		os.Exit(1)
	}

	logger.Info("backendsidecar listening",
		"listen", *listen,
		"forward", *forward,
		"probe_forward", probeForwardAddr,
		"probe_path_prefixes", normalizePathPrefixes(*probePathPrefixes),
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
			go mux.handle(conn)
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
