package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lstoll/ingress/internal/mtls"
)

func validateServerIdentityFlags(serverCert, serverKey, serverBundle string) error {
	hasBundle := strings.TrimSpace(serverBundle) != ""
	hasCert := strings.TrimSpace(serverCert) != ""
	hasKey := strings.TrimSpace(serverKey) != ""

	if hasBundle && (hasCert || hasKey) {
		return fmt.Errorf("use either --server-bundle or --server-cert/--server-key, not both")
	}
	if hasBundle {
		return nil
	}
	if hasCert && hasKey {
		return nil
	}
	return fmt.Errorf("either --server-bundle or both --server-cert and --server-key are required")
}

func serverIdentityFromFlags(serverCert, serverKey, serverBundle *string) mtls.IdentityFiles {
	return mtls.IdentityFiles{
		BundleFile: *serverBundle,
		CertFile:   *serverCert,
		KeyFile:    *serverKey,
	}
}

func parseSidecarFlags(fs *flag.FlagSet) (
	listen, forward, expectedClientSVID *string,
	serverCert, serverKey, serverBundle, clientCA *string,
	probeListen, probeForward, metricsListen *string,
	probePathPrefixes *stringSlice,
	certReloadInterval *time.Duration,
	logLevel *string,
	err error,
) {
	listen = fs.String("listen", "0.0.0.0:9443", "Listen address for mTLS ingress connections; also serves plain HTTP probes when --probe-listen is not set")
	forward = fs.String("forward", "127.0.0.1:8080", "Address to forward verified mTLS connections to")
	expectedClientSVID = fs.String("expected-client-svid", "", "Required SPIFFE URI SAN on ingress client certificate")
	serverCert = fs.String("server-cert", "", "Server certificate file")
	serverKey = fs.String("server-key", "", "Server private key file")
	serverBundle = fs.String("server-bundle", "", "Server credential bundle file (Kubernetes pod certificate format)")
	clientCA = fs.String("client-ca", "", "CA bundle for verifying client certificates")
	probeListen = fs.String("probe-listen", "", "Optional plain HTTP listen address for kubelet probes (requires --probe-path-prefix; use when probes target a different port than --listen)")
	probeForward = fs.String("probe-forward", "", "Address to forward allowed plain HTTP probe requests to (defaults to --forward)")
	metricsListen = fs.String("metrics-listen", "", "Optional HTTP listen address for Prometheus metrics and sidecar health endpoints (/metrics, /healthz, /readyz)")
	probePathPrefixes = new(stringSlice)
	fs.Var(probePathPrefixes, "probe-path-prefix", "Allowed plain HTTP path prefix for kubelet probes (repeatable or comma-separated; plain HTTP is disabled unless at least one prefix is set)")
	certReloadInterval = fs.Duration("cert-reload-interval", mtls.DefaultReloadInterval, "How often to reload certificate files from disk")
	logLevel = fs.String("log-level", envOrDefault("BACKEND_SIDECAR_LOG_LEVEL", "info"), "Log level: debug, info, warn, error")
	err = fs.Parse(os.Args[1:])
	return
}

func validateSidecarStartup(expectedClientSVID string, identity mtls.IdentityFiles) error {
	if expectedClientSVID == "" {
		return fmt.Errorf("missing required flag: expected-client-svid")
	}
	if err := validateServerIdentityFlags(identity.CertFile, identity.KeyFile, identity.BundleFile); err != nil {
		return err
	}
	return identity.Validate()
}
