package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/oklog/run"
	proxyproto "github.com/pires/go-proxyproto"
	"golang.org/x/term"
	"inet.af/tcpproxy"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	k8sscheme "k8s.io/client-go/kubernetes/scheme"
)

var scheme = k8sscheme.Scheme

func main() {
	ctx := context.Background()
	version := readVersion()

	fs := flag.NewFlagSet("ingress", flag.ExitOnError)

	var (
		tlsListen               = fs.String("tls-listen", "0.0.0.0:443", "TLS listener address")
		listenProxyProto        = fs.Bool("listen-proxy-protocol", false, "Enable Proxy Protocol parsing on incoming frontend listeners")
		listenProxyProtoTimeout = fs.Duration("listen-proxy-protocol-timeout", 10*time.Second, "Timeout for reading Proxy Protocol header on incoming frontend listeners")
		httpListen              = fs.String("http-listen", "", "Optional plain HTTP listener for HTTPS redirects")
		httpsRedirectPort       = fs.String("https-redirect-port", "", "Optional explicit HTTPS port for redirects")
		instance                = fs.String("instance", "", "Ingress instance name to select services (ingress.lds.li/instance label)")
		watchNamespace          = fs.String("watch-namespace", "", "Optional namespace to watch services in. Empty means all namespaces")
		certMode                = fs.String("cert-mode", certModeSelfSigned, "Certificate mode for terminated TLS routes: self-signed or autocert")
		autocertSecret          = fs.String("autocert-secret", "", "namespace/name secret for autocert cache (required when --cert-mode=autocert)")
		logLevel                = fs.String("log-level", envOrDefault("INGRESS_LOG_LEVEL", "info"), "Log level: debug, info, warn, error")
		showVersion             = fs.Bool("version", false, "Print version and exit")
	)

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if *showVersion {
		fmt.Println(version)
		return
	}

	appLogger, err := setupLogger(*logLevel, os.Stdout, term.IsTerminal(int(os.Stdout.Fd())))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid log level %q: %v\n", *logLevel, err)
		os.Exit(2)
	}
	slog.SetDefault(appLogger)
	logf.SetLogger(logr.FromSlogHandler(appLogger.With("component", "controller-runtime").Handler()))

	log := appLogger.With("component", "ingress")
	if err := validateStartupConfig(*instance, *certMode, *autocertSecret); err != nil {
		log.Error("invalid startup configuration", "error", err)
		os.Exit(2)
	}
	log.Info("starting ingress",
		"version", version,
		"instance", *instance,
		"tls_listen", *tlsListen,
		"listen_proxy_protocol", *listenProxyProto,
		"listen_proxy_protocol_timeout", listenProxyProtoTimeout.String(),
		"http_listen", *httpListen,
		"watch_namespace", *watchNamespace,
		"cert_mode", *certMode,
	)

	cfg := config.GetConfigOrDie()

	var ir *ingressRouter
	cp, err := newCertProvider(*certMode, certProviderConfig{
		KubeConfig:     cfg,
		AutocertSecret: *autocertSecret,
		HostPolicy: func(_ context.Context, host string) error {
			if ir != nil && ir.HasHost(host) {
				return nil
			}
			return fmt.Errorf("host %q is not configured by any attached route", host)
		},
		AllowHost: func(host string) bool {
			return ir != nil && ir.HasHost(host)
		},
	})
	if err != nil {
		log.Error("creating certificate provider", "error", err)
		os.Exit(1)
	}
	log.Info("certificate provider initialized")

	// TLS front: SNI index + per-Service bindings (see router.go model).
	ir = newIngressRouter(log.With("component", "ingress-router"), ctx, cp)

	mgr, err := newMgr(cfg, *watchNamespace, &ServiceReconciler{
		logger:   log.With("component", "service-reconciler"),
		router:   ir,
		instance: *instance,
	})
	if err != nil {
		log.Error("creating manager", "error", err)
		os.Exit(1)
	}

	var g run.Group

	g.Add(run.SignalHandler(ctx, os.Interrupt))

	mgrContext, mgrCancel := context.WithCancel(ctx)
	g.Add(func() error {
		return mgr.Start(mgrContext)
	}, func(error) {
		mgrCancel()
	})

	p := &tcpproxy.Proxy{}
	if *listenProxyProto {
		p.ListenFunc = func(network, laddr string) (net.Listener, error) {
			return listenWithOptionalProxyProto(network, laddr, *listenProxyProto, *listenProxyProtoTimeout)
		}
	}
	proxyContext, proxyCancel := context.WithCancel(ctx)
	g.Add(func() error {
		log.Info("starting TLS proxy listener", "addr", *tlsListen)
		p.AddSNIMatchRoute(*tlsListen, ir.matchSNI, ir)
		if err := p.Start(); err != nil {
			return err
		}
		<-proxyContext.Done()
		return nil
	}, func(error) {
		proxyCancel()
		_ = ir.Close()
		_ = p.Close()
	})

	if *httpListen != "" {
		hs := &http.Server{
			Addr:    *httpListen,
			Handler: httpsRedirectHandler(ir, *httpsRedirectPort, log),
		}
		g.Add(func() error {
			log.Info("starting HTTP redirect listener", "addr", *httpListen)
			ln, err := listenWithOptionalProxyProto("tcp", *httpListen, *listenProxyProto, *listenProxyProtoTimeout)
			if err != nil {
				return err
			}
			return hs.Serve(ln)
		}, func(error) {
			_ = hs.Close()
		})
	}

	if err := g.Run(); err != nil {
		log.Error("running", "error", err)
	}
}

type hostIndex interface {
	HasHost(host string) bool
}

func httpsRedirectHandler(hi hostIndex, httpsRedirectPort string, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		}
		if !hi.HasHost(host) {
			log.Debug("http redirect miss", "host", host, "path", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		redirectHost := host
		if httpsRedirectPort != "" {
			redirectHost = net.JoinHostPort(host, httpsRedirectPort)
		}
		log.Debug("redirecting http to https", "host", host, "target_host", redirectHost, "path", r.URL.Path)
		http.Redirect(w, r, "https://"+redirectHost+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
}

func listenWithOptionalProxyProto(network, addr string, enabled bool, timeout time.Duration) (net.Listener, error) {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return ln, nil
	}
	return &proxyproto.Listener{
		Listener:          ln,
		ReadHeaderTimeout: timeout,
	}, nil
}

func setupLogger(level string, out io.Writer, interactive bool) (*slog.Logger, error) {
	var slogLevel slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
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

	opts := &slog.HandlerOptions{Level: slogLevel}
	if interactive {
		return slog.New(slog.NewTextHandler(out, opts)), nil
	}
	return slog.New(slog.NewJSONHandler(out, opts)), nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func readVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}

	version := bi.Main.Version
	if version == "" {
		version = "devel"
	}

	var revision, vcsTime string
	var modified bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			vcsTime = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}

	parts := []string{version}
	if revision != "" {
		if len(revision) > 12 {
			revision = revision[:12]
		}
		parts = append(parts, "rev="+revision)
	}
	if vcsTime != "" {
		parts = append(parts, "time="+vcsTime)
	}
	if modified {
		parts = append(parts, "dirty=true")
	}

	return strings.Join(parts, " ")
}

func validateStartupConfig(instance, certMode, autocertSecret string) error {
	if instance == "" {
		return fmt.Errorf("--instance must be set")
	}
	if certMode == certModeAutocert && autocertSecret == "" {
		return fmt.Errorf("--autocert-secret must be set when --cert-mode=autocert")
	}
	if certMode == certModeAutocert {
		if _, _, err := splitNamespacedName(autocertSecret); err != nil {
			return fmt.Errorf("invalid --autocert-secret, expected namespace/name: %w", err)
		}
	}
	return nil
}
func newMgr(cfg *rest.Config, watchNamespace string, reconciler *ServiceReconciler) (manager.Manager, error) {
	opts := manager.Options{
		Scheme: scheme,
	}
	if watchNamespace != "" {
		opts.Cache = cache.Options{
			DefaultNamespaces: map[string]cache.Config{
				watchNamespace: {},
			},
		}
	}

	mgr, err := manager.New(cfg, opts)
	if err != nil {
		return nil, err
	}

	reconciler.Client = mgr.GetClient()

	err = builder.
		ControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Complete(reconciler)
	if err != nil {
		return nil, err
	}

	return mgr, nil
}
