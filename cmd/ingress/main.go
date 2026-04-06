package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/oklog/run"
	"inet.af/tcpproxy"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	k8sscheme "k8s.io/client-go/kubernetes/scheme"
)

var scheme = k8sscheme.Scheme

const (
	debugV = 4
)

func main() {
	ctx := context.Background()

	fs := flag.NewFlagSet("ingress", flag.ExitOnError)

	zapOpts := &zap.Options{}
	zapOpts.BindFlags(fs)

	var (
		tlsListen         = fs.String("tls-listen", "0.0.0.0:443", "TLS listener address")
		httpListen        = fs.String("http-listen", "", "Optional plain HTTP listener for HTTPS redirects")
		httpsRedirectPort = fs.String("https-redirect-port", "", "Optional explicit HTTPS port for redirects")
		instance          = fs.String("instance", "", "Ingress instance name to select services (ingress.lds.li/instance label)")
		watchNamespace    = fs.String("watch-namespace", "", "Optional namespace to watch services in. Empty means all namespaces")
		certMode          = fs.String("cert-mode", certModeSelfSigned, "Certificate mode for terminated TLS routes: self-signed or autocert")
		autocertSecret    = fs.String("autocert-secret", "", "namespace/name secret for autocert cache (required when --cert-mode=autocert)")
	)

	fs.Parse(os.Args[1:])

	logf.SetLogger(zap.New(zap.UseFlagOptions(zapOpts)))

	var log = logf.Log.WithName("ingress")
	if err := validateStartupConfig(*instance, *certMode, *autocertSecret); err != nil {
		log.Error(err, "invalid startup configuration")
		os.Exit(2)
	}

	cfg := config.GetConfigOrDie()

	rdb := &routedb{
		logger: log,
		routes: map[string]route{},
	}
	cp, err := newCertProvider(*certMode, certProviderConfig{
		KubeConfig:     cfg,
		AutocertSecret: *autocertSecret,
		HostPolicy: func(_ context.Context, host string) error {
			if rdb.HasHost(host) {
				return nil
			}
			return fmt.Errorf("host %q is not configured by any attached route", host)
		},
	})
	if err != nil {
		log.Error(err, "creating certificate provider")
		os.Exit(1)
	}

	mgr, err := newMgr(cfg, *watchNamespace, &ServiceReconciler{
		logger:   logf.Log,
		rdb:      rdb,
		instance: *instance,
	})
	if err != nil {
		log.Error(err, "creating manager")
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

	d := &director{
		logger: log,
		ps:     rdb,
		cp:     cp,
	}

	p := &tcpproxy.Proxy{}
	proxyContext, proxyCancel := context.WithCancel(ctx)
	g.Add(func() error {
		p.AddSNIMatchRoute(*tlsListen, MatchAny, d)
		if err := p.Start(); err != nil {
			return err
		}
		<-proxyContext.Done()
		return nil
	}, func(error) {
		proxyCancel()
		_ = p.Close()
	})

	if *httpListen != "" {
		hs := &http.Server{
			Addr: *httpListen,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host := r.Host
				if h, _, err := net.SplitHostPort(r.Host); err == nil {
					host = h
				}
				if !rdb.HasHost(host) {
					http.NotFound(w, r)
					return
				}
				redirectHost := host
				if *httpsRedirectPort != "" {
					redirectHost = net.JoinHostPort(host, *httpsRedirectPort)
				}
				http.Redirect(w, r, "https://"+redirectHost+r.URL.RequestURI(), http.StatusPermanentRedirect)
			}),
		}
		g.Add(func() error {
			return hs.ListenAndServe()
		}, func(error) {
			_ = hs.Close()
		})
	}

	if err := g.Run(); err != nil {
		log.Error(err, "running")
	}
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
