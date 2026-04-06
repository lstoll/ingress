package main

import (
	"context"
	"fmt"
	"flag"
	"net"
	"os"
	"strconv"

	"github.com/oklog/run"
	"inet.af/tcpproxy"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

var scheme = k8sscheme.Scheme

func init() {
	utilruntime.Must(gatewayv1.AddToScheme(scheme))
}

const (
	debugV = 4
)

func main() {
	ctx := context.Background()

	fs := flag.NewFlagSet("ingress", flag.ExitOnError)

	zapOpts := &zap.Options{}
	zapOpts.BindFlags(fs)

	var (
		addr             = fs.String("listen", "", "Address to listen on. If empty, derive from configured Gateway listener")
		gatewayName      = fs.String("gateway-name", "", "Gateway name to configure this ingress instance from")
		gatewayNamespace = fs.String("gateway-namespace", defaultNamespace(), "Gateway namespace")
		listenerName     = fs.String("listener-name", "", "Optional Gateway listener name to scope routing and listen address selection")
		watchNamespace   = fs.String("watch-namespace", "", "Optional namespace to watch routes/services in. Empty means all namespaces")
		certMode         = fs.String("cert-mode", certModeSelfSigned, "Certificate mode for terminated TLS routes: self-signed or autocert")
	)

	fs.Parse(os.Args[1:])

	logf.SetLogger(zap.New(zap.UseFlagOptions(zapOpts)))

	var log = logf.Log.WithName("ingress")
	if *gatewayName == "" {
		log.Error(fmt.Errorf("missing required flag"), "--gateway-name must be set")
		os.Exit(2)
	}

	cfg := config.GetConfigOrDie()
	resolvedListenAddr, terminateTLS, err := resolveListenerConfig(ctx, cfg, types.NamespacedName{
		Namespace: *gatewayNamespace,
		Name:      *gatewayName,
	}, *listenerName, *addr)
	if err != nil {
		log.Error(err, "resolving listen address from Gateway")
		os.Exit(1)
	}

	rdb := &routedb{
		logger: log,
		routes: map[string]route{},
	}
	cp, err := newCertProvider(*certMode)
	if err != nil {
		log.Error(err, "creating certificate provider")
		os.Exit(1)
	}

	mgr, err := newMgr(cfg, *watchNamespace, &TLSRouteReconciler{
		logger:           logf.Log,
		rdb:              rdb,
		gatewayName:      *gatewayName,
		gatewayNamespace: *gatewayNamespace,
		listenerName:     *listenerName,
		terminateTLS:     terminateTLS,
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

		p.AddSNIMatchRoute(resolvedListenAddr, MatchAny, d)
		if err := p.Start(); err != nil {
			return err
		}
		<-proxyContext.Done()
		return nil
	}, func(error) {
		proxyCancel()
		_ = p.Close()
	})

	if err := g.Run(); err != nil {
		log.Error(err, "running")
	}
}

func defaultNamespace() string {
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}
	return "default"
}

func resolveListenerConfig(ctx context.Context, cfg *rest.Config, gatewayNN types.NamespacedName, listenerName, explicitListenAddr string) (string, bool, error) {
	if explicitListenAddr != "" {
		return explicitListenAddr, false, nil
	}

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return "", false, fmt.Errorf("creating client: %w", err)
	}

	var gw gatewayv1.Gateway
	if err := c.Get(ctx, gatewayNN, &gw); err != nil {
		return "", false, fmt.Errorf("getting gateway %s: %w", gatewayNN, err)
	}

	for _, listener := range gw.Spec.Listeners {
		if listenerName != "" && string(listener.Name) != listenerName {
			continue
		}
		if listener.Protocol != gatewayv1.TLSProtocolType {
			continue
		}
		terminateTLS := false
		if listener.TLS != nil && listener.TLS.Mode != nil && *listener.TLS.Mode == gatewayv1.TLSModeTerminate {
			terminateTLS = true
		}
		return net.JoinHostPort("0.0.0.0", strconv.Itoa(int(listener.Port))), terminateTLS, nil
	}

	if listenerName == "" {
		return "", false, fmt.Errorf("gateway %s has no TLS listeners", gatewayNN)
	}
	return "", false, fmt.Errorf("gateway %s has no TLS listener named %q", gatewayNN, listenerName)
}

func newMgr(cfg *rest.Config, watchNamespace string, reconciler *TLSRouteReconciler) (manager.Manager, error) {
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
		For(&gatewayv1.TLSRoute{}).
		Complete(reconciler)
	if err != nil {
		return nil, err
	}

	return mgr, nil
}
