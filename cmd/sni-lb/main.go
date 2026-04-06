package main

import (
	"context"
	"flag"
	"os"

	"github.com/oklog/run"
	"inet.af/tcpproxy"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/builder"
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

	fs := flag.NewFlagSet("sni-lb", flag.ExitOnError)

	zapOpts := &zap.Options{}
	zapOpts.BindFlags(fs)

	var (
		addr = fs.String("listen", "0.0.0.0:8080", "Address to listen on")
	)

	fs.Parse(os.Args[1:])

	logf.SetLogger(zap.New(zap.UseFlagOptions(zapOpts)))

	var log = logf.Log.WithName("sni-lb")

	cfg := config.GetConfigOrDie()

	rdb := &routedb{
		logger: log,
		routes: map[string]route{},
	}

	mgr, err := newMgr(cfg, &TLSRouteReconciler{
		logger: logf.Log,
		rdb:    rdb,
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
	}

	p := &tcpproxy.Proxy{}
	g.Add(func() error {

		p.AddSNIMatchRoute(*addr, MatchAny, d)
		return p.Start()
	}, func(error) {
		_ = p.Close()
	})

	if err := g.Run(); err != nil {
		log.Error(err, "running")
	}
}

func newMgr(cfg *rest.Config, reconciler *TLSRouteReconciler) (manager.Manager, error) {
	mgr, err := manager.New(cfg, manager.Options{
		Scheme: scheme,
	})
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
