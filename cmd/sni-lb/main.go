package main

import (
	"flag"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
)

const (
	debugV = 4
)

func main() {
	fs := flag.NewFlagSet("sni-lb", flag.ExitOnError)

	zapOpts := &zap.Options{}
	zapOpts.BindFlags(fs)

	fs.Parse(os.Args[1:])

	logf.SetLogger(zap.New(zap.UseFlagOptions(zapOpts)))

	var log = logf.Log.WithName("sni-lb")

	cfg := config.GetConfigOrDie()

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Error(err, "creating kubernetes client")
		os.Exit(1)
	}

	mgr, err := newMgr(cfg, &ServiceReconciler{
		logger: logf.Log,
		coreV1: cs.CoreV1(),
	})
	if err != nil {
		log.Error(err, "creating manager")
		os.Exit(1)
	}

	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		log.Error(err, "could not start manager")
		os.Exit(1)
	}
}

func newMgr(cfg *rest.Config, reconciler *ServiceReconciler) (manager.Manager, error) {
	mgr, err := manager.New(cfg, manager.Options{})
	if err != nil {
		return nil, err
	}

	err = builder.
		ControllerManagedBy(mgr). // Create the ControllerManagedBy
		For(&corev1.Service{}).   // ReplicaSet is the Application API
		Complete(reconciler)
	if err != nil {
		return nil, err
	}

	return mgr, nil
}
