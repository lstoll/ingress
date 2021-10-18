package main

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreclientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	hostnamesAnnotation         = "service.beta.lds.li/hostnames"
	disableProxyProtoAnnotation = "service.beta.lds.li/disable-proxy-proto"
)

type ServiceReconciler struct {
	Client client.Client // TODO what is this
	logger logr.Logger
	rdb    *routedb
	coreV1 coreclientv1.CoreV1Interface
}

func (s *ServiceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	s.logger.Info("reconcile called", "object", req.NamespacedName)

	svc, err := s.coreV1.Services(req.Namespace).Get(ctx, req.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			// assume deleted
			if err := s.rdb.DeleteService(req.NamespacedName); err != nil {
				return reconcile.Result{}, err
			}
		}
		return reconcile.Result{}, fmt.Errorf("getting service: %w", err)
	}
	if err := s.rdb.AddService(*svc); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func (a *ServiceReconciler) InjectClient(c client.Client) error {
	a.Client = c
	return nil
}
