package main

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type TLSRouteReconciler struct {
	Client client.Client
	logger logr.Logger
	rdb    *routedb
}

func (s *TLSRouteReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	s.logger.Info("reconcile called", "object", req.NamespacedName)

	var tlsRoute gatewayv1.TLSRoute
	if err := s.Client.Get(ctx, req.NamespacedName, &tlsRoute); err != nil {
		if apierrors.IsNotFound(err) {
			s.logger.Info("TLSRoute not found, assuming deleted", "object", req.NamespacedName)
			s.rdb.RemoveRoute(req.NamespacedName)
			return reconcile.Result{}, nil
		}
		s.logger.Error(err, "getting TLSRoute", "object", req.NamespacedName)
		return reconcile.Result{}, fmt.Errorf("getting tlsroute: %w", err)
	}

	var hostnames []string
	for _, h := range tlsRoute.Spec.Hostnames {
		hostnames = append(hostnames, string(h))
	}

	if len(hostnames) == 0 {
		s.rdb.RemoveRoute(req.NamespacedName)
		return reconcile.Result{}, nil
	}

	if len(tlsRoute.Spec.Rules) == 0 || len(tlsRoute.Spec.Rules[0].BackendRefs) == 0 {
		s.rdb.RemoveRoute(req.NamespacedName)
		return reconcile.Result{}, nil
	}

	backendRef := tlsRoute.Spec.Rules[0].BackendRefs[0]
	if (backendRef.Group != nil && *backendRef.Group != "") || (backendRef.Kind != nil && *backendRef.Kind != "Service") {
		// We only support Services right now
		s.rdb.RemoveRoute(req.NamespacedName)
		return reconcile.Result{}, nil
	}
	if backendRef.Port == nil {
		s.logger.Info("backend service port not set", "object", req.NamespacedName)
		s.rdb.RemoveRoute(req.NamespacedName)
		return reconcile.Result{}, nil
	}

	backendName := string(backendRef.Name)
	backendNamespace := req.Namespace
	if backendRef.Namespace != nil {
		backendNamespace = string(*backendRef.Namespace)
	}

	var svc corev1.Service
	svcName := types.NamespacedName{Namespace: backendNamespace, Name: backendName}
	if err := s.Client.Get(ctx, svcName, &svc); err != nil {
		if apierrors.IsNotFound(err) {
			s.logger.Info("backend service not found", "service", svcName)
			s.rdb.RemoveRoute(req.NamespacedName)
			// we can't route without backend. Could return nil, but returning error causes requeue
			return reconcile.Result{}, nil
		}
		s.logger.Error(err, "getting backend service", "service", svcName)
		return reconcile.Result{}, err
	}

	if svc.Spec.ClusterIP == "" {
		s.logger.Info("backend service has no ClusterIP", "service", svcName)
		return reconcile.Result{}, nil
	}

	targetAddr := net.JoinHostPort(svc.Spec.ClusterIP, strconv.Itoa(int(*backendRef.Port)))

	// maintain proxy protocol compatibility, default true for ingress
	proxyProto := true
	if _, disable := tlsRoute.Annotations["service.beta.lds.li/disable-proxy-proto"]; disable {
		proxyProto = false
	} else if pb := tlsRoute.Annotations["gateway.lstoll.com/proxy-protocol"]; pb == "false" {
		proxyProto = false
	}

	if err := s.rdb.SetRoute(req.NamespacedName, hostnames, targetAddr, proxyProto); err != nil {
		s.logger.Error(err, "adding TLSRoute to rdb", "object", req.NamespacedName)
		return reconcile.Result{}, err
	}

	s.logger.Info("successfully configured TLSRoute proxy targets", "object", req.NamespacedName, "hostnames", len(hostnames))
	return reconcile.Result{}, nil
}
