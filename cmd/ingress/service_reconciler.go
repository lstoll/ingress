package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	labelIngressInstance       = "ingress.lds.li/instance"
	annMode                    = "ingress.lds.li/mode"
	annSNIHostnames            = "ingress.lds.li/sni-hostnames"
	annHTTPHostnames           = "ingress.lds.li/hostnames"
	annProxyProtocol           = "ingress.lds.li/proxy-protocol"
	modeTLSPassthrough         = "tls-passthrough"
	modeTLSTermination         = "tls-termination"
	modeHTTPS                  = "https"
	proxyProtocolVersion1Value = "v1"
)

type ServiceReconciler struct {
	Client client.Client
	logger logr.Logger
	rdb    *routedb

	instance string
}

func (s *ServiceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	s.logger.Info("reconcile called", "object", req.NamespacedName)

	var svc corev1.Service
	if err := s.Client.Get(ctx, req.NamespacedName, &svc); err != nil {
		if apierrors.IsNotFound(err) {
			s.rdb.RemoveRoute(req.NamespacedName)
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("getting service: %w", err)
	}

	if !s.managesService(&svc) {
		s.rdb.RemoveRoute(req.NamespacedName)
		return reconcile.Result{}, nil
	}

	mode := svc.Annotations[annMode]
	if mode != modeTLSPassthrough && mode != modeTLSTermination && mode != modeHTTPS {
		s.rdb.RemoveRoute(req.NamespacedName)
		return reconcile.Result{}, nil
	}

	hostnamesAnn := annSNIHostnames
	if mode == modeHTTPS {
		hostnamesAnn = annHTTPHostnames
	}
	hostnames := splitCSV(svc.Annotations[hostnamesAnn])
	if len(hostnames) == 0 {
		s.rdb.RemoveRoute(req.NamespacedName)
		return reconcile.Result{}, nil
	}

	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone || len(svc.Spec.Ports) == 0 {
		s.rdb.RemoveRoute(req.NamespacedName)
		return reconcile.Result{}, nil
	}

	targetAddr := net.JoinHostPort(svc.Spec.ClusterIP, strconv.Itoa(int(svc.Spec.Ports[0].Port)))
	proxyProto := svc.Annotations[annProxyProtocol] == proxyProtocolVersion1Value
	if err := s.rdb.SetRoute(req.NamespacedName, hostnames, targetAddr, mode, proxyProto); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

func (s *ServiceReconciler) managesService(svc *corev1.Service) bool {
	if svc.Labels == nil {
		return false
	}
	return svc.Labels[labelIngressInstance] == s.instance
}

func splitCSV(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}
