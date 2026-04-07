package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

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
	annAuthMode                = "ingress.lds.li/auth-mode"
	annOIDCIssuer              = "ingress.lds.li/oidc-issuer"
	annOIDCDynamicClient       = "ingress.lds.li/oidc-dynamic-client"
	annOIDCUsernameHeader      = "ingress.lds.li/oidc-preferred-username-header"
	annOIDCEmailHeader         = "ingress.lds.li/oidc-email-header"
	annRequireGroup            = "ingress.lds.li/require-group"
	modeTLSPassthrough         = "tls-passthrough"
	modeTLSTermination         = "tls-termination"
	modeHTTPS                  = "https"
	authModeOIDC               = "OIDC"
	proxyProtocolVersion1Value = "v1"
)

type ServiceReconciler struct {
	Client client.Client
	logger *slog.Logger
	// router holds the TLS SNI index and per-Service workload bindings.
	router *ingressRouter

	instance string
}

func (s *ServiceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	s.logger.Debug("reconcile called", "name", req.Name, "namespace", req.Namespace)

	var svc corev1.Service
	if err := s.Client.Get(ctx, req.NamespacedName, &svc); err != nil {
		if apierrors.IsNotFound(err) {
			s.logger.Debug("service not found; removing routes", "name", req.Name, "namespace", req.Namespace)
			s.router.RemoveRoute(req.NamespacedName)
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("getting service: %w", err)
	}

	if !s.managesService(&svc) {
		s.logger.Debug("service does not match instance; removing routes",
			"name", req.Name, "namespace", req.Namespace, "instance", s.instance)
		s.router.RemoveRoute(req.NamespacedName)
		return reconcile.Result{}, nil
	}

	mode := svc.Annotations[annMode]
	if mode != modeTLSPassthrough && mode != modeTLSTermination && mode != modeHTTPS {
		s.logger.Debug("unsupported service mode; removing routes", "mode", mode, "name", req.Name, "namespace", req.Namespace)
		s.router.RemoveRoute(req.NamespacedName)
		return reconcile.Result{}, nil
	}

	hostnamesAnn := annSNIHostnames
	if mode == modeHTTPS {
		hostnamesAnn = annHTTPHostnames
	}
	hostnames := splitCSV(svc.Annotations[hostnamesAnn])
	if len(hostnames) == 0 {
		s.logger.Debug("service has no hostnames; removing routes", "annotation", hostnamesAnn, "name", req.Name, "namespace", req.Namespace)
		s.router.RemoveRoute(req.NamespacedName)
		return reconcile.Result{}, nil
	}

	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone || len(svc.Spec.Ports) == 0 {
		s.logger.Debug("service has no routable cluster ip/ports; removing routes", "name", req.Name, "namespace", req.Namespace)
		s.router.RemoveRoute(req.NamespacedName)
		return reconcile.Result{}, nil
	}

	targetAddr := net.JoinHostPort(svc.Spec.ClusterIP, strconv.Itoa(int(svc.Spec.Ports[0].Port)))
	proxyProto := svc.Annotations[annProxyProtocol] == proxyProtocolVersion1Value

	var oidcCfg *oidcConfig
	if mode == modeHTTPS && strings.EqualFold(svc.Annotations[annAuthMode], authModeOIDC) {
		if !strings.EqualFold(svc.Annotations[annOIDCDynamicClient], "true") {
			s.logger.Info("ignoring service: oidc auth requires dynamic client registration",
				"name", req.Name, "namespace", req.Namespace)
			s.router.RemoveRoute(req.NamespacedName)
			return reconcile.Result{}, nil
		}
		issuer := strings.TrimSpace(svc.Annotations[annOIDCIssuer])
		if issuer == "" {
			s.logger.Info("ignoring service: missing oidc issuer for auth mode OIDC",
				"name", req.Name, "namespace", req.Namespace)
			s.router.RemoveRoute(req.NamespacedName)
			return reconcile.Result{}, nil
		}
		oidcCfg = &oidcConfig{
			Issuer:         issuer,
			UsernameHeader: strings.TrimSpace(svc.Annotations[annOIDCUsernameHeader]),
			EmailHeader:    strings.TrimSpace(svc.Annotations[annOIDCEmailHeader]),
			RequireGroup:   strings.TrimSpace(svc.Annotations[annRequireGroup]),
		}
	}

	if err := s.router.SetRoute(req.NamespacedName, hostnames, targetAddr, mode, proxyProto, oidcCfg); err != nil {
		return reconcile.Result{}, err
	}
	s.logger.Info("configured service route",
		"name", req.Name,
		"namespace", req.Namespace,
		"mode", mode,
		"hostnames", len(hostnames),
		"target", targetAddr,
		"oidc", oidcCfg != nil,
	)
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
	for p := range strings.SplitSeq(v, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}
