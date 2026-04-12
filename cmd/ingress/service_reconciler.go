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
	// labelIngressInstance is the label used to identify which ingress instance should manage this service.
	labelIngressInstance = "ingress.lds.li/instance"
	// annMode defines the proxying mode: tls-passthrough, tls-termination, or https.
	annMode = "ingress.lds.li/mode"
	// annSNIHostnames is a comma-separated list of hostnames for SNI-based routing (tls-passthrough/termination).
	annSNIHostnames = "ingress.lds.li/sni-hostnames"
	// annHTTPHostnames is a comma-separated list of hostnames for HTTP-based routing (https).
	annHTTPHostnames = "ingress.lds.li/hostnames"
	// annProxyProtocol enables Proxy Protocol v1 if set to "v1".
	annProxyProtocol = "ingress.lds.li/proxy-protocol"
	// annAuthMode sets the authentication mode, e.g., "OIDC".
	annAuthMode = "ingress.lds.li/auth-mode"
	// annOIDCIssuer is the OIDC provider issuer URL.
	annOIDCIssuer = "ingress.lds.li/oidc-issuer"
	// annOIDCDynamicClient enables dynamic OIDC client registration if set to "true".
	annOIDCDynamicClient = "ingress.lds.li/oidc-dynamic-client"
	// annOIDCAllowUnauthenticated allows unauthenticated requests to reach the backend if set to "true".
	annOIDCAllowUnauthenticated = "ingress.lds.li/oidc-allow-unauthenticated"
	// annOIDCLoginPath is the path that triggers the OIDC login flow.
	annOIDCLoginPath = "ingress.lds.li/oidc-login-path"
	// annOIDCLogoutPath is the path that triggers the OIDC logout flow.
	annOIDCLogoutPath = "ingress.lds.li/oidc-logout-path"
	// annOIDCClientID is an explicit OIDC client ID to use instead of dynamic registration.
	annOIDCClientID = "ingress.lds.li/oidc-client-id"
	// annOIDCClientSecret is an explicit OIDC client secret to use instead of dynamic registration.
	annOIDCClientSecret = "ingress.lds.li/oidc-client-secret"
	// annOIDCUsernameHeader is the header to populate with the preferred_username claim.
	annOIDCUsernameHeader = "ingress.lds.li/oidc-preferred-username-header"
	// annOIDCEmailHeader is the header to populate with the email claim.
	annOIDCEmailHeader = "ingress.lds.li/oidc-email-header"
	// annOIDCNameHeader is the header to populate with the name claim.
	annOIDCNameHeader = "ingress.lds.li/oidc-name-header"
	// annOIDCBypassPatterns is a comma-separated list of path prefixes to bypass OIDC authentication.
	annOIDCBypassPatterns = "ingress.lds.li/oidc-bypass-patterns"
	// annRequireGroup is an OIDC group name required for successful authentication.
	annRequireGroup = "ingress.lds.li/require-group"

	// modeTLSPassthrough is the mode for transparently passing through TLS connections to the backend.
	modeTLSPassthrough = "tls-passthrough"
	// modeTLSTermination is the mode for terminating TLS at the ingress and proxying the connection to the backend.
	modeTLSTermination = "tls-termination"
	// modeHTTPS is the mode for terminating TLS and proxying HTTP requests to the backend.
	modeHTTPS = "https"
	// authModeOIDC is the OIDC authentication mode value.
	authModeOIDC = "OIDC"
	// proxyProtocolVersion1Value is the value to enable Proxy Protocol v1.
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
		issuer := strings.TrimSpace(svc.Annotations[annOIDCIssuer])
		if issuer == "" {
			s.logger.Info("ignoring service: missing oidc issuer for auth mode OIDC",
				"name", req.Name, "namespace", req.Namespace)
			s.router.RemoveRoute(req.NamespacedName)
			return reconcile.Result{}, nil
		}

		clientID := strings.TrimSpace(svc.Annotations[annOIDCClientID])
		clientSecret := strings.TrimSpace(svc.Annotations[annOIDCClientSecret])
		dynamic := strings.EqualFold(svc.Annotations[annOIDCDynamicClient], "true")

		if !dynamic && (clientID == "" || clientSecret == "") {
			s.logger.Info("ignoring service: oidc auth requires dynamic client registration or explicit client id/secret",
				"name", req.Name, "namespace", req.Namespace)
			s.router.RemoveRoute(req.NamespacedName)
			return reconcile.Result{}, nil
		}

		oidcCfg = &oidcConfig{
			Issuer:               issuer,
			ClientID:             clientID,
			ClientSecret:         clientSecret,
			UsernameHeader:       strings.TrimSpace(svc.Annotations[annOIDCUsernameHeader]),
			EmailHeader:          strings.TrimSpace(svc.Annotations[annOIDCEmailHeader]),
			NameHeader:           strings.TrimSpace(svc.Annotations[annOIDCNameHeader]),
			BypassPatterns:       splitCSV(svc.Annotations[annOIDCBypassPatterns]),
			RequireGroup:         strings.TrimSpace(svc.Annotations[annRequireGroup]),
			AllowUnauthenticated: strings.EqualFold(svc.Annotations[annOIDCAllowUnauthenticated], "true"),
			LoginPath:            strings.TrimSpace(svc.Annotations[annOIDCLoginPath]),
			LogoutPath:           strings.TrimSpace(svc.Annotations[annOIDCLogoutPath]),
		}
	}

	if err := s.router.SetRoute(req.NamespacedName, hostnames, targetAddr, mode, proxyProto, oidcCfg); err != nil {
		reconcileTotal.WithLabelValues("error").Inc()
		return reconcile.Result{}, err
	}
	reconcileTotal.WithLabelValues("configured").Inc()
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

