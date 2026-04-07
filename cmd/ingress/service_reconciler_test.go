package main

import (
	"context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"testing"
)

func TestServiceReconcile(t *testing.T) {
	ctx := context.Background()

	router := newIngressRouter(testLogger(), ctx, nil)
	r := &ServiceReconciler{
		logger:   testLogger(),
		router:   router,
		instance: "ingress1",
	}

	svcNamespace := "default"

	passSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-pass",
			Namespace: svcNamespace,
			Labels: map[string]string{
				labelIngressInstance: "ingress1",
			},
			Annotations: map[string]string{
				annMode:          modeTLSPassthrough,
				annSNIHostnames:  "foo.example.com",
				annProxyProtocol: proxyProtocolVersion1Value,
			},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Port: 443},
			},
			ClusterIP: "10.0.0.99",
		},
	}

	termSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-term",
			Namespace: svcNamespace,
			Labels: map[string]string{
				labelIngressInstance: "ingress1",
			},
			Annotations: map[string]string{
				annMode:          modeHTTPS,
				annHTTPHostnames: "bar.example.com",
			},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Port: 8080},
			},
			ClusterIP: "10.0.0.98",
		},
	}

	r.Client = fake.NewClientBuilder().WithScheme(scheme).WithObjects(passSvc, termSvc).Build()
	if _, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: svcNamespace, Name: passSvc.Name}}); err != nil {
		t.Fatalf("reconcile pass service: %v", err)
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: svcNamespace, Name: termSvc.Name}}); err != nil {
		t.Fatalf("reconcile term service: %v", err)
	}

	gotPass, ok := router.RouteFor("foo.example.com")
	if !ok {
		t.Fatalf("expected foo.example.com route")
	}
	if gotPass.Owner != (types.NamespacedName{Namespace: svcNamespace, Name: "backend-pass"}) {
		t.Fatalf("unexpected pass owner: %#v", gotPass.Owner)
	}
	if gotPass.TargetAddr != "10.0.0.99:443" {
		t.Fatalf("unexpected pass target addr: %s", gotPass.TargetAddr)
	}
	if gotPass.Mode != modeTLSPassthrough {
		t.Fatalf("unexpected pass mode: %s", gotPass.Mode)
	}
	if gotPass.Proxy == nil || gotPass.Proxy.ProxyProtocolVersion != 1 {
		t.Fatalf("expected pass proxy with proxy protocol v1")
	}

	gotTerm, ok := router.RouteFor("bar.example.com")
	if !ok {
		t.Fatalf("expected bar.example.com route")
	}
	if gotTerm.Owner != (types.NamespacedName{Namespace: svcNamespace, Name: "backend-term"}) {
		t.Fatalf("unexpected term owner: %#v", gotTerm.Owner)
	}
	if gotTerm.TargetAddr != "10.0.0.98:8080" {
		t.Fatalf("unexpected term target addr: %s", gotTerm.TargetAddr)
	}
	if gotTerm.Mode != modeHTTPS {
		t.Fatalf("unexpected term mode: %s", gotTerm.Mode)
	}
	if gotTerm.Proxy != nil {
		t.Fatalf("expected nil proxy for https mode")
	}
	if gotTerm.HTTPProxy == nil {
		t.Fatalf("expected HTTP proxy for https mode")
	}
}

func TestServiceReconcileRemovesRouteForWrongInstance(t *testing.T) {
	ctx := context.Background()
	router := newIngressRouter(testLogger(), context.Background(), nil)
	r := &ServiceReconciler{
		logger:   testLogger(),
		router:   router,
		instance: "ingress1",
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend",
			Namespace: "default",
			Labels: map[string]string{
				labelIngressInstance: "other-instance",
			},
			Annotations: map[string]string{
				annMode:         modeTLSPassthrough,
				annSNIHostnames: "ignored.example.com",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.99",
			Ports: []corev1.ServicePort{
				{Port: 443},
			},
		},
	}
	r.Client = fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc).Build()

	if _, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "backend"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, ok := router.RouteFor("ignored.example.com"); ok {
		t.Fatalf("did not expect route for non-matching instance")
	}
}

func TestServiceReconcileOIDCConfigValidation(t *testing.T) {
	ctx := context.Background()
	router := newIngressRouter(testLogger(), ctx, nil)
	r := &ServiceReconciler{
		logger:   testLogger(),
		router:   router,
		instance: "ingress1",
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-https-auth",
			Namespace: "default",
			Labels: map[string]string{
				labelIngressInstance: "ingress1",
			},
			Annotations: map[string]string{
				annMode:               modeHTTPS,
				annHTTPHostnames:      "auth.example.com",
				annAuthMode:           authModeOIDC,
				annOIDCDynamicClient:  "false",
				annOIDCIssuer:         "https://issuer.example.com",
				annOIDCUsernameHeader: "Remote-User",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.98",
			Ports: []corev1.ServicePort{
				{Port: 8080},
			},
		},
	}
	r.Client = fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc).Build()

	if _, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: svc.Name}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, ok := router.RouteFor("auth.example.com"); ok {
		t.Fatalf("expected no route when oidc dynamic client is not true")
	}
}
