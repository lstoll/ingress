package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/lstoll/ingress/internal/mtls"
)

func TestBackendMTLSTunnel(t *testing.T) {
	fix := mtls.NewTestFixture(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("via-sidecar"))
	}))
	t.Cleanup(backend.Close)

	sidecarLn := startTestSidecar(t, fix, backend.Listener.Addr().String())

	dialer := newTestBackendDialer(t, fix)

	conn, err := dialer.DialContext(context.Background(), "tcp", sidecarLn.Addr().String(), "backend-sidecar", true)
	if err != nil {
		t.Fatalf("dial sidecar: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: ignored\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "via-sidecar" {
		t.Fatalf("unexpected body %q", string(body))
	}
}

func TestBackendMTLSRejectsWrongSVID(t *testing.T) {
	fix := mtls.NewTestFixture(t)

	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plainLn.Close() })

	serverCfg, err := mtls.ServerConfig(fix.ServerIdentity(), fix.CAFile, fix.WrongSVID)
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(plainLn, serverCfg)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}()

	dialer := newTestBackendDialer(t, fix)

	_, err = dialer.DialContext(context.Background(), "tcp", ln.Addr().String(), "backend-sidecar", true)
	if err == nil {
		t.Fatal("expected handshake failure for wrong SVID")
	}
}

func TestServiceReconcileBackendMTLSRequiresIngressConfig(t *testing.T) {
	ctx := context.Background()
	router := newIngressRouter(testLogger(), ctx, nil)
	r := &ServiceReconciler{
		logger:   testLogger(),
		router:   router,
		instance: "ingress1",
	}

	svc := backendMTLSTestService("backend-mtls", true)
	r.Client = fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc).Build()

	if _, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: svc.Name}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, ok := router.RouteFor("mtls.example.com"); ok {
		t.Fatal("expected no route without ingress backend mTLS config")
	}
}

func TestServiceReconcileBackendMTLSConfigured(t *testing.T) {
	ctx := context.Background()
	fix := mtls.NewTestFixture(t)

	router := newIngressRouter(testLogger(), ctx, nil)
	router.backendDialer = newTestBackendDialer(t, fix)
	r := &ServiceReconciler{
		logger:   testLogger(),
		router:   router,
		instance: "ingress1",
	}

	svc := backendMTLSTestService("backend-mtls", true)
	r.Client = fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc).Build()

	if _, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: svc.Name}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	route, ok := router.RouteFor("mtls.example.com")
	if !ok {
		t.Fatal("expected route")
	}
	if !route.BackendMTLS {
		t.Fatal("expected backend mTLS enabled on route")
	}
}

func TestBackendMTLSClientCredentialBundle(t *testing.T) {
	fix := mtls.NewTestFixture(t)
	bundle := fix.ClientBundleFile(t)

	reloader, err := mtls.NewClientReloader(testLogger(), mtls.IdentityFiles{BundleFile: bundle}, fix.CAFile, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dialer := newBackendDialer(reloader)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(backend.Close)

	sidecarLn := startTestSidecar(t, fix, backend.Listener.Addr().String())

	conn, err := dialer.DialContext(context.Background(), "tcp", sidecarLn.Addr().String(), "backend-sidecar", true)
	if err != nil {
		t.Fatalf("dial with bundle identity: %v", err)
	}
	_ = conn.Close()
}

func backendMTLSTestService(name string, backendMTLS bool) *corev1.Service {
	annotations := map[string]string{
		annMode:          modeHTTPS,
		annHTTPHostnames: "mtls.example.com",
	}
	if backendMTLS {
		annotations[annBackendMTLS] = "true"
	}
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels: map[string]string{
				labelIngressInstance: "ingress1",
			},
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.50",
			Ports: []corev1.ServicePort{
				{Port: 8080},
			},
		},
	}
}

func startTestSidecar(t *testing.T, fix mtls.TestFixture, forwardAddr string) net.Listener {
	t.Helper()

	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	serverCfg, err := mtls.ServerConfig(fix.ServerIdentity(), fix.CAFile, fix.IngressSVID)
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(plainLn, serverCfg)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxySidecarConn(logger, conn, forwardAddr)
		}
	}()

	t.Cleanup(func() { _ = plainLn.Close() })
	return ln
}

func proxySidecarConn(logger *slog.Logger, client net.Conn, forwardAddr string) {
	defer func() { _ = client.Close() }()

	upstream, err := net.Dial("tcp", forwardAddr)
	if err != nil {
		logger.Warn("dialing forward target", "forward", forwardAddr, "error", err)
		return
	}
	defer func() { _ = upstream.Close() }()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, client)
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
	}()
	wg.Wait()
}

func newTestBackendDialer(t *testing.T, fix mtls.TestFixture) *backendDialer {
	t.Helper()
	reloader, err := mtls.NewClientReloader(testLogger(), fix.ClientIdentity(), fix.CAFile, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return newBackendDialer(reloader)
}

func TestBackendMTLSReloaderPicksUpRotatedClientCert(t *testing.T) {
	fix := mtls.NewTestFixture(t)
	reloader, err := mtls.NewClientReloader(testLogger(), fix.ClientIdentity(), fix.CAFile, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dialer := newBackendDialer(reloader)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(backend.Close)

	sidecarLn := startTestSidecar(t, fix, backend.Listener.Addr().String())

	dial := func() error {
		conn, err := dialer.DialContext(context.Background(), "tcp", sidecarLn.Addr().String(), "backend-sidecar", true)
		if err != nil {
			return err
		}
		return conn.Close()
	}
	if err := dial(); err != nil {
		t.Fatalf("initial dial: %v", err)
	}

	fix.RotateClientCert(t)
	if err := reloader.ReloadOnce(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := dial(); err != nil {
		t.Fatalf("dial after rotation: %v", err)
	}
}
