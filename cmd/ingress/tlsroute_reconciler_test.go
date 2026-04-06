package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"inet.af/tcpproxy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestTLSRouteReconcile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	testbinPath := filepath.Join("..", "..", "testbin")
	binaryAssetsPath := filepath.Join(testbinPath, "bin")
	if _, err := os.Stat(binaryAssetsPath); os.IsNotExist(err) {
		t.Skipf("%s not found, skipping", binaryAssetsPath)
	}
	testEnv := &envtest.Environment{
		BinaryAssetsDirectory: binaryAssetsPath,
		CRDDirectoryPaths:     []string{filepath.Join(testbinPath, "crds")},
	}

	cfg, err := testEnv.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer testEnv.Stop()

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}

	rdb := &routedb{
		logger: testLogger(),
		routes: map[string]route{},
	}

	r := &TLSRouteReconciler{
		logger: testLogger(),
		rdb:    rdb,
	}

	mgr, err := newMgr(cfg, r)
	if err != nil {
		t.Fatal(err)
	}

	mgrErr := make(chan error, 1)
	go func() {
		err := mgr.Start(ctx)
		cancel()
		mgrErr <- err
	}()

	svcName := "backend-svc"
	svcNamespace := "default"
	portNumber := int32(1234)

	// Create Backend Service
	backendSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName,
			Namespace: svcNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Port: portNumber},
			},
			ClusterIP: "10.0.0.99",
		},
	}
	if err := c.Create(ctx, backendSvc); err != nil {
		t.Fatal(err)
	}

	kindService := gatewayv1.Kind("Service")
	port1234 := gatewayv1.PortNumber(1234)
	tlsRouteName := "example-route"

	route1 := &gatewayv1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tlsRouteName,
			Namespace: svcNamespace,
		},
		Spec: gatewayv1.TLSRouteSpec{
			Hostnames: []gatewayv1.Hostname{
				gatewayv1.Hostname("foo.example.com"),
			},
			Rules: []gatewayv1.TLSRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: gatewayv1.ObjectName(svcName),
								Port: &port1234,
								Kind: &kindService,
							},
						},
					},
				},
			},
		},
	}

	if err := c.Create(ctx, route1); err != nil {
		t.Fatal(err)
	}

	want := map[string]route{
		"foo.example.com": {
			Owner: types.NamespacedName{
				Namespace: svcNamespace,
				Name:      tlsRouteName,
			},
			Proxy: &tcpproxy.DialProxy{
				Addr:                 "10.0.0.99:1234",
				ProxyProtocolVersion: 1,
			},
		},
	}

	// Poll until reconciled
	start := time.Now()
	var diff string
	for {
		rdb.routesMu.RLock()
		diff = cmp.Diff(want, rdb.routes, cmpopts.IgnoreUnexported(tcpproxy.DialProxy{}))
		rdb.routesMu.RUnlock()
		if diff == "" || time.Since(start) > 5*time.Second {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// If it timed out, print the error diff
	if diff != "" {
		t.Errorf("route db mismatch (-want +got):\n%s", diff)
	}

	select {
	case err := <-mgrErr:
		if err != nil {
			t.Fatalf("manager exited with error: %v", err)
		}
	default:
		// manager still running, as expected for this test
	}
}
