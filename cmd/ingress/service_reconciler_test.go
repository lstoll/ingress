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
)

func TestServiceReconcile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	testbinPath := filepath.Join("..", "..", "testbin")
	binaryAssetsPath := filepath.Join(testbinPath, "bin")
	if _, err := os.Stat(binaryAssetsPath); os.IsNotExist(err) {
		t.Skipf("%s not found, skipping", binaryAssetsPath)
	}
	testEnv := &envtest.Environment{
		BinaryAssetsDirectory: binaryAssetsPath,
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

	r := &ServiceReconciler{
		logger:   testLogger(),
		rdb:      rdb,
		instance: "ingress1",
	}

	svcNamespace := "default"
	mgr, err := newMgr(cfg, svcNamespace, r)
	if err != nil {
		t.Fatal(err)
	}

	mgrErr := make(chan error, 1)
	go func() {
		err := mgr.Start(ctx)
		cancel()
		mgrErr <- err
	}()

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
	if err := c.Create(ctx, passSvc); err != nil {
		t.Fatal(err)
	}

	termSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-term",
			Namespace: svcNamespace,
			Labels: map[string]string{
				labelIngressInstance: "ingress1",
			},
			Annotations: map[string]string{
				annMode:         modeTLSTermination,
				annSNIHostnames: "bar.example.com",
			},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Port: 8080},
			},
			ClusterIP: "10.0.0.98",
		},
	}
	if err := c.Create(ctx, termSvc); err != nil {
		t.Fatal(err)
	}

	want := map[string]route{
		"foo.example.com": {
			Owner: types.NamespacedName{
				Namespace: svcNamespace,
				Name:      "backend-pass",
			},
			TargetAddr:   "10.0.0.99:443",
			TerminateTLS: false,
			Proxy: &tcpproxy.DialProxy{
				Addr:                 "10.0.0.99:443",
				ProxyProtocolVersion: 1,
			},
		},
		"bar.example.com": {
			Owner: types.NamespacedName{
				Namespace: svcNamespace,
				Name:      "backend-term",
			},
			TargetAddr:   "10.0.0.98:8080",
			TerminateTLS: true,
			Proxy:        nil,
		},
	}

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
	if diff != "" {
		t.Errorf("route db mismatch (-want +got):\n%s", diff)
	}

	select {
	case err := <-mgrErr:
		if err != nil {
			t.Fatalf("manager exited with error: %v", err)
		}
	default:
	}
}
