package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"inet.af/tcpproxy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestReconcile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := os.Stat("../../testbin"); os.IsNotExist(err) {
		t.Skip("../../testbin not found, skipping")
	}
	testEnv := &envtest.Environment{
		BinaryAssetsDirectory: "../../testbin",
	}

	// KUBEBUILDER_ATTACH_CONTROL_PLANE_OUTPUT=true
	cfg, err := testEnv.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer testEnv.Stop()

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	rdb := &routedb{
		logger: testLogger(),
		routes: map[string]route{},
	}

	r := &ServiceReconciler{
		logger: testLogger(),
		rdb:    rdb,
		coreV1: cs.CoreV1(),
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

	for _, tc := range []struct {
		Name   string
		Insert []corev1.Service
		Delete []types.NamespacedName
		Want   map[string]route
	}{
		{
			Name: "Initial Load",
			Insert: []corev1.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "default",
						Name:      "service-1",
						Annotations: map[string]string{
							hostnamesAnnotation: "service1.com",
						},
					},
					Spec: corev1.ServiceSpec{
						Type:              corev1.ServiceTypeLoadBalancer,
						LoadBalancerClass: sPtr(sniLbClass),
						Ports: []corev1.ServicePort{
							{
								Port: 1234,
							},
						},
						ClusterIP: "10.0.0.100",
					},
				},
			},
			Want: map[string]route{
				"service1.com": {
					Owner: types.NamespacedName{
						Namespace: "default",
						Name:      "service-1",
					},
					Proxy: &tcpproxy.DialProxy{
						Addr:                 "10.0.0.100:1234",
						ProxyProtocolVersion: 1,
					},
				},
			},
		},
		{
			Name: "Deletion",
			Insert: []corev1.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "default",
						Name:      "service-2",
						Annotations: map[string]string{
							hostnamesAnnotation: "service2.com",
						},
					},
					Spec: corev1.ServiceSpec{
						Type:              corev1.ServiceTypeLoadBalancer,
						LoadBalancerClass: sPtr(sniLbClass),
						Ports: []corev1.ServicePort{
							{
								Port: 1234,
							},
						},
						ClusterIP: "10.0.0.102",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "default",
						Name:      "service-3",
						Annotations: map[string]string{
							hostnamesAnnotation: "service3.com",
						},
					},
					Spec: corev1.ServiceSpec{
						Type:              corev1.ServiceTypeLoadBalancer,
						LoadBalancerClass: sPtr(sniLbClass),
						Ports: []corev1.ServicePort{
							{
								Port: 1234,
							},
						},
						ClusterIP: "10.0.0.103",
					},
				},
			},
			Delete: []types.NamespacedName{
				{
					Namespace: "defaultt",
					Name:      "service-3",
				},
			},
			Want: map[string]route{
				"service2.com": {
					Owner: types.NamespacedName{
						Namespace: "default",
						Name:      "service-2",
					},
					Proxy: &tcpproxy.DialProxy{
						Addr:                 "10.0.0.102:1234",
						ProxyProtocolVersion: 1,
					},
				},
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			for _, is := range tc.Insert {
				if _, err := cs.CoreV1().Services(is.Namespace).Create(ctx, &is, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			for _, ds := range tc.Delete {
				if err := cs.CoreV1().Services(ds.Namespace).Delete(ctx, ds.Name, metav1.DeleteOptions{}); err != nil {
					t.Fatal(err)
				}
			}

			time.Sleep(1 * time.Second) // TODO - how do we wait for reconciles done / be steady

			if diff := cmp.Diff(tc.Want, rdb.routes); diff != "" {
				t.Error(diff)
			}
		})
	}

	// check if there's a mgr error
	select {
	case <-mgrErr:
		t.Fatal(err)
	default:
		cancel()
	}
}

func sPtr(s string) *string {
	return &s
}
