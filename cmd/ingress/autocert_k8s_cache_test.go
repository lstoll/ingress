package main

import (
	"bytes"
	"context"
	"testing"

	"golang.org/x/crypto/acme/autocert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAutocertCachePutGetDelete(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	cache := &autocertCache{
		clientset:       client,
		secretNamespace: "default",
		secretName:      "ingress-autocert",
	}

	if _, err := cache.Get(ctx, "app.localtest.me"); err != autocert.ErrCacheMiss {
		t.Fatalf("expected ErrCacheMiss before put, got %v", err)
	}

	want := []byte("test-certificate-bytes")
	if err := cache.Put(ctx, "app.localtest.me", want); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	got, err := cache.Get(ctx, "app.localtest.me")
	if err != nil {
		t.Fatalf("Get() after put error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Get() = %q, want %q", string(got), string(want))
	}

	if err := cache.Delete(ctx, "app.localtest.me"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := cache.Get(ctx, "app.localtest.me"); err != autocert.ErrCacheMiss {
		t.Fatalf("expected ErrCacheMiss after delete, got %v", err)
	}
}

func TestAutocertCachePutHandlesNilMapsOnExistingSecret(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	if _, err := client.CoreV1().Secrets("default").Create(ctx, newEmptySecret("default", "ingress-autocert"), metav1.CreateOptions{}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	cache := &autocertCache{
		clientset:       client,
		secretNamespace: "default",
		secretName:      "ingress-autocert",
	}

	if err := cache.Put(ctx, "app.localtest.me", []byte("cert-data")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if _, err := cache.Get(ctx, "app.localtest.me"); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
}

func newEmptySecret(namespace, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
	}
}
