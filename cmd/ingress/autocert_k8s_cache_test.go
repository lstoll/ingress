package main

import (
	"bytes"
	"context"
	"encoding/base64"
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

// TestAutocertCacheMigratesDoubleEncodedData verifies that values written by
// the old double-base64 format are transparently decoded and re-written as raw
// bytes. This migration path can be removed once all secrets have been
// re-written by a Put call.
func TestAutocertCacheMigratesDoubleEncodedData(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()

	// Simulate old format: base64-encode the data before storing in Secret.Data.
	raw := []byte("old-cert-data")
	encoded := secKeyEnc.EncodeToString([]byte("migrated.localtest.me"))
	oldEncoded := []byte(base64.StdEncoding.EncodeToString(raw))

	if _, err := client.CoreV1().Secrets("default").Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "default",
			Name:        "ingress-autocert",
			Annotations: map[string]string{keyNameAnnotation + encoded: "migrated.localtest.me"},
		},
		Data: map[string][]byte{encoded: oldEncoded},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	cache := &autocertCache{
		clientset:       client,
		secretNamespace: "default",
		secretName:      "ingress-autocert",
	}

	got, err := cache.Get(ctx, "migrated.localtest.me")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("Get() = %q, want %q (should decode double-encoded value)", string(got), string(raw))
	}

	// Verify the secret was re-written with raw bytes.
	sec, err := client.CoreV1().Secrets("default").Get(ctx, "ingress-autocert", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get secret error = %v", err)
	}
	if bytes.Equal(sec.Data[encoded], oldEncoded) {
		t.Fatal("secret data should have been migrated to raw bytes")
	}
	if !bytes.Equal(sec.Data[encoded], raw) {
		t.Fatalf("migrated data = %q, want %q", string(sec.Data[encoded]), string(raw))
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
