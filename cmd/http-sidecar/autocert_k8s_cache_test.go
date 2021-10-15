package main

import (
	"bytes"
	"context"
	"flag"
	"testing"

	"golang.org/x/crypto/acme/autocert"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	kubeconfig = flag.String("kubeconfig", "", "path to kubeconfig to test secret cache, test skipped if not set")
	secret     = flag.String("secret", "default/ingress-test", "secret to test against")
)

func TestK8SAutocertCache(t *testing.T) {
	if *kubeconfig == "" {
		t.Skip("-kubeconfig not set")
	}

	ctx := context.Background()

	kc, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		t.Fatalf("building kubeconfig from %s: %v", *kubeconfig, err)
	}
	cs, err := kubernetes.NewForConfig(kc)
	if err != nil {
		t.Fatalf("building kubernetes clientset: %v", err)
	}

	secretNamespace, secretName, err := splitKubernetesPath(*secret)
	if err != nil {
		t.Fatal(err)
	}

	// ensure secret doesn't exist

	if err := cs.CoreV1().Secrets(secretNamespace).Delete(ctx, secretName, metav1.DeleteOptions{}); err != nil {
		if !apierrors.IsNotFound(err) {
			t.Fatal(err)
		}
	}

	testCert := []byte("---- BEGIN CERIFICATE ---")

	cache := &autocertCache{
		clientset:       cs,
		secretNamespace: secretNamespace,
		secretName:      secretName,
	}

	if _, err := cache.Get(ctx, "www.website.com"); err != autocert.ErrCacheMiss {
		t.Errorf("wanted autocert.ErrCacheMiss, got: %v", err)
	}

	if err := cache.Put(ctx, "www.website.com", testCert); err != nil {
		t.Errorf("unexptected error putting cert: %v", err)
	}

	got, err := cache.Get(ctx, "www.website.com")
	if err != nil {
		t.Errorf("unexptected error getting cert: %v", err)
	}

	if !bytes.Equal(testCert, got) {
		t.Errorf("wanted to get %s, but got: %v", string(testCert), string(got))
	}

	if err := cache.Delete(ctx, "www.website.com"); err != nil {
		t.Errorf("unexptected error deleting cert: %v", err)
	}

	if _, err := cache.Get(ctx, "www.website.com"); err != autocert.ErrCacheMiss {
		t.Errorf("wanted autocert.ErrCacheMiss after deleting, got: %v", err)
	}
}
