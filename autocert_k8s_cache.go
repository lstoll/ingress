package main

import (
	"context"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/acme/autocert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
)

var _ autocert.Cache = (*autocertCache)(nil)

// autocertCache is an implementation of the store that autocert uses to manage
// certificates. we stick it all into a single kubernetes secret, as in our
// usage we're unlikely to have more than one of them
type autocertCache struct {
	clientset       kubernetes.Interface
	secretNamespace string
	secretName      string
}

// Get returns a certificate data for the specified key.
// If there's no such key, Get returns ErrCacheMiss.
func (a *autocertCache) Get(ctx context.Context, key string) ([]byte, error) {
	sec, err := a.clientset.CoreV1().Secrets(a.secretNamespace).Get(ctx, a.secretName, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			// unexpected
			return nil, fmt.Errorf("fetching %s/%s from destination: %v", a.secretNamespace, a.secretName, err)
		}
		return nil, autocert.ErrCacheMiss
	}

	v, ok := sec.Data[key]
	if !ok {
		return nil, autocert.ErrCacheMiss
	}

	dec, err := base64.StdEncoding.DecodeString(string(v))
	if err != nil {
		return nil, fmt.Errorf("base64 decoding secret: %v", err)
	}
	return dec, nil
}

// Put stores the data in the cache under the specified key.
// Underlying implementations may use any data storage format,
// as long as the reverse operation, Get, results in the original data.
func (a *autocertCache) Put(ctx context.Context, key string, data []byte) error {
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var needsCreate bool
		sec, err := a.clientset.CoreV1().Secrets(a.secretNamespace).Get(ctx, a.secretName, metav1.GetOptions{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				// unexpected
				return err
			}
			// item wasn't found, start with a new one
			needsCreate = true
			sec = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: a.secretNamespace,
					Name:      a.secretName,
				},
				Data: map[string][]byte{},
			}
		}

		sec.Data[key] = []byte(base64.StdEncoding.EncodeToString(data))

		if needsCreate {
			// need to return the raw error so the retry can detect a conflict and correctly retry.
			// TODO at some point I hope error wrapping is supported, if it is return more descriptive with %w
			if _, err := a.clientset.CoreV1().Secrets(a.secretNamespace).Create(context.TODO(), sec, metav1.CreateOptions{}); err != nil {
				return err
			}
		} else {
			if _, err := a.clientset.CoreV1().Secrets(a.secretNamespace).Update(context.TODO(), sec, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("putting in secret %s/%s: %v", a.secretNamespace, a.secretName, err)
	}
	return nil
}

// Delete removes a certificate data from the cache under the specified key.
// If there's no such key in the cache, Delete returns nil.
func (a *autocertCache) Delete(ctx context.Context, key string) error {
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		sec, err := a.clientset.CoreV1().Secrets(a.secretNamespace).Get(ctx, a.secretName, metav1.GetOptions{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				// unexpected
				return err
			}
			return nil
		}

		if _, ok := sec.Data[key]; !ok {
			return nil
		}

		delete(sec.Data, key)

		if _, err := a.clientset.CoreV1().Secrets(a.secretNamespace).Update(context.TODO(), sec, metav1.UpdateOptions{}); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("deleting %s from secret %s/%s: %v", key, a.secretNamespace, a.secretName, err)
	}
	return nil
}
