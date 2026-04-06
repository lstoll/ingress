package main

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/acme/autocert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
)

const keyNameAnnotation = "key-mapping/"

var _ autocert.Cache = (*autocertCache)(nil)

var secKeyEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// autocertCache stores autocert items in one kubernetes secret.
type autocertCache struct {
	clientset       kubernetes.Interface
	secretNamespace string
	secretName      string
}

func (a *autocertCache) Get(ctx context.Context, key string) ([]byte, error) {
	sec, err := a.clientset.CoreV1().Secrets(a.secretNamespace).Get(ctx, a.secretName, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			slog.Error("autocert cache get failed", "namespace", a.secretNamespace, "name", a.secretName, "key", key, "error", err)
			return nil, fmt.Errorf("fetching %s/%s from destination: %v", a.secretNamespace, a.secretName, err)
		}
		slog.Debug("autocert cache miss: secret not found", "namespace", a.secretNamespace, "name", a.secretName, "key", key)
		return nil, autocert.ErrCacheMiss
	}

	v, ok := sec.Data[secKeyEnc.EncodeToString([]byte(key))]
	if !ok {
		slog.Debug("autocert cache miss: key not found", "namespace", a.secretNamespace, "name", a.secretName, "key", key)
		return nil, autocert.ErrCacheMiss
	}

	dec, err := base64.StdEncoding.DecodeString(string(v))
	if err != nil {
		slog.Error("autocert cache decode failed", "namespace", a.secretNamespace, "name", a.secretName, "key", key, "error", err)
		return nil, fmt.Errorf("base64 decoding secret: %v", err)
	}
	slog.Debug("autocert cache hit", "namespace", a.secretNamespace, "name", a.secretName, "key", key)
	return dec, nil
}

func (a *autocertCache) Put(ctx context.Context, key string, data []byte) error {
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var needsCreate bool
		sec, err := a.clientset.CoreV1().Secrets(a.secretNamespace).Get(ctx, a.secretName, metav1.GetOptions{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return err
			}
			needsCreate = true
			sec = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   a.secretNamespace,
					Name:        a.secretName,
					Annotations: map[string]string{},
				},
				Data: map[string][]byte{},
			}
		}
		if sec.Annotations == nil {
			sec.Annotations = map[string]string{}
		}
		if sec.Data == nil {
			sec.Data = map[string][]byte{}
		}

		encoded := secKeyEnc.EncodeToString([]byte(key))
		sec.Annotations[keyNameAnnotation+encoded] = key
		sec.Data[encoded] = []byte(base64.StdEncoding.EncodeToString(data))

		if needsCreate {
			if _, err := a.clientset.CoreV1().Secrets(a.secretNamespace).Create(context.TODO(), sec, metav1.CreateOptions{}); err != nil {
				return err
			}
			slog.Info("autocert cache secret created", "namespace", a.secretNamespace, "name", a.secretName)
		} else {
			if _, err := a.clientset.CoreV1().Secrets(a.secretNamespace).Update(context.TODO(), sec, metav1.UpdateOptions{}); err != nil {
				return err
			}
			slog.Debug("autocert cache secret updated", "namespace", a.secretNamespace, "name", a.secretName)
		}
		return nil
	})
	if err != nil {
		slog.Error("autocert cache put failed", "namespace", a.secretNamespace, "name", a.secretName, "key", key, "error", err)
		return fmt.Errorf("putting in secret %s/%s: %v", a.secretNamespace, a.secretName, err)
	}
	slog.Info("autocert cache put", "namespace", a.secretNamespace, "name", a.secretName, "key", key)
	return nil
}

func (a *autocertCache) Delete(ctx context.Context, key string) error {
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		sec, err := a.clientset.CoreV1().Secrets(a.secretNamespace).Get(ctx, a.secretName, metav1.GetOptions{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return err
			}
			return nil
		}

		encoded := secKeyEnc.EncodeToString([]byte(key))
		if _, ok := sec.Data[encoded]; !ok {
			return nil
		}

		delete(sec.Data, encoded)
		delete(sec.Annotations, keyNameAnnotation+encoded)

		if _, err := a.clientset.CoreV1().Secrets(a.secretNamespace).Update(context.TODO(), sec, metav1.UpdateOptions{}); err != nil {
			return err
		}
		slog.Debug("autocert cache secret updated", "namespace", a.secretNamespace, "name", a.secretName)
		return nil
	})
	if err != nil {
		slog.Error("autocert cache delete failed", "namespace", a.secretNamespace, "name", a.secretName, "key", key, "error", err)
		return fmt.Errorf("deleting %s from secret %s/%s: %v", key, a.secretNamespace, a.secretName, err)
	}
	slog.Info("autocert cache delete", "namespace", a.secretNamespace, "name", a.secretName, "key", key)
	return nil
}
