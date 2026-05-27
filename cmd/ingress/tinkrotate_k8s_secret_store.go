package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"lds.li/tinkrotate"
	tinkrotatev1 "lds.li/tinkrotate/proto/tinkrotate/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	secretDataKeyset  = "keyset.bin"
	secretDataMeta    = "metadata.pb"
	secretDataName    = "keyset-name"
	managedByLabelKey = "app.kubernetes.io/managed-by"
	managedByLabelVal = "ingress"
)

type k8sSecretManagedStore struct {
	cl     client.Client
	secret types.NamespacedName
}

var _ tinkrotate.ManagedStore = (*k8sSecretManagedStore)(nil)

func newK8sSecretManagedStore(cl client.Client, secret types.NamespacedName) *k8sSecretManagedStore {
	return &k8sSecretManagedStore{
		cl:     cl,
		secret: secret,
	}
}

func (s *k8sSecretManagedStore) ReadKeysetAndMetadata(ctx context.Context, keysetName string) (*tinkrotate.ReadResult, error) {
	var sec corev1.Secret
	if err := s.cl.Get(ctx, s.secret, &sec); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, tinkrotate.ErrKeysetNotFound
		}
		return nil, fmt.Errorf("reading secret: %w", err)
	}
	if sec.Data == nil {
		return nil, tinkrotate.ErrKeysetNotFound
	}
	if string(sec.Data[secretDataName]) != keysetName {
		return nil, tinkrotate.ErrKeysetNotFound
	}
	hb := sec.Data[secretDataKeyset]
	mb := sec.Data[secretDataMeta]
	if len(hb) == 0 || len(mb) == 0 {
		return nil, tinkrotate.ErrKeysetNotFound
	}

	h, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(hb)))
	if err != nil {
		return nil, fmt.Errorf("decoding keyset from secret: %w", err)
	}
	md := &tinkrotatev1.KeyRotationMetadata{}
	if err := proto.Unmarshal(mb, md); err != nil {
		return nil, fmt.Errorf("decoding metadata from secret: %w", err)
	}
	return &tinkrotate.ReadResult{
		Handle:   h,
		Metadata: md,
		Context:  sec.ResourceVersion,
	}, nil
}

func (s *k8sSecretManagedStore) WriteKeysetAndMetadata(ctx context.Context, keysetName string, handle *keyset.Handle, metadata *tinkrotatev1.KeyRotationMetadata, expectedContext any) error {
	if handle == nil || metadata == nil {
		return errors.New("handle and metadata are required")
	}
	var hbb bytes.Buffer
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(&hbb)); err != nil {
		return fmt.Errorf("encoding keyset: %w", err)
	}
	mb, err := proto.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("encoding metadata: %w", err)
	}

	rv, _ := expectedContext.(string)
	if rv == "" {
		var existing corev1.Secret
		err := s.cl.Get(ctx, s.secret, &existing)
		if err == nil {
			return tinkrotate.ErrOptimisticLockFailed
		}
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("checking existing secret: %w", err)
		}
		sec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      s.secret.Name,
				Namespace: s.secret.Namespace,
				Labels: map[string]string{
					managedByLabelKey: managedByLabelVal,
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				secretDataName:   []byte(keysetName),
				secretDataKeyset: hbb.Bytes(),
				secretDataMeta:   mb,
			},
		}
		if err := s.cl.Create(ctx, sec); err != nil {
			if apierrors.IsAlreadyExists(err) {
				return tinkrotate.ErrOptimisticLockFailed
			}
			return fmt.Errorf("creating keyset secret: %w", err)
		}
		return nil
	}

	var sec corev1.Secret
	if err := s.cl.Get(ctx, s.secret, &sec); err != nil {
		if apierrors.IsNotFound(err) {
			return tinkrotate.ErrOptimisticLockFailed
		}
		return fmt.Errorf("loading secret for update: %w", err)
	}
	if sec.ResourceVersion != rv {
		return tinkrotate.ErrOptimisticLockFailed
	}
	if sec.Data == nil {
		sec.Data = map[string][]byte{}
	}
	sec.Data[secretDataName] = []byte(keysetName)
	sec.Data[secretDataKeyset] = hbb.Bytes()
	sec.Data[secretDataMeta] = mb
	if err := s.cl.Update(ctx, &sec); err != nil {
		if apierrors.IsConflict(err) {
			return tinkrotate.ErrOptimisticLockFailed
		}
		return fmt.Errorf("updating keyset secret: %w", err)
	}
	return nil
}

func (s *k8sSecretManagedStore) ForEachKeyset(ctx context.Context, fn func(keysetName string) error) error {
	var sec corev1.Secret
	if err := s.cl.Get(ctx, s.secret, &sec); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("reading secret for iteration: %w", err)
	}
	if sec.Data == nil {
		return nil
	}
	name := string(sec.Data[secretDataName])
	if name == "" {
		return nil
	}
	return fn(name)
}

func (s *k8sSecretManagedStore) GetHandle(ctx context.Context, keysetName string) (*keyset.Handle, error) {
	rr, err := s.ReadKeysetAndMetadata(ctx, keysetName)
	if err != nil {
		return nil, err
	}
	return rr.Handle, nil
}

func (s *k8sSecretManagedStore) GetPublicHandle(ctx context.Context, keysetName string) (*keyset.Handle, error) {
	h, err := s.GetHandle(ctx, keysetName)
	if err != nil {
		return nil, err
	}
	ph, err := h.Public()
	if err != nil {
		return nil, err
	}
	return ph, nil
}
