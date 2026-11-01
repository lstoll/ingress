package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"lds.li/keyset"
	"lds.li/keyset/insecurecleartext"
	"lds.li/keyset/k8sstore"
	"lds.li/oauth2ext/jwt"
)

const (
	// oidcClientKeysetName is the single ingress-wide keyset used to sign
	// private_key_jwt client assertions for every OIDC-protected host.
	oidcClientKeysetName = "oidc-client-es256"

	// oidcJWKSPath serves the public half of the client keyset on every host
	// that uses private_key_jwt, so the IdP can be pointed at
	// https://<host>/.ingress/oidc-jwks.
	oidcJWKSPath = "/.ingress/oidc-jwks"

	oidcClientKeyRotateInterval  = 10 * time.Minute
	oidcClientKeyRefreshInterval = time.Minute
	oidcJWKSCacheControl         = "public, max-age=300"

	clientAuthSecret        = "client_secret"
	clientAuthPrivateKeyJWT = "private_key_jwt"
)

// oidcClientKeyPolicy rotates daily. A new key is published for Propagate
// before it signs anything, which must comfortably exceed how long the IdP
// caches our JWKS. Assertions live for minutes, so the old key only needs to
// stay published briefly after it stops signing.
var oidcClientKeyPolicy = keyset.Policy{
	Primary:   24 * time.Hour,
	Propagate: 6 * time.Hour,
	PhaseOut:  6 * time.Hour,
	Retention: 24 * time.Hour,
}

// oidcClientKeyType generates P-256 keys: PKCS#8 private, PKIX public.
var oidcClientKeyType = keyset.Type{
	Policy: oidcClientKeyPolicy,
	New: func(context.Context) (keyset.Material, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return keyset.Material{}, err
		}
		priv, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return keyset.Material{}, err
		}
		pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return keyset.Material{}, err
		}
		return keyset.Material{Private: priv, Public: pub}, nil
	},
}

// oidcClientKeys holds the live signer and published verification keys. Both
// are swapped in place on refresh, so holders of the pointers see rotations.
type oidcClientKeys struct {
	Signer *jwt.SigningKeySet
	Keys   *jwt.VerificationKeySet
}

// newOIDCClientKeysFromSecret starts the client keyset backed by the
// namespace/name Secret. Key material is stored unencrypted: the Secret is the
// protection boundary, and wrapping it with a key from another Secret would
// not add anything.
func newOIDCClientKeysFromSecret(ctx context.Context, logger *slog.Logger, cfg *rest.Config, secretRef string) (*oidcClientKeys, error) {
	namespace, name, err := splitNamespacedName(secretRef)
	if err != nil {
		return nil, fmt.Errorf("invalid --oidc-client-keyset-secret, expected namespace/name: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("building kubernetes clientset: %w", err)
	}
	store, err := k8sstore.New(clientset, namespace, name, insecurecleartext.Keeper)
	if err != nil {
		return nil, fmt.Errorf("oidc client keys: create store: %w", err)
	}
	return startOIDCClientKeys(ctx, logger, store)
}

// startOIDCClientKeys provisions and rotates the client keyset in store, loads
// it, and keeps the loaded handles fresh until ctx is done.
func startOIDCClientKeys(ctx context.Context, logger *slog.Logger, store keyset.AdminStore) (*oidcClientKeys, error) {
	registry, err := keyset.NewRegistry(map[string]keyset.Type{oidcClientKeysetName: oidcClientKeyType})
	if err != nil {
		return nil, fmt.Errorf("oidc client keys: create registry: %w", err)
	}
	rotator, err := keyset.NewRotator(store, registry,
		keyset.WithInterval(oidcClientKeyRotateInterval),
		keyset.WithEnsure(map[string]string{oidcClientKeysetName: oidcClientKeysetName}),
		keyset.WithLogger(logger),
	)
	if err != nil {
		return nil, fmt.Errorf("oidc client keys: create rotator: %w", err)
	}
	if err := rotator.Once(ctx); err != nil {
		return nil, fmt.Errorf("oidc client keys: provision: %w", err)
	}
	if err := rotator.Run(ctx); err != nil {
		return nil, fmt.Errorf("oidc client keys: start rotator: %w", err)
	}

	keys, err := loadOIDCClientKeys(ctx, store)
	if err != nil {
		rotator.Stop()
		return nil, err
	}

	go func() {
		ticker := time.NewTicker(oidcClientKeyRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := keys.refresh(ctx, store); err != nil {
					logger.Error("oidc client keys: refresh failed", "error", err)
				}
			}
		}
	}()

	return keys, nil
}

func loadOIDCClientKeys(ctx context.Context, store keyset.Store) (*oidcClientKeys, error) {
	ks, err := store.Get(ctx, oidcClientKeysetName)
	if err != nil {
		return nil, fmt.Errorf("oidc client keys: load keyset: %w", err)
	}

	primary, ok := ks.Primary()
	if !ok {
		return nil, fmt.Errorf("oidc client keys: keyset has no primary key")
	}
	priv, err := x509.ParsePKCS8PrivateKey(primary.Private)
	if err != nil {
		return nil, fmt.Errorf("oidc client keys: parse primary key %s: %w", primary.ID, err)
	}
	privSigner, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("oidc client keys: primary key %s is %T, not a signer", primary.ID, priv)
	}
	identity, err := jwt.NewSigningIdentity(privSigner, jwt.ES256, primary.ID)
	if err != nil {
		return nil, fmt.Errorf("oidc client keys: signing identity: %w", err)
	}
	signer, err := jwt.NewSigningKeySet(identity)
	if err != nil {
		return nil, fmt.Errorf("oidc client keys: signing key set: %w", err)
	}

	// Publish pending keys too, so the IdP learns them before they sign.
	var vks []jwt.VerificationKey
	for _, pk := range ks.Public().Keys {
		if !pk.State.IsUsable() {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(pk.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("oidc client keys: parse public key %s: %w", pk.ID, err)
		}
		vk, err := jwt.NewVerificationKey(pub, jwt.ES256, pk.ID)
		if err != nil {
			return nil, fmt.Errorf("oidc client keys: verification key %s: %w", pk.ID, err)
		}
		vks = append(vks, vk)
	}
	keys, err := jwt.NewVerificationKeySet(vks...)
	if err != nil {
		return nil, fmt.Errorf("oidc client keys: verification key set: %w", err)
	}

	return &oidcClientKeys{Signer: signer, Keys: keys}, nil
}

// refresh reloads from store and swaps the new handles in. The published keys
// are replaced before the signer so a new kid is never used before it is served.
func (k *oidcClientKeys) refresh(ctx context.Context, store keyset.Store) error {
	next, err := loadOIDCClientKeys(ctx, store)
	if err != nil {
		return err
	}
	if err := k.Keys.Replace(next.Keys); err != nil {
		return fmt.Errorf("oidc client keys: replace verification keys: %w", err)
	}
	if err := k.Signer.Replace(next.Signer); err != nil {
		return fmt.Errorf("oidc client keys: replace signer: %w", err)
	}
	return nil
}

// ServeHTTP serves the public keys as a JWKS document.
func (k *oidcClientKeys) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	body, err := k.Keys.JWKS()
	if err != nil {
		slog.Error("oidc client keys: marshal jwks", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", oidcJWKSCacheControl)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}
