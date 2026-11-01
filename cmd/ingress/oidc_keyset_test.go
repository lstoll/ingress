package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"lds.li/keyset"
	"lds.li/keyset/insecurecleartext"
	"lds.li/keyset/memstore"
	"lds.li/oauth2ext/clientjwt"
	"lds.li/oauth2ext/jwt"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func newTestOIDCClientKeys(t *testing.T) (*oidcClientKeys, *memstore.Store) {
	t.Helper()
	store := memstore.New(insecurecleartext.Keeper)
	keys, err := startOIDCClientKeys(t.Context(), testLogger(), store)
	if err != nil {
		t.Fatalf("start client keys: %v", err)
	}
	return keys, store
}

func fetchJWKS(t *testing.T, h http.Handler) *jwt.VerificationKeySet {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example"+oidcJWKSPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("jwks status: got %d, body %q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/jwk-set+json" {
		t.Fatalf("jwks content type: got %q", ct)
	}
	set, err := jwt.ParseVerificationJWKS(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parse jwks: %v", err)
	}
	return set
}

func jwksKIDs(t *testing.T, set *jwt.VerificationKeySet) []string {
	t.Helper()
	raw, err := set.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys []struct {
			KID string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var kids []string
	for _, k := range doc.Keys {
		kids = append(kids, k.KID)
	}
	return kids
}

func signedKID(t *testing.T, compact string) string {
	t.Helper()
	header, _, _ := strings.Cut(compact, ".")
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		t.Fatal(err)
	}
	var h struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h.KID
}

func verifyClientAssertion(t *testing.T, keys *jwt.VerificationKeySet, compact, clientID, audience string) error {
	t.Helper()
	v, err := jwt.NewVerifier(keys, jwt.ValidationPolicy{
		ExpectedIssuer:    clientID,
		ExpectedAudiences: []string{audience},
		AllowedAlgorithms: []jwt.Algorithm{jwt.ES256},
		Type:              jwt.TypeJWTOrAbsent,
		RequireIssuedAt:   true,
		ClockSkew:         jwt.DefaultClockSkew,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(compact)
	return err
}

func TestOIDCClientKeysSignAndPublish(t *testing.T) {
	keys, _ := newTestOIDCClientKeys(t)

	published := fetchJWKS(t, keys)
	compact, err := clientjwt.Sign(t.Context(), keys.Signer, clientjwt.SignOptions{
		ClientID: "client", Audience: "https://idp.example/token", Algorithm: jwt.ES256,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := verifyClientAssertion(t, published, compact, "client", "https://idp.example/token"); err != nil {
		t.Fatalf("assertion does not verify against published jwks: %v", err)
	}
}

func TestOIDCClientKeysRotation(t *testing.T) {
	keys, store := newTestOIDCClientKeys(t)
	ctx := t.Context()

	sign := func() string {
		t.Helper()
		compact, err := clientjwt.Sign(ctx, keys.Signer, clientjwt.SignOptions{
			ClientID: "client", Audience: "aud", Algorithm: jwt.ES256,
		})
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	oldKID := signedKID(t, sign())

	// Walk the keyset forward through a full rotation, as the rotator would.
	now := time.Now()
	for _, at := range []time.Duration{0, oidcClientKeyPolicy.Primary - oidcClientKeyPolicy.Propagate + time.Minute, oidcClientKeyPolicy.Primary + time.Minute} {
		ks, rev, err := store.Read(ctx, oidcClientKeysetName)
		if err != nil {
			t.Fatal(err)
		}
		typ := oidcClientKeyType
		if _, err := ks.Rotate(ctx, now.Add(at), &typ); err != nil {
			t.Fatal(err)
		}
		if err := store.Write(ctx, oidcClientKeysetName, ks, rev); err != nil {
			t.Fatal(err)
		}
		if err := keys.refresh(ctx, store); err != nil {
			t.Fatal(err)
		}
	}

	compact := sign()
	newKID := signedKID(t, compact)
	if newKID == oldKID {
		t.Fatalf("expected signer to rotate away from kid %s", oldKID)
	}
	published := fetchJWKS(t, keys)
	kids := jwksKIDs(t, published)
	if !containsString(kids, oldKID) || !containsString(kids, newKID) {
		t.Fatalf("expected jwks to publish old %s and new %s, got %v", oldKID, newKID, kids)
	}
	if err := verifyClientAssertion(t, published, compact, "client", "aud"); err != nil {
		t.Fatalf("rotated assertion does not verify: %v", err)
	}
}

func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// fakeIdP serves just enough OIDC for the middleware to discover it, and
// records the client authentication it sees at the token endpoint.
type fakeIdP struct {
	srv *httptest.Server

	mu         sync.Mutex
	tokenForms []url.Values
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vk, err := jwt.NewVerificationKey(&key.PublicKey, jwt.ES256, "idp")
	if err != nil {
		t.Fatal(err)
	}
	idpKeys, err := jwt.NewVerificationKeySet(vk)
	if err != nil {
		t.Fatal(err)
	}

	f := &fakeIdP{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := f.srv.URL
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/authorize",
			"token_endpoint":                        base + "/token",
			"jwks_uri":                              base + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"ES256"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post", "private_key_jwt"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		b, _ := idpKeys.JWKS()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		f.mu.Lock()
		f.tokenForms = append(f.tokenForms, form)
		f.mu.Unlock()
		// The test only cares about client authentication, so fail the grant.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func TestOIDCMiddlewarePrivateKeyJWT(t *testing.T) {
	keys, _ := newTestOIDCClientKeys(t)
	idp := newFakeIdP(t)

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("backend"))
	})
	mw, err := buildMiddlewareForHost(t.Context(), "app.example", oidcConfig{
		Issuer:         idp.srv.URL,
		ClientID:       "app-client",
		ClientKeys:     keys,
		BypassPatterns: []string{"/"},
	})
	if err != nil {
		t.Fatalf("build middleware: %v", err)
	}
	h := mw(backend)

	// The JWKS is served by ingress, not proxied, even with a catch-all bypass.
	published := fetchJWKS(t, h)

	// A callback triggers the code exchange; the token endpoint must receive a
	// valid assertion. Use a real login to get a matching state cookie.
	login := httptest.NewRecorder()
	mwNoBypass, err := buildMiddlewareForHost(t.Context(), "app.example", oidcConfig{
		Issuer:     idp.srv.URL,
		ClientID:   "app-client",
		ClientKeys: keys,
	})
	if err != nil {
		t.Fatalf("build middleware: %v", err)
	}
	h = mwNoBypass(backend)
	h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "https://app.example/", nil))
	if login.Code != http.StatusFound && login.Code != http.StatusSeeOther {
		t.Fatalf("expected login redirect, got %d", login.Code)
	}
	authURL, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := authURL.Query().Get("state")
	if state == "" {
		t.Fatalf("no state in auth redirect %s", authURL)
	}

	cb := httptest.NewRequest(http.MethodGet, "https://app.example/.ingress/oidc-callback?code=abc&state="+url.QueryEscape(state), nil)
	for _, c := range login.Result().Cookies() {
		cb.AddCookie(c)
	}
	h.ServeHTTP(httptest.NewRecorder(), cb)

	idp.mu.Lock()
	forms := idp.tokenForms
	idp.mu.Unlock()
	if len(forms) != 1 {
		t.Fatalf("expected one token request, got %d", len(forms))
	}
	form := forms[0]
	if form.Get("client_secret") != "" {
		t.Fatalf("client_secret must not be sent")
	}
	if got := form.Get("client_assertion_type"); got != clientjwt.AssertionType {
		t.Fatalf("client_assertion_type: got %q", got)
	}
	if err := verifyClientAssertion(t, published, form.Get("client_assertion"), "app-client", idp.srv.URL+"/token"); err != nil {
		t.Fatalf("assertion does not verify against served jwks: %v", err)
	}
}

func TestServiceReconcileOIDCPrivateKeyJWT(t *testing.T) {
	ctx := context.Background()
	router := newIngressRouter(testLogger(), ctx, nil)
	router.authMiddlewareBuilder = func(_ context.Context, _ string, _ oidcConfig) (func(http.Handler) http.Handler, error) {
		return func(h http.Handler) http.Handler { return h }, nil
	}
	keys, _ := newTestOIDCClientKeys(t)

	base := map[string]string{
		annMode:           modeHTTPS,
		annHTTPHostnames:  "jwt.example.com",
		annAuthMode:       authModeOIDC,
		annOIDCIssuer:     "https://issuer.example.com",
		annOIDCClientAuth: clientAuthPrivateKeyJWT,
		annOIDCClientID:   "client",
	}
	for _, tc := range []struct {
		name      string
		keys      *oidcClientKeys
		mutate    func(map[string]string)
		wantRoute bool
	}{
		{name: "valid", keys: keys, wantRoute: true},
		{name: "no keyset configured", keys: nil},
		{name: "missing client id", keys: keys, mutate: func(a map[string]string) { delete(a, annOIDCClientID) }},
		{name: "with secret", keys: keys, mutate: func(a map[string]string) { a[annOIDCClientSecret] = "s" }},
		{name: "with dynamic", keys: keys, mutate: func(a map[string]string) { a[annOIDCDynamicClient] = "true" }},
		{name: "unknown method", keys: keys, mutate: func(a map[string]string) { a[annOIDCClientAuth] = "tls_client_auth" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ann := map[string]string{}
			for k, v := range base {
				ann[k] = v
			}
			if tc.mutate != nil {
				tc.mutate(ann)
			}
			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "jwt",
					Namespace:   "default",
					Labels:      map[string]string{labelIngressInstance: "ingress1"},
					Annotations: ann,
				},
				Spec: corev1.ServiceSpec{ClusterIP: "10.0.0.97", Ports: []corev1.ServicePort{{Port: 8080}}},
			}
			r := &ServiceReconciler{
				Client:         fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc).Build(),
				logger:         testLogger(),
				router:         router,
				instance:       "ingress1",
				oidcClientKeys: tc.keys,
			}
			if _, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "jwt"}}); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			route, ok := router.RouteFor("jwt.example.com")
			if ok != tc.wantRoute {
				t.Fatalf("route present: got %v want %v", ok, tc.wantRoute)
			}
			if ok && route.OIDC.ClientKeys != keys {
				t.Fatalf("expected client keys on route config")
			}
		})
	}
}

var _ keyset.AdminStore = (*memstore.Store)(nil)
