package mtls_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/lstoll/ingress/internal/mtls"
)

func TestParseCredentialBundle(t *testing.T) {
	fix := mtls.NewTestFixture(t)
	bundlePath := fix.ClientBundleFile(t)

	cert, err := mtls.LoadCredentialBundle(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) != 1 {
		t.Fatalf("expected one certificate in chain, got %d", len(cert.Certificate))
	}
	if cert.PrivateKey == nil {
		t.Fatal("expected private key")
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	got, ok := mtls.ClientSVID(leaf)
	if !ok || got != fix.IngressSVID {
		t.Fatalf("unexpected leaf SVID: %q", got)
	}
}

func TestClientConfigFromCredentialBundle(t *testing.T) {
	fix := mtls.NewTestFixture(t)
	bundlePath := fix.ClientBundleFile(t)

	cfg, err := mtls.ClientConfig(mtls.IdentityFiles{BundleFile: bundlePath}, fix.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected one certificate, got %d", len(cfg.Certificates))
	}
}

func TestReloaderReloadsCredentialBundle(t *testing.T) {
	fix := mtls.NewTestFixture(t)
	bundlePath := fix.ClientBundleFile(t)

	reloader, err := mtls.NewClientReloader(testLogger(), mtls.IdentityFiles{BundleFile: bundlePath}, fix.CAFile, 0)
	if err != nil {
		t.Fatal(err)
	}

	fix.RotateClientCert(t)
	rewriteCredentialBundle(t, bundlePath, fix.ClientKey, fix.ClientCert)

	if err := reloader.ReloadOnce(); err != nil {
		t.Fatalf("reload bundle: %v", err)
	}
}

func rewriteCredentialBundle(t *testing.T, bundlePath, keyFile, certFile string) {
	t.Helper()
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	privateKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	var bundle []byte
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})...)
	bundle = append(bundle, certPEM...)
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
}
