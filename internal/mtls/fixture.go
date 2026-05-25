package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestFixture holds PEM file paths for integration tests.
type TestFixture struct {
	CAFile      string
	ServerCert  string
	ServerKey   string
	ClientCert  string
	ClientKey   string
	IngressSVID string
	WrongSVID   string

	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
}

// NewTestFixture generates a temporary CA, server cert, and client cert with a SPIFFE URI SAN.
func NewTestFixture(t *testing.T) TestFixture {
	t.Helper()

	dir := t.TempDir()
	ingressSVID := "spiffe://example.test/ns/ingress/sa/ingress"
	wrongSVID := "spiffe://example.test/ns/other/sa/other"

	caKey, caCert := newCA(t)
	serverKey, serverCert := newLeaf(t, caCert, caKey, leafOptions{dnsName: "backend-sidecar", isServer: true})
	clientKey, clientCert := newLeaf(t, caCert, caKey, leafOptions{spiffeID: ingressSVID, isClient: true})

	return TestFixture{
		CAFile:      writeCertPEM(t, dir, "ca.pem", caCert.Raw),
		ServerCert:  writeCertPEM(t, dir, "server.pem", serverCert.Raw),
		ServerKey:   writeKeyPEM(t, dir, "server-key.pem", serverKey),
		ClientCert:  writeCertPEM(t, dir, "client.pem", clientCert.Raw),
		ClientKey:   writeKeyPEM(t, dir, "client-key.pem", clientKey),
		IngressSVID: ingressSVID,
		WrongSVID:   wrongSVID,
		ca:          caCert,
		caKey:       caKey,
	}
}

// ClientIdentity returns separate-file identity paths for this fixture.
func (f TestFixture) ClientIdentity() IdentityFiles {
	return IdentityFiles{CertFile: f.ClientCert, KeyFile: f.ClientKey}
}

// ServerIdentity returns separate-file identity paths for this fixture.
func (f TestFixture) ServerIdentity() IdentityFiles {
	return IdentityFiles{CertFile: f.ServerCert, KeyFile: f.ServerKey}
}

// ClientBundleFile writes a Kubernetes-style credential bundle and returns its path.
func (f TestFixture) ClientBundleFile(t *testing.T) string {
	t.Helper()
	return writeCredentialBundle(t, f.ClientKey, f.ClientCert)
}

// ServerBundleFile writes a Kubernetes-style credential bundle and returns its path.
func (f TestFixture) ServerBundleFile(t *testing.T) string {
	t.Helper()
	return writeCredentialBundle(t, f.ServerKey, f.ServerCert)
}

func writeCredentialBundle(t *testing.T, keyFile, certFile string) string {
	t.Helper()
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("failed to decode key PEM")
	}
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

	path := filepath.Join(filepath.Dir(keyFile), "bundle.pem")
	var bundle []byte
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})...)
	bundle = append(bundle, certPEM...)
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// RotateClientCert replaces the client certificate files with a new leaf from the same CA.
func (f *TestFixture) RotateClientCert(t *testing.T) {
	t.Helper()
	clientKey, clientCert := newLeaf(t, f.ca, f.caKey, leafOptions{spiffeID: f.IngressSVID, isClient: true})
	if err := os.WriteFile(f.ClientCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	writeKeyToFile(t, f.ClientKey, clientKey)
}

// RotateServerCert replaces the server certificate files with a new leaf from the same CA.
func (f *TestFixture) RotateServerCert(t *testing.T) {
	t.Helper()
	serverKey, serverCert := newLeaf(t, f.ca, f.caKey, leafOptions{dnsName: "backend-sidecar", isServer: true})
	if err := os.WriteFile(f.ServerCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	writeKeyToFile(t, f.ServerKey, serverKey)
}

type leafOptions struct {
	dnsName  string
	spiffeID string
	isServer bool
	isClient bool
}

func newCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func newLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, opts leafOptions) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: opts.dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if opts.dnsName != "" {
		template.DNSNames = []string{opts.dnsName}
	}
	if opts.spiffeID != "" {
		u, err := url.Parse(opts.spiffeID)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = []*url.URL{u}
	}
	if opts.isServer {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if opts.isClient {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func writeCertPEM(t *testing.T, dir, name string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeKeyPEM(t *testing.T, dir, name string, key *ecdsa.PrivateKey) string {
	t.Helper()
	path := filepath.Join(dir, name)
	writeKeyToFile(t, path, key)
	return path
}

func writeKeyToFile(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}
