package mtls_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/lstoll/ingress/internal/mtls"
)

func TestClientSVID(t *testing.T) {
	fix := mtls.NewTestFixture(t)
	cert := mustLoadCert(t, fix.ClientCert)
	got, ok := mtls.ClientSVID(cert)
	if !ok {
		t.Fatal("expected SPIFFE URI SAN")
	}
	if got != fix.IngressSVID {
		t.Fatalf("got SVID %q, want %q", got, fix.IngressSVID)
	}
}

func TestVerifyClientSVID(t *testing.T) {
	fix := mtls.NewTestFixture(t)
	cert := mustLoadCert(t, fix.ClientCert)
	if err := mtls.VerifyClientSVID(cert, fix.IngressSVID); err != nil {
		t.Fatalf("expected match: %v", err)
	}
	if err := mtls.VerifyClientSVID(cert, fix.WrongSVID); err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestClientAndServerConfig(t *testing.T) {
	fix := mtls.NewTestFixture(t)

	clientCfg, err := mtls.ClientConfig(fix.ClientIdentity(), fix.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(clientCfg.Certificates) != 1 {
		t.Fatalf("expected one client certificate, got %d", len(clientCfg.Certificates))
	}

	serverCfg, err := mtls.ServerConfig(fix.ServerIdentity(), fix.CAFile, fix.IngressSVID)
	if err != nil {
		t.Fatal(err)
	}
	if serverCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("unexpected client auth mode: %v", serverCfg.ClientAuth)
	}
}

func mustLoadCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("failed to decode PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
