package main

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestSelfSignedCertProviderReturnsCachedCertForHost(t *testing.T) {
	p := &selfSignedCertProvider{
		certs: map[string]*tls.Certificate{},
	}

	cert1, err := p.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.localtest.me"})
	if err != nil {
		t.Fatalf("GetCertificate() first call error = %v", err)
	}
	cert2, err := p.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.localtest.me"})
	if err != nil {
		t.Fatalf("GetCertificate() second call error = %v", err)
	}
	if cert1 != cert2 {
		t.Fatalf("expected cached certificate pointer to be reused")
	}
}

func TestSelfSignedCertProviderIncludesServerNameInSAN(t *testing.T) {
	p := &selfSignedCertProvider{
		certs: map[string]*tls.Certificate{},
	}

	cert, err := p.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.localtest.me"})
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "app.localtest.me" {
		t.Fatalf("expected SAN DNSNames to include app.localtest.me, got %#v", parsed.DNSNames)
	}
}

func TestSelfSignedCertProviderFallsBackToLocalhost(t *testing.T) {
	p := &selfSignedCertProvider{
		certs: map[string]*tls.Certificate{},
	}

	cert, err := p.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "localhost" {
		t.Fatalf("expected SAN DNSNames to include localhost, got %#v", parsed.DNSNames)
	}
}
