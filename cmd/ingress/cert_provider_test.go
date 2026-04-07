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

	cert1, err := p.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "app.localtest.me"})
	if err != nil {
		t.Fatalf("GetCertificate() first call error = %v", err)
	}
	cert2, err := p.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "app.localtest.me"})
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

	cert, err := p.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "app.localtest.me"})
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

func TestSelfSignedCertProviderAllowHostRejectsUnknown(t *testing.T) {
	p := &selfSignedCertProvider{
		certs: map[string]*tls.Certificate{},
		allowHost: func(host string) bool {
			return host == "allowed.example"
		},
	}
	_, err := p.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example"})
	if err == nil {
		t.Fatal("expected error for disallowed host")
	}
}

func TestSelfSignedCertProviderFallsBackToLocalhost(t *testing.T) {
	p := &selfSignedCertProvider{
		certs: map[string]*tls.Certificate{},
	}

	cert, err := p.TLSConfig().GetCertificate(&tls.ClientHelloInfo{})
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

func TestSplitNamespacedName(t *testing.T) {
	ns, name, err := splitNamespacedName("ingress-dev/autocert-cache")
	if err != nil {
		t.Fatalf("splitNamespacedName() error = %v", err)
	}
	if ns != "ingress-dev" || name != "autocert-cache" {
		t.Fatalf("splitNamespacedName() got %q/%q, want ingress-dev/autocert-cache", ns, name)
	}
}
