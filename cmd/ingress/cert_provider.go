package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

const (
	certModeSelfSigned = "self-signed"
	certModeAutocert   = "autocert"
)

// CertProvider is the abstraction used to source server certificates for
// terminated TLS connections.
type CertProvider interface {
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

type selfSignedCertProvider struct {
	mu    sync.Mutex
	certs map[string]*tls.Certificate
}

func newCertProvider(mode string) (CertProvider, error) {
	switch mode {
	case certModeSelfSigned:
		return &selfSignedCertProvider{
			certs: map[string]*tls.Certificate{},
		}, nil
	case certModeAutocert:
		return nil, fmt.Errorf("cert mode %q not implemented yet", certModeAutocert)
	default:
		return nil, fmt.Errorf("unsupported cert mode %q", mode)
	}
}

func (p *selfSignedCertProvider) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := "localhost"
	if hello != nil && hello.ServerName != "" {
		host = hello.ServerName
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if cert, ok := p.certs[host]; ok {
		return cert, nil
	}

	cert, err := generateSelfSignedCert(host)
	if err != nil {
		return nil, err
	}
	p.certs[host] = cert
	return cert, nil
}

func generateSelfSignedCert(host string) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ingress-dev"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(12 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		DNSNames:               []string{host},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
		template.DNSNames = nil
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %w", err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
	return cert, nil
}
