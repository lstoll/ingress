package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	certModeSelfSigned = "self-signed"
	certModeAutocert   = "autocert"
)

// CertProvider is the abstraction used to source server certificates for
// terminated TLS connections.
type CertProvider interface {
	TLSConfig() *tls.Config
}

type certProviderConfig struct {
	KubeConfig     *rest.Config
	AutocertSecret string
	HostPolicy     autocert.HostPolicy
	// AllowHost, when set for self-signed mode, rejects GetCertificate for
	// hostnames that are not configured (defense in depth with SNI matching).
	AllowHost func(host string) bool
}

type selfSignedCertProvider struct {
	mu        sync.Mutex
	certs     map[string]*tls.Certificate
	allowHost func(host string) bool
}

func newCertProvider(mode string, cfg certProviderConfig) (CertProvider, error) {
	switch mode {
	case certModeSelfSigned:
		return &selfSignedCertProvider{
			certs:     map[string]*tls.Certificate{},
			allowHost: cfg.AllowHost,
		}, nil
	case certModeAutocert:
		return newAutocertProvider(cfg)
	default:
		return nil, fmt.Errorf("unsupported cert mode %q", mode)
	}
}

func (p *selfSignedCertProvider) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1"},
		GetCertificate: p.getCertificate,
	}
}

func (p *selfSignedCertProvider) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := "localhost"
	if hello != nil && hello.ServerName != "" {
		host = strings.ToLower(strings.TrimSpace(hello.ServerName))
	}

	if p.allowHost != nil && !p.allowHost(host) {
		return nil, errors.New("ingress: host not allowed for certificate")
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
		DNSNames:              []string{host},
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

type autocertCertProvider struct {
	manager *autocert.Manager
}

func newAutocertProvider(cfg certProviderConfig) (CertProvider, error) {
	if cfg.KubeConfig == nil {
		return nil, fmt.Errorf("kubernetes config is required for autocert mode")
	}
	secretNamespace, secretName, err := splitNamespacedName(cfg.AutocertSecret)
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(cfg.KubeConfig)
	if err != nil {
		return nil, fmt.Errorf("building kubernetes clientset: %w", err)
	}

	hostPolicy := cfg.HostPolicy
	if hostPolicy == nil {
		hostPolicy = func(context.Context, string) error { return nil }
	}

	return &autocertCertProvider{
		manager: &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache: &autocertCache{
				clientset:       clientset,
				secretNamespace: secretNamespace,
				secretName:      secretName,
			},
			HostPolicy: hostPolicy,
		},
	}, nil
}

func (p *autocertCertProvider) TLSConfig() *tls.Config {
	cfg := p.manager.TLSConfig()
	cfg.MinVersion = tls.VersionTLS12
	return cfg
}

func splitNamespacedName(p string) (namespace, name string, err error) {
	sp := strings.Split(p, "/")
	if len(sp) != 2 {
		return "", "", fmt.Errorf("splitting %s on / yielded %d items, not 2", p, len(sp))
	}
	if sp[0] == "" || sp[1] == "" {
		return "", "", fmt.Errorf("invalid namespaced name %q", p)
	}
	return sp[0], sp[1], nil
}
