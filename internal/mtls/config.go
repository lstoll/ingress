package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// ClientConfig loads a client certificate and optional CA pool for verifying
// backend server certificates.
func ClientConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("client cert and key paths are required")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading client certificate: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if caFile != "" {
		pool, err := loadCAPool(caFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}

	return cfg, nil
}

// ServerConfig loads a server certificate and requires client certificates signed
// by the given CA. expectedClientSVID, when non-empty, must appear as a URI SAN
// on the client certificate.
func ServerConfig(certFile, keyFile, clientCAFile, expectedClientSVID string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("server cert and key paths are required")
	}
	if clientCAFile == "" {
		return nil, fmt.Errorf("client CA path is required")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading server certificate: %w", err)
	}
	clientCAs, err := loadCAPool(clientCAFile)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	if expectedClientSVID != "" {
		expected := expectedClientSVID
		cfg.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("no client certificate presented")
			}
			return VerifyClientSVID(state.PeerCertificates[0], expected)
		}
	}

	return cfg, nil
}

func loadCAPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading CA file %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in CA file %s", caFile)
	}
	return pool, nil
}
