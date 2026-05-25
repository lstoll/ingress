package mtls

import (
	"crypto/tls"
	"fmt"
)

// ClientConfig loads a client certificate and optional CA pool for verifying
// backend server certificates.
func ClientConfig(identity IdentityFiles, caFile string) (*tls.Config, error) {
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	cert, err := identity.Load()
	if err != nil {
		return nil, err
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
func ServerConfig(identity IdentityFiles, clientCAFile, expectedClientSVID string) (*tls.Config, error) {
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	if clientCAFile == "" {
		return nil, fmt.Errorf("client CA path is required")
	}

	cert, err := identity.Load()
	if err != nil {
		return nil, err
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
