package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
)

type backendDialer struct {
	tlsConfig *tls.Config
}

func newBackendDialer(tlsConfig *tls.Config) *backendDialer {
	return &backendDialer{tlsConfig: tlsConfig}
}

func (d *backendDialer) enabled() bool {
	return d != nil && d.tlsConfig != nil
}

func (d *backendDialer) DialContext(ctx context.Context, network, address, serverName string, mtls bool) (net.Conn, error) {
	if !mtls || d == nil || d.tlsConfig == nil {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, address)
	}
	if serverName == "" {
		return nil, fmt.Errorf("backend mTLS requires a server name for certificate verification")
	}

	raw, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	cfg := d.tlsConfig.Clone()
	cfg.ServerName = serverName
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("backend mTLS handshake: %w", err)
	}
	return conn, nil
}
