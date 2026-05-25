package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/lstoll/ingress/internal/mtls"
)

type backendDialer struct {
	reloader *mtls.Reloader
}

func newBackendDialer(reloader *mtls.Reloader) *backendDialer {
	return &backendDialer{reloader: reloader}
}

func (d *backendDialer) enabled() bool {
	return d != nil && d.reloader != nil
}

func (d *backendDialer) DialContext(ctx context.Context, network, address, serverName string, mtlsEnabled bool) (net.Conn, error) {
	if !mtlsEnabled || d == nil || d.reloader == nil {
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

	conn := tls.Client(raw, d.reloader.ClientTLSConfig(serverName))
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("backend mTLS handshake: %w", err)
	}
	return conn, nil
}
