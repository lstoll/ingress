package main

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

	"github.com/lstoll/ingress/internal/mtls"
)

func TestKubernetesServiceDNS(t *testing.T) {
	got := kubernetesServiceDNS("web", "default")
	want := "web.default.svc.cluster.local"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBackendMTLSRejectsWrongServerName(t *testing.T) {
	fix := mtls.NewTestFixture(t)

	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plainLn.Close() })

	serverCfg, err := mtls.ServerConfig(fix.ServerCert, fix.ServerKey, fix.CAFile, fix.IngressSVID)
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(plainLn, serverCfg)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}()

	clientCfg, err := mtls.ClientConfig(fix.ClientCert, fix.ClientKey, fix.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	dialer := newBackendDialer(clientCfg)

	_, err = dialer.DialContext(context.Background(), "tcp", ln.Addr().String(), "wrong.example.test", true)
	if err == nil {
		t.Fatal("expected handshake failure for wrong server name")
	}
}
