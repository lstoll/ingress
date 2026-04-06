package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"go.uber.org/zap/zapcore"
	"inet.af/tcpproxy"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

type connCtxKey struct{}

type mockProxySource struct {
	targets map[string]string
}

func (m *mockProxySource) DialProxyFor(hostName string) (*tcpproxy.DialProxy, error) {
	if addr, ok := m.targets[hostName]; ok {
		return &tcpproxy.DialProxy{Addr: addr}, nil
	}
	return nil, nil
}

func TestDirector(t *testing.T) {
	host1server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("host-1"))
	}))
	host1server.TLS = mustTLSCert(t, "host-1")

	host1server.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, connCtxKey{}, c)
	}

	host1server.StartTLS()

	host2server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("host-2"))
	}))
	host2server.TLS = mustTLSCert(t, "host-2")

	host2server.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, connCtxKey{}, c)
	}

	host2server.StartTLS()

	d := &director{
		logger: testLogger(),
		ps: &mockProxySource{
			targets: map[string]string{
				"host-1": host1server.Listener.Addr().String(),
				"host-2": host2server.Listener.Addr().String(),
			},
		},
	}

	// alloc an unused port for the proxy
	tl, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	_, lp, err := net.SplitHostPort(tl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = tl.Close()

	proxyAddr := net.JoinHostPort("localhost", lp)

	p := &tcpproxy.Proxy{}
	p.AddSNIMatchRoute(proxyAddr, MatchAny, d)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	{
		host1client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         "host-1",
				},
			},
		}

		h1req, err := http.NewRequest("GET", "https://"+proxyAddr, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("requesting %s", h1req.URL.String())
		resp, err := host1client.Do(h1req)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if string(b) != "host-1" {
			t.Errorf("wanted connection for host-1, got: %s", string(b))
		}
	}

	{
		host2client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         "host-2",
				},
			},
		}

		h2req, err := http.NewRequest("GET", "https://"+proxyAddr, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("requesting %s", h2req.URL.String())
		resp, err := host2client.Do(h2req)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if string(b) != "host-2" {
			t.Errorf("wanted connection for host-2, got: %s", string(b))
		}
	}

	{
		host3client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         "host-3",
				},
			},
		}

		h3req, err := http.NewRequest("GET", "https://"+proxyAddr, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("requesting %s", h3req.URL.String())
		_, err = host3client.Do(h3req)
		if !errors.Is(err, io.EOF) {
			t.Errorf("wanted %v error for bad hostname, got: %v", io.EOF, err)
		}
	}

	host1server.Close()
	host2server.Close()
}

func mustTLSCert(t *testing.T, serverName string) *tls.Config {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	keyUsage := x509.KeyUsageDigitalSignature

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Testing"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),

		DNSNames: []string{serverName},

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{derBytes},
				PrivateKey:  priv,
			},
		},
	}
}

func testLogger() logr.Logger {
	return zap.New(zap.UseDevMode(true), zap.Level(zapcore.Level(0)))
}
