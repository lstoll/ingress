package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"inet.af/tcpproxy"
	"k8s.io/apimachinery/pkg/types"
)

type connCtxKey struct{}

// One Kubernetes Service per hostname: each passthrough backend is its own binding.
func testIngressRouterPassthrough(hostToAddr map[string]string) *ingressRouter {
	ir := newIngressRouter(testLogger(), context.Background(), nil)
	ir.mu.Lock()
	defer ir.mu.Unlock()
	n := 0
	for host, addr := range hostToAddr {
		n++
		owner := types.NamespacedName{Namespace: "test", Name: fmt.Sprintf("svc%d", n)}
		ir.tlsHostnameToService[host] = owner
		ir.serviceBindings[owner] = &serviceBinding{
			serviceRef:  owner,
			mode:        modeTLSPassthrough,
			targetAddr:  addr,
			hostnames:   []string{host},
			passthrough: &tcpproxy.DialProxy{Addr: addr},
		}
	}
	return ir
}

func TestIngressRouter_PassthroughSNI(t *testing.T) {
	host1server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("host-1"))
	}))
	host1server.TLS = mustTLSCert(t, "host-1")

	host1server.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, connCtxKey{}, c)
	}

	host1server.StartTLS()

	host2server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("host-2"))
	}))
	host2server.TLS = mustTLSCert(t, "host-2")

	host2server.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, connCtxKey{}, c)
	}

	host2server.StartTLS()

	ir := testIngressRouterPassthrough(map[string]string{
		"host-1": host1server.Listener.Addr().String(),
		"host-2": host2server.Listener.Addr().String(),
	})

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
	p.AddSNIMatchRoute(proxyAddr, ir.matchSNI, ir)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = p.Close()
	}()

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
		if err == nil {
			t.Fatal("expected error for unknown SNI (tcpproxy closes before handshake completes)")
		}
	}

	host1server.Close()
	host2server.Close()
}

func TestIngressRouter_HTTPSSNIMustMatchHost(t *testing.T) {
	owner := types.NamespacedName{Namespace: "default", Name: "web"}
	ir := newIngressRouter(testLogger(), context.Background(), nil)
	ir.mu.Lock()
	ir.tlsHostnameToService["a.example.test"] = owner
	ir.serviceBindings[owner] = &serviceBinding{
		serviceRef: owner,
		mode:       modeHTTPS,
		targetAddr: "127.0.0.1:9",
		hostnames:  []string{"a.example.test"},
		httpsHosts: map[string]httpsHostBinding{
			"a.example.test": {
				handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusTeapot)
				}),
			},
		},
	}
	ir.mu.Unlock()

	h := ir.serveHTTPForOwner(owner)

	t.Run("mismatch_421", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://b.example.test/", nil)
		req.Host = "b.example.test"
		req.TLS = &tls.ConnectionState{ServerName: "a.example.test"}
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusMisdirectedRequest {
			t.Fatalf("code %d, body %q", rr.Code, rr.Body.String())
		}
	})

	t.Run("match_proxies", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://a.example.test/", nil)
		req.Host = "a.example.test"
		req.TLS = &tls.ConnectionState{ServerName: "a.example.test"}
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusTeapot {
			t.Fatalf("expected backend handler, got %d", rr.Code)
		}
	})
}

func TestIngressRouter_TLSTermination(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("terminated"))
	}))
	defer backend.Close()

	addr := backend.Listener.Addr().String()

	cp, err := newCertProvider(certModeSelfSigned, certProviderConfig{
		AllowHost: func(host string) bool { return host == "app.localtest.me" },
	})
	if err != nil {
		t.Fatal(err)
	}

	owner := types.NamespacedName{Namespace: "default", Name: "term"}
	ir := newIngressRouter(testLogger(), context.Background(), cp)
	ir.mu.Lock()
	ir.tlsHostnameToService["app.localtest.me"] = owner
	ir.serviceBindings[owner] = &serviceBinding{
		serviceRef: owner,
		mode:       modeTLSTermination,
		targetAddr: addr,
		hostnames:  []string{"app.localtest.me"},
	}
	ir.mu.Unlock()

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
	p.AddSNIMatchRoute(proxyAddr, ir.matchSNI, ir)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = p.Close()
	}()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "app.localtest.me",
			},
		},
	}
	req, err := http.NewRequest("GET", "https://"+proxyAddr, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "terminated" {
		t.Fatalf("expected terminated response, got %q", string(body))
	}
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

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
