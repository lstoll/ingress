package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type connCtxKey struct{}

func TestSNISniffing(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, ok := r.Context().Value(connCtxKey{}).(net.Conn)
		if !ok {
			t.Fatal("no conn in ctx")
		}
		log.Printf("conn: %#v", conn)
		// log.Printf("conn host: %s", conn.ServerName())

		w.Write([]byte("host-2"))
	})

	{
		plainserver := httptest.NewUnstartedServer(h)
		plainserver.Listener = NewSNISniffListener(plainserver.Listener)

		plainserver.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connCtxKey{}, c)
		}

		plainserver.Start()

		plainclient := http.DefaultClient

		plainreq, err := http.NewRequest("GET", plainserver.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("requesting %s", plainreq.URL.String())
		resp, err := plainclient.Do(plainreq)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal()
		}
		_ = resp.Close
		log.Printf("body: %s", string(b))
	}

	{

		server := httptest.NewUnstartedServer(h)
		server.TLS = mustTLSCert(t, "host-1")
		server.Listener = NewSNISniffListener(server.Listener)

		server.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connCtxKey{}, c)
		}

		server.StartTLS()

		host1client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         "host-1",
				},
			},
		}

		h1req, err := http.NewRequest("GET", server.URL, nil)
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
			t.Fatal()
		}
		_ = resp.Close
		log.Printf("body: %s", string(b))

		return

		host2client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         "host-1",
				},
			},
		}

		h2req, err := http.NewRequest("GET", server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err = host2client.Do(h2req)
		if err != nil {
			t.Fatal(err)
		}
		b, err = io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal()
		}
		_ = resp.Close
		_ = b
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
