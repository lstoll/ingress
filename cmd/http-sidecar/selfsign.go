package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"time"
)

func mustSelfCert() tls.Certificate {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	t := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"ingresssssssssssssss"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 12),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
	}

	db, err := x509.CreateCertificate(rand.Reader, &t, &t, &p.PublicKey, p)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{db},
		PrivateKey:  p,
	}
}
