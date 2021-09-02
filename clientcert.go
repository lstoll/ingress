package main

import (
	"context"
	"crypto/x509"
	_ "embed"
	"log"
	"net/http"
)

type clientCertContextKey struct{}

type presentedCert struct {
	// TODO - what data can/should we capture?

	CommonName string
}

func captureClientCert(clientCAPool *x509.CertPool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var validCert *x509.Certificate

		if r.TLS == nil {
			log.Print("nil tls")
			next.ServeHTTP(w, r)
			return
		}

		for _, c := range r.TLS.PeerCertificates {
			// first make sure we were presented with a certificate we trust
			o := x509.VerifyOptions{
				Roots: clientCAPool,
				// TODO - key usage we should check?
			}
			if _, err := c.Verify(o); err == nil {
				validCert = c
				break
			}
			log.Printf("failed to verify cert %s, ignoring it", c.Subject.CommonName)
		}

		if validCert != nil {
			pc := presentedCert{
				CommonName: validCert.Subject.CommonName,
			}
			r = r.WithContext(context.WithValue(r.Context(), clientCertContextKey{}, &pc))
		}

		next.ServeHTTP(w, r)
	})
}

func presentedCertFromContext(ctx context.Context) *presentedCert {
	v, _ := ctx.Value(clientCertContextKey{}).(*presentedCert)
	return v
}
