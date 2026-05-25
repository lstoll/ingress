package mtls

import (
	"crypto/x509"
	"fmt"
	"strings"
)

const spiffePrefix = "spiffe://"

// ClientSVID returns the SPIFFE URI SAN from a client certificate, if present.
func ClientSVID(cert *x509.Certificate) (string, bool) {
	for _, uri := range cert.URIs {
		if uri == nil {
			continue
		}
		s := uri.String()
		if strings.HasPrefix(s, spiffePrefix) {
			return s, true
		}
	}
	return "", false
}

// VerifyClientSVID checks that cert carries exactly the expected SPIFFE ID.
func VerifyClientSVID(cert *x509.Certificate, expected string) error {
	if expected == "" {
		return fmt.Errorf("expected client SVID must be set")
	}
	got, ok := ClientSVID(cert)
	if !ok {
		return fmt.Errorf("client certificate has no SPIFFE URI SAN")
	}
	if got != expected {
		return fmt.Errorf("client SVID %q does not match expected %q", got, expected)
	}
	return nil
}
