package main

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/lstoll/ingress/internal/mtls"
)

func loadBackendMTLSClientConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cfg, err := mtls.ClientConfig(certFile, keyFile, caFile)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func validateBackendMTLSFlags(clientCert, clientKey, caFile string) error {
	set := []string{clientCert, clientKey, caFile}
	anySet := false
	allSet := true
	for _, v := range set {
		if strings.TrimSpace(v) != "" {
			anySet = true
		} else {
			allSet = false
		}
	}
	if !anySet {
		return nil
	}
	if !allSet {
		return fmt.Errorf("--backend-mtls-client-cert, --backend-mtls-client-key, and --backend-mtls-ca must all be set together")
	}
	return nil
}
