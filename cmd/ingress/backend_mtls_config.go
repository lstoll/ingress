package main

import (
	"fmt"
	"strings"
)

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
