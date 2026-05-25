package main

import (
	"fmt"
	"strings"
)

func validateBackendMTLSFlags(clientCert, clientKey, clientBundle, caFile string) error {
	hasCA := strings.TrimSpace(caFile) != ""
	hasBundle := strings.TrimSpace(clientBundle) != ""
	hasCert := strings.TrimSpace(clientCert) != ""
	hasKey := strings.TrimSpace(clientKey) != ""
	hasIdentity := hasBundle || hasCert || hasKey

	if !hasIdentity && !hasCA {
		return nil
	}
	if !hasCA {
		return fmt.Errorf("--backend-mtls-ca is required when backend mTLS identity material is configured")
	}
	if hasBundle && (hasCert || hasKey) {
		return fmt.Errorf("use either --backend-mtls-client-bundle or --backend-mtls-client-cert/--backend-mtls-client-key, not both")
	}
	if hasBundle {
		return nil
	}
	if hasCert && hasKey {
		return nil
	}
	return fmt.Errorf("backend mTLS requires either --backend-mtls-client-bundle or both --backend-mtls-client-cert and --backend-mtls-client-key")
}

func backendMTLSConfigured(clientCert, clientKey, clientBundle, caFile string) bool {
	if strings.TrimSpace(caFile) == "" {
		return false
	}
	if strings.TrimSpace(clientBundle) != "" {
		return true
	}
	return strings.TrimSpace(clientCert) != "" && strings.TrimSpace(clientKey) != ""
}
