package main

import "testing"

func TestValidateStartupConfig(t *testing.T) {
	tests := []struct {
		name                    string
		instance                string
		certMode                string
		autocertSecret          string
		backendMTLSCert         string
		backendMTLSKey          string
		backendMTLSBundle       string
		backendMTLSCA           string
		wantErr                 bool
	}{
		{
			name:     "valid self-signed mode",
			instance: "ingress1",
			certMode: certModeSelfSigned,
		},
		{
			name:     "missing instance",
			certMode: certModeSelfSigned,
			wantErr:  true,
		},
		{
			name:       "autocert missing secret",
			instance:   "ingress1",
			certMode:   certModeAutocert,
			wantErr:    true,
		},
		{
			name:           "autocert invalid secret format",
			instance:       "ingress1",
			certMode:       certModeAutocert,
			autocertSecret: "autocert-cache",
			wantErr:        true,
		},
		{
			name:           "autocert valid secret format",
			instance:       "ingress1",
			certMode:       certModeAutocert,
			autocertSecret: "ingress-dev/autocert-cache",
		},
		{
			name:            "backend mtls partial flags",
			instance:        "ingress1",
			certMode:        certModeSelfSigned,
			backendMTLSCert: "cert.pem",
			wantErr:         true,
		},
		{
			name:            "backend mtls all split flags",
			instance:        "ingress1",
			certMode:        certModeSelfSigned,
			backendMTLSCert: "cert.pem",
			backendMTLSKey:  "key.pem",
			backendMTLSCA:   "ca.pem",
		},
		{
			name:              "backend mtls bundle flags",
			instance:          "ingress1",
			certMode:          certModeSelfSigned,
			backendMTLSBundle: "bundle.pem",
			backendMTLSCA:     "ca.pem",
		},
		{
			name:              "backend mtls bundle and split flags",
			instance:          "ingress1",
			certMode:          certModeSelfSigned,
			backendMTLSBundle: "bundle.pem",
			backendMTLSCert:   "cert.pem",
			backendMTLSKey:    "key.pem",
			backendMTLSCA:     "ca.pem",
			wantErr:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateStartupConfig(tt.instance, tt.certMode, tt.autocertSecret, tt.backendMTLSCert, tt.backendMTLSKey, tt.backendMTLSBundle, tt.backendMTLSCA)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error but got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateBackendMTLSFlags(t *testing.T) {
	if err := validateBackendMTLSFlags("", "", "", ""); err != nil {
		t.Fatalf("expected nil for unset flags: %v", err)
	}
	if err := validateBackendMTLSFlags("cert", "key", "", "ca"); err != nil {
		t.Fatalf("expected nil for split flags: %v", err)
	}
	if err := validateBackendMTLSFlags("", "", "bundle", "ca"); err != nil {
		t.Fatalf("expected nil for bundle flags: %v", err)
	}
	if err := validateBackendMTLSFlags("cert", "", "", "ca"); err == nil {
		t.Fatal("expected error for partial split flags")
	}
	if err := validateBackendMTLSFlags("", "", "bundle", ""); err == nil {
		t.Fatal("expected error for bundle without ca")
	}
	if err := validateBackendMTLSFlags("cert", "key", "bundle", "ca"); err == nil {
		t.Fatal("expected error for bundle and split flags together")
	}
}
