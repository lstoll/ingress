package main

import "testing"

func TestValidateStartupConfig(t *testing.T) {
	tests := []struct {
		name           string
		gatewayName    string
		certMode       string
		autocertSecret string
		wantErr        bool
	}{
		{
			name:        "valid self-signed mode",
			gatewayName: "ingress",
			certMode:    certModeSelfSigned,
		},
		{
			name:        "missing gateway name",
			certMode:    certModeSelfSigned,
			wantErr:     true,
		},
		{
			name:        "autocert missing secret",
			gatewayName: "ingress",
			certMode:    certModeAutocert,
			wantErr:     true,
		},
		{
			name:           "autocert invalid secret format",
			gatewayName:    "ingress",
			certMode:       certModeAutocert,
			autocertSecret: "autocert-cache",
			wantErr:        true,
		},
		{
			name:           "autocert valid secret format",
			gatewayName:    "ingress",
			certMode:       certModeAutocert,
			autocertSecret: "ingress-dev/autocert-cache",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateStartupConfig(tt.gatewayName, tt.certMode, tt.autocertSecret)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error but got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
