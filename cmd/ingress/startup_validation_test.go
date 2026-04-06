package main

import "testing"

func TestValidateStartupConfig(t *testing.T) {
	tests := []struct {
		name           string
		instance       string
		certMode       string
		autocertSecret string
		wantErr        bool
	}{
		{
			name:        "valid self-signed mode",
			instance:    "ingress1",
			certMode:    certModeSelfSigned,
		},
		{
			name:        "missing instance",
			certMode:    certModeSelfSigned,
			wantErr:     true,
		},
		{
			name:        "autocert missing secret",
			instance:    "ingress1",
			certMode:    certModeAutocert,
			wantErr:     true,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateStartupConfig(tt.instance, tt.certMode, tt.autocertSecret)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error but got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
