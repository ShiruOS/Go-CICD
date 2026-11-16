package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		authHeader  string
		expectedKey string
		expectError bool
	}{
		{
			name:        "valid API key",
			authHeader:  "ApiKey my-secret-key",
			expectedKey: "my-secret-key",
			expectError: false,
		},
		{
			name:        "missing authorization header",
			authHeader:  "",
			expectedKey: "",
			expectError: true,
		},
		{
			name:        "invalid authentication scheme",
			authHeader:  "Bearer my-secret-key",
			expectedKey: "",
			expectError: true,
		},
		{
			name:        "malformed header - missing API key",
			authHeader:  "ApiKey",
			expectedKey: "",
			expectError: true,
		},
		{
			name:        "malformed header - empty API key",
			authHeader:  "ApiKey ",
			expectedKey: "",
			expectError: false,
		},
		{
			name:        "extra values in header",
			authHeader:  "ApiKey my-secret-key extra",
			expectedKey: "my-secret-key",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)

			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			gotKey, err := GetAPIKey(headers)

			if tt.expectError && err == nil {
				t.Fatal("expected an error, got nil")
			}

			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if gotKey != tt.expectedKey {
				t.Errorf("expected API key %q, got %q",
					tt.expectedKey, gotKey)
			}
		})
	}
}
