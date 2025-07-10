package beacon

import (
	"testing"
)

func TestParseBeaconURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "http URL",
			input:   "http://localhost:5052",
			want:    "http://localhost:5052",
			wantErr: false,
		},
		{
			name:    "https URL",
			input:   "https://beacon.example.com:5052",
			want:    "https://beacon.example.com:5052",
			wantErr: false,
		},
		{
			name:    "URL with path",
			input:   "http://localhost:5052/eth/v1/beacon",
			want:    "http://localhost:5052/eth/v1/beacon",
			wantErr: false,
		},
		{
			name:    "URL without scheme",
			input:   "localhost:5052",
			want:    "http://localhost:5052",
			wantErr: false,
		},
		{
			name:    "IP address without scheme",
			input:   "192.168.1.1:5052",
			want:    "http://192.168.1.1:5052",
			wantErr: false,
		},
		{
			name:    "URL with trailing slash",
			input:   "http://localhost:5052/",
			want:    "http://localhost:5052/",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid URL",
			input:   "://invalid",
			want:    "",
			wantErr: true,
		},
		{
			name:    "URL with auth",
			input:   "http://user:pass@localhost:5052",
			want:    "http://user:pass@localhost:5052",
			wantErr: false,
		},
		{
			name:    "URL with query params",
			input:   "http://localhost:5052?key=value",
			want:    "http://localhost:5052?key=value",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseBeaconURL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseBeaconURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseBeaconURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseBeaconURLEdgeCases(t *testing.T) {
	// Test with various edge cases
	edgeCases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "only hostname",
			input:   "beacon-node",
			wantErr: false,
		},
		{
			name:    "localhost without port",
			input:   "localhost",
			wantErr: false,
		},
		{
			name:    "IPv6 address",
			input:   "[::1]:5052",
			wantErr: false,
		},
		{
			name:    "IPv6 with scheme",
			input:   "http://[::1]:5052",
			wantErr: false,
		},
		{
			name:    "ftp scheme (invalid)",
			input:   "ftp://localhost:5052",
			wantErr: true,
		},
		{
			name:    "file scheme (invalid)",
			input:   "file:///path/to/file",
			wantErr: true,
		},
		{
			name:    "very long URL",
			input:   "http://very-long-hostname-that-goes-on-and-on-and-on.example.com:5052/very/long/path/that/continues/forever",
			wantErr: false,
		},
		{
			name:    "URL with fragment",
			input:   "http://localhost:5052#fragment",
			wantErr: false,
		},
		{
			name:    "multiple slashes",
			input:   "http://localhost:5052//double//slash",
			wantErr: false,
		},
		{
			name:    "special characters in path",
			input:   "http://localhost:5052/path%20with%20spaces",
			wantErr: false,
		},
	}

	for _, tc := range edgeCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseBeaconURL(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ParseBeaconURL(%q) expected error, got nil", tc.input)
				}
			} else {
				if err != nil {
					t.Errorf("ParseBeaconURL(%q) unexpected error: %v", tc.input, err)
				}
				// For edge cases without explicit want value, just check it's not empty
				if result == "" {
					t.Errorf("ParseBeaconURL(%q) returned empty string", tc.input)
				}
			}
		})
	}
}
