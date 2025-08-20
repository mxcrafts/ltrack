package utils

import (
	"os"
	"strings"
	"testing"
)

func TestGetHostname(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "get hostname successfully",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostname, err := GetHostname()
			
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHostname() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if !tt.wantErr {
				// Verify that hostname is not empty
				if hostname == "" {
					t.Errorf("GetHostname() returned empty hostname")
				}
				
				// Verify that hostname doesn't contain invalid characters
				if strings.Contains(hostname, "\n") || strings.Contains(hostname, "\r") {
					t.Errorf("GetHostname() returned hostname with newline characters: %q", hostname)
				}
				
				// Compare with os.Hostname() directly to ensure consistency
				expectedHostname, expectedErr := os.Hostname()
				if expectedErr != nil {
					t.Errorf("os.Hostname() failed: %v", expectedErr)
				}
				
				if hostname != expectedHostname {
					t.Errorf("GetHostname() = %v, want %v", hostname, expectedHostname)
				}
				
				t.Logf("Hostname: %s", hostname)
			}
		})
	}
}

func TestGetHostnameConsistency(t *testing.T) {
	// Test that multiple calls return the same result
	hostname1, err1 := GetHostname()
	if err1 != nil {
		t.Fatalf("First GetHostname() call failed: %v", err1)
	}
	
	hostname2, err2 := GetHostname()
	if err2 != nil {
		t.Fatalf("Second GetHostname() call failed: %v", err2)
	}
	
	if hostname1 != hostname2 {
		t.Errorf("GetHostname() returned inconsistent results: %q vs %q", hostname1, hostname2)
	}
}

func BenchmarkGetHostname(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GetHostname()
		if err != nil {
			b.Fatalf("GetHostname() failed: %v", err)
		}
	}
}

// TestGetHostnameExample demonstrates how to use GetHostname function
func ExampleGetHostname() {
	hostname, err := GetHostname()
	if err != nil {
		panic(err)
	}
	
	// hostname will contain the current machine's hostname
	_ = hostname
}
