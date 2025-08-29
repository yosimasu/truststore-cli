package client

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)


func TestNewCTLogClient(t *testing.T) {
	client := NewCTLogClient()
	if client == nil {
		t.Fatal("NewCTLogClient returned nil")
	}
}

func TestSearchCertificatesByIssuer(t *testing.T) {
	tests := []struct {
		name           string
		issuerName     string
		responseBody   string
		responseStatus int
		wantError      bool
		wantCount      int
	}{
		{
			name:           "successful search with results",
			issuerName:     "Test CA",
			responseBody:   `[{"id": 1, "common_name": "example.com", "issuer_name": "Test CA", "serial_number": "123"}]`,
			responseStatus: 200,
			wantError:      false,
			wantCount:      1,
		},
		{
			name:           "successful search with no results",
			issuerName:     "Nonexistent CA",
			responseBody:   `[]`,
			responseStatus: 200,
			wantError:      false,
			wantCount:      0,
		},
		{
			name:           "empty response body",
			issuerName:     "Empty CA",
			responseBody:   "",
			responseStatus: 200,
			wantError:      false,
			wantCount:      0,
		},
		{
			name:           "API error response",
			issuerName:     "Error CA",
			responseBody:   "Internal Server Error",
			responseStatus: 500,
			wantError:      true,
			wantCount:      0,
		},
		{
			name:           "invalid JSON response",
			issuerName:     "Invalid JSON CA",
			responseBody:   `{"invalid": json}`,
			responseStatus: 200,
			wantError:      true,
			wantCount:      0,
		},
		{
			name:       "empty issuer name",
			issuerName: "",
			wantError:  true,
			wantCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip server setup for empty issuer name test
			if tt.issuerName == "" {
				client := NewCTLogClient()
				_, err := client.SearchCertificatesByIssuer(tt.issuerName)
				if !tt.wantError {
					t.Errorf("SearchCertificatesByIssuer() error = %v, wantError %v", err, tt.wantError)
				}
				return
			}

			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify query parameters
				if r.URL.Query().Get("CN") != tt.issuerName {
					t.Errorf("Expected CN parameter %q, got %q", tt.issuerName, r.URL.Query().Get("CN"))
				}
				if r.URL.Query().Get("output") != "json" {
					t.Errorf("Expected output parameter 'json', got %q", r.URL.Query().Get("output"))
				}
				if r.URL.Query().Get("exclude") != "expired" {
					t.Errorf("Expected exclude parameter 'expired', got %q", r.URL.Query().Get("exclude"))
				}

				w.WriteHeader(tt.responseStatus)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			// Create client using new constructor and override base URL
			client := NewCTLogClientWithHTTPClient(NewHTTPClient(DefaultConfig())).(*ctLogClient)
			client.baseURL = server.URL + "/"

			entries, err := client.SearchCertificatesByIssuer(tt.issuerName)

			if (err != nil) != tt.wantError {
				t.Errorf("SearchCertificatesByIssuer() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if len(entries) != tt.wantCount {
				t.Errorf("SearchCertificatesByIssuer() got %d entries, want %d", len(entries), tt.wantCount)
			}

			// Verify first entry if we expect results
			if tt.wantCount > 0 && len(entries) > 0 {
				if entries[0].ID != 1 {
					t.Errorf("Expected first entry ID 1, got %d", entries[0].ID)
				}
				if entries[0].CommonName != "example.com" {
					t.Errorf("Expected first entry CommonName 'example.com', got %q", entries[0].CommonName)
				}
			}
		})
	}
}

func TestDownloadCertificate(t *testing.T) {
	tests := []struct {
		name           string
		id             int
		responseBody   string
		responseStatus int
		wantError      bool
	}{
		{
			name:           "successful download",
			id:             123,
			responseBody:   testCertPEM,
			responseStatus: 200,
			wantError:      false,
		},
		{
			name:           "API error response",
			id:             456,
			responseBody:   "Not Found",
			responseStatus: 404,
			wantError:      true,
		},
		{
			name:           "empty response body",
			id:             789,
			responseBody:   "",
			responseStatus: 200,
			wantError:      true,
		},
		{
			name:           "invalid PEM data",
			id:             101,
			responseBody:   "not a certificate",
			responseStatus: 200,
			wantError:      true,
		},
		{
			name:      "invalid ID (zero)",
			id:        0,
			wantError: true,
		},
		{
			name:      "invalid ID (negative)",
			id:        -1,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip server setup for invalid ID tests
			if tt.id <= 0 {
				client := NewCTLogClient()
				_, err := client.DownloadCertificate(tt.id)
				if !tt.wantError {
					t.Errorf("DownloadCertificate() error = %v, wantError %v", err, tt.wantError)
				}
				return
			}

			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify query parameters
				expectedPath := fmt.Sprintf("/?d=%d", tt.id)
				if r.URL.Path+"?"+r.URL.RawQuery != expectedPath {
					t.Errorf("Expected path %q, got %q", expectedPath, r.URL.Path+"?"+r.URL.RawQuery)
				}

				w.WriteHeader(tt.responseStatus)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			// Create client using new constructor and override base URL
			client := NewCTLogClientWithHTTPClient(NewHTTPClient(DefaultConfig())).(*ctLogClient)
			client.baseURL = server.URL + "/"

			cert, err := client.DownloadCertificate(tt.id)

			if (err != nil) != tt.wantError {
				t.Errorf("DownloadCertificate() error = %v, wantError %v", err, tt.wantError)
				return
			}

			// Verify certificate if we expect success
			if !tt.wantError {
				if cert == nil {
					t.Error("DownloadCertificate() returned nil certificate")
				} else if cert.Subject.CommonName != "test.example.com" {
					t.Errorf("Expected certificate CN 'test.example.com', got %q", cert.Subject.CommonName)
				}
			}
		})
	}
}

func TestCTLogClient_NetworkFailure(t *testing.T) {
	// Create client with invalid URL to simulate network failure
	config := &Config{
		Timeout:    100 * time.Millisecond,
		MaxRetries: 1,
		BaseDelay:  1 * time.Millisecond,
		MaxDelay:   1 * time.Millisecond,
	}
	client := NewCTLogClientWithHTTPClient(NewHTTPClient(config)).(*ctLogClient)
	client.baseURL = "http://invalid-url-that-does-not-exist.invalid/"

	// Test search network failure
	_, err := client.SearchCertificatesByIssuer("Test CA")
	if err == nil {
		t.Error("Expected error for network failure in SearchCertificatesByIssuer")
	}
	if !strings.Contains(err.Error(), "failed to search certificates") {
		t.Errorf("Expected search error message, got: %v", err)
	}

	// Test download network failure
	_, err = client.DownloadCertificate(123)
	if err == nil {
		t.Error("Expected error for network failure in DownloadCertificate")
	}
	if !strings.Contains(err.Error(), "failed to download certificate") {
		t.Errorf("Expected download error message, got: %v", err)
	}
}