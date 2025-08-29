package client

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testCertPEM = `-----BEGIN CERTIFICATE-----
MIIDozCCAougAwIBAgIUfdhU6GQU6oD22HvwXjzQ03Xqh78wDQYJKoZIhvcNAQEL
BQAwYTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJh
bmNpc2NvMRIwEAYDVQQKDAlUZXN0IENvcnAxGTAXBgNVBAMMEHRlc3QuZXhhbXBs
ZS5jb20wHhcNMjUwODI4MTYwNTU0WhcNMjYwODI4MTYwNTU0WjBhMQswCQYDVQQG
EwJVUzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xEjAQBgNV
BAoMCVRlc3QgQ29ycDEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMPXfV/BNis9ZV5OcbwdjFisiKN2AqIG
w+riNCaNlBRwIhX2geijDK5r8U+r93k3LE/yIm6DZzLGqkBYDHj7e1Ba1k6deIak
UYlU5gcdrDOlvNOf5c7TnU2+kvM5MKl/1XHd5AKvUWpp0BLbX8ElDSKmZMMhpwJ7
aywAR5S0Fu9rmmJlJ85qb3Adk5TvZDDH2eXhvhMViwk1eAXtMTn0isNyepXEVSiy
484lIeDK7TZz231qAeKe1TJch3WWvCIeRO52XEBGq4zON0hcw8daG0wesuuMVGp2
Nf7trM35U18rlBYkMkMSabMoFQly6W6tC44vagZfhCpQDIgp/xgVTLkCAwEAAaNT
MFEwHQYDVR0OBBYEFGccvF8TPjDUteZyZKxbgSlKvrJzMB8GA1UdIwQYMBaAFGcc
vF8TPjDUteZyZKxbgSlKvrJzMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAKat9EvGNsQz9coc7SfBJiJbDsqXrp5ItuyGp46KQwGxd/Id9oBRk51W
2GbsFH1Rkm2oAW+VqWroRBIHdyPSPWAcxIP+by4+jWaPJWWXb+75BpCitV+FbM+A
nrgNC8ez4uZ8a8iJ21bGl/b46S8VkzIQ9DOoXqIvxZS6Gqimw8EgrFQYb3ztdIyT
B+N1jOlP2YAabbhOCsi+HFgniarAyVWaEOSLIQZATO4h0WaQFznlvE3O2JPtAXrW
/DMiQajQYDidCplTPlqi7YsY1Bi2MA8iNcf5NehNgV7inuaTi1isIBxX5y8OQXEV
iDAAHBIw3Qui4t7XMnqz+8Y7nr3PSQg=
-----END CERTIFICATE-----`

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

			// Create client with mock server URL
			client := &ctLogClient{
				baseURL:    server.URL + "/",
				httpClient: server.Client(),
			}

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

			// Create client with mock server URL
			client := &ctLogClient{
				baseURL:    server.URL + "/",
				httpClient: server.Client(),
			}

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
	client := &ctLogClient{
		baseURL:    "http://invalid-url-that-does-not-exist.invalid/",
		httpClient: &http.Client{},
	}

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