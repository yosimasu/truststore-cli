package client

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"
)

// MockServerConfig configures mock server behavior
type MockServerConfig struct {
	// ResponseDelay adds artificial delay to responses
	ResponseDelay time.Duration
	// FailAfterAttempts causes server to fail after N successful requests
	FailAfterAttempts int
	// ReturnStatus specifies the HTTP status code to return
	ReturnStatus int
	// ResponseBody specifies the response body
	ResponseBody string
}

// MockServer provides enhanced mock server functionality for testing HTTP clients
type MockServer struct {
	*httptest.Server
	config       MockServerConfig
	requestCount int64
	URL          string // Exposed URL for easy access
}

// Close closes the mock server
func (m *MockServer) Close() {
	if m.Server != nil {
		m.Server.Close()
	}
}

// NewMockServer creates a new mock server with the given configuration
func NewMockServer(config MockServerConfig) *MockServer {
	mock := &MockServer{
		config: config,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt64(&mock.requestCount, 1)

		// Add artificial delay if configured
		if mock.config.ResponseDelay > 0 {
			time.Sleep(mock.config.ResponseDelay)
		}

		// Fail after specified attempts
		if mock.config.FailAfterAttempts > 0 && int(count) > mock.config.FailAfterAttempts {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Mock server configured to fail"))
			return
		}

		// Return configured status code
		status := mock.config.ReturnStatus
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)

		// Return configured response body
		if mock.config.ResponseBody != "" {
			_, _ = w.Write([]byte(mock.config.ResponseBody))
		}
	}))

	mock.Server = server
	mock.URL = server.URL
	return mock
}

// RequestCount returns the number of requests received by the mock server
func (m *MockServer) RequestCount() int {
	return int(atomic.LoadInt64(&m.requestCount))
}

// ResetRequestCount resets the request counter
func (m *MockServer) ResetRequestCount() {
	atomic.StoreInt64(&m.requestCount, 0)
}

// MockTimeoutServer creates a mock server that never responds (for timeout testing)
func NewMockTimeoutServer() *MockServer {
	mock := &MockServer{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&mock.requestCount, 1)
		// Never write response to simulate timeout
		time.Sleep(10 * time.Second)
	}))

	mock.Server = server
	mock.URL = server.URL
	return mock
}

// MockNetworkErrorServer creates a server that immediately closes connections
func NewMockNetworkErrorServer() *MockServer {
	mock := &MockServer{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&mock.requestCount, 1)
		// Force connection close to simulate network error
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			if conn != nil {
				if err := conn.Close(); err != nil {
					// Log but don't fail - mock cleanup
					_ = err
				}
			}
		}
	}))

	mock.Server = server
	mock.URL = server.URL
	return mock
}

// CTLogMockServer provides crt.sh API specific mock functionality
type CTLogMockServer struct {
	*MockServer
}

// NewCTLogMockServer creates a mock server that simulates crt.sh API behavior
func NewCTLogMockServer() *CTLogMockServer {
	mock := &CTLogMockServer{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		// Handle certificate search requests
		if query.Get("CN") != "" && query.Get("output") == "json" {
			mock.handleSearchRequest(w, r)
			return
		}

		// Handle certificate download requests
		if query.Get("d") != "" {
			mock.handleDownloadRequest(w, r)
			return
		}

		// Unknown request
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Unknown request"))
	}))

	mock.MockServer = &MockServer{
		Server: server,
		URL:    server.URL,
	}
	return mock
}

func (m *CTLogMockServer) handleSearchRequest(w http.ResponseWriter, r *http.Request) {
	cn := r.URL.Query().Get("CN")

	// Simulate different responses based on CN
	switch cn {
	case "example.org":
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[
			{
				"id": 123456789,
				"common_name": "example.org",
				"issuer_name": "Example CA",
				"serial_number": "1234567890",
				"not_before": "2025-01-01T00:00:00Z",
				"not_after": "2026-01-01T00:00:00Z"
			}
		]`))
	case "notfound.example":
		// Return empty array for no results
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	case "error.example":
		// Return server error
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal server error"))
	default:
		// Return generic result
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `[
			{
				"id": 987654321,
				"common_name": "%s",
				"issuer_name": "Generic CA",
				"serial_number": "0987654321",
				"not_before": "2025-01-01T00:00:00Z",
				"not_after": "2026-01-01T00:00:00Z"
			}
		]`, cn)
	}
}

func (m *CTLogMockServer) handleDownloadRequest(w http.ResponseWriter, r *http.Request) {
	certID := r.URL.Query().Get("d")

	switch certID {
	case "123456789", "987654321":
		// Return valid certificate
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(testCertPEM))
	case "404":
		// Return not found
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Certificate not found"))
	case "500":
		// Return server error
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal server error"))
	default:
		// Return invalid PEM
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Invalid certificate data"))
	}
}

// TestCertPEM is a valid test certificate for use in tests
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
