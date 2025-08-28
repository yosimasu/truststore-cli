package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewListCommand(t *testing.T) {
	cmd := NewListCommand()

	// Test command properties
	if cmd.Use != "list [source]" {
		t.Errorf("Expected Use to be 'list [source]', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected Short description to be non-empty")
	}

	if cmd.Long == "" {
		t.Error("Expected Long description to be non-empty")
	}

	// Test that password flag is available
	passwordFlag := cmd.Flags().Lookup("password")
	if passwordFlag == nil {
		t.Error("Expected 'password' flag to be available")
	}

	if passwordFlag.Shorthand != "p" {
		t.Errorf("Expected password flag shorthand to be 'p', got %q", passwordFlag.Shorthand)
	}
}

func TestListCommandExecution(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "list help",
			args:     []string{"--help"},
			wantErr:  false,
			contains: "List certificates from various sources",
		},
		{
			name:    "list with domain",
			args:    []string{"example.org"},
			wantErr: false,
		},
		{
			name:    "list with domain and port",
			args:    []string{"example.org:443"},
			wantErr: false,
		},
		{
			name:    "list with password flag",
			args:    []string{"keystore.jks", "--password", "secret"},
			wantErr: false,
		},
		{
			name:    "list with password shorthand",
			args:    []string{"keystore.p12", "-p", "secret"},
			wantErr: false,
		},
		{
			name:    "list without arguments",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "list with too many arguments",
			args:    []string{"arg1", "arg2"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewListCommand()
			cmd.SetArgs(tt.args)

			// Capture output
			var output strings.Builder
			cmd.SetOut(&output)
			cmd.SetErr(&output)

			err := cmd.Execute()

			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.contains != "" {
				got := output.String()
				if !strings.Contains(got, tt.contains) {
					t.Errorf("Execute() output = %q, want containing %q", got, tt.contains)
				}
			}
		})
	}
}

func TestRunListCommand(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		password string
		wantErr  bool
	}{
		{
			name:     "run with domain",
			args:     []string{"example.org"},
			password: "",
			wantErr:  false,
		},
		{
			name:     "run with domain and password",
			args:     []string{"keystore.jks"},
			password: "secret",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewListCommand()
			if tt.password != "" {
				cmd.SetArgs(append(tt.args, "--password", tt.password))
			} else {
				cmd.SetArgs(tt.args)
			}

			err := runListCommand(cmd, tt.args)

			if (err != nil) != tt.wantErr {
				t.Errorf("runListCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsDomainSource(t *testing.T) {
	// Create a temporary test file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.pem")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	tests := []struct {
		name     string
		source   string
		expected bool
	}{
		// Domain cases
		{
			name:     "simple domain",
			source:   "example.org",
			expected: true,
		},
		{
			name:     "domain with port",
			source:   "example.org:443",
			expected: true,
		},
		{
			name:     "subdomain",
			source:   "www.example.org",
			expected: true,
		},
		{
			name:     "IP address",
			source:   "192.168.1.1",
			expected: true,
		},
		{
			name:     "IP address with port",
			source:   "192.168.1.1:8443",
			expected: true,
		},
		// File cases - by extension
		{
			name:     "PEM file extension",
			source:   "certificate.pem",
			expected: false,
		},
		{
			name:     "CRT file extension",
			source:   "certificate.crt",
			expected: false,
		},
		{
			name:     "JKS file extension",
			source:   "keystore.jks",
			expected: false,
		},
		{
			name:     "P12 file extension",
			source:   "keystore.p12",
			expected: false,
		},
		{
			name:     "PFX file extension",
			source:   "keystore.pfx",
			expected: false,
		},
		{
			name:     "CER file extension",
			source:   "certificate.cer",
			expected: false,
		},
		{
			name:     "case insensitive extension",
			source:   "certificate.PEM",
			expected: false,
		},
		// File cases - by path
		{
			name:     "unix path",
			source:   "/path/to/certificate",
			expected: false,
		},
		{
			name:     "relative unix path",
			source:   "./certificate",
			expected: false,
		},
		{
			name:     "windows path",
			source:   "C:\\path\\to\\certificate",
			expected: false,
		},
		{
			name:     "relative windows path",
			source:   ".\\certificate",
			expected: false,
		},
		// File cases - by existence
		{
			name:     "existing file",
			source:   testFile,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isDomainSource(tt.source)
			if result != tt.expected {
				t.Errorf("isDomainSource(%q) = %v, want %v", tt.source, result, tt.expected)
			}
		})
	}
}

func TestHandleFileSource(t *testing.T) {
	// Create test PEM file
	tempDir := t.TempDir()
	testPemFile := filepath.Join(tempDir, "test.pem")
	
	// Copy a valid test certificate
	testCertContent := `-----BEGIN CERTIFICATE-----
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
	
	if err := os.WriteFile(testPemFile, []byte(testCertContent), 0644); err != nil {
		t.Fatalf("Failed to create test PEM file: %v", err)
	}

	tests := []struct {
		name     string
		source   string
		password string
		wantErr  bool
	}{
		{
			name:     "PEM file",
			source:   testPemFile,
			password: "",
			wantErr:  false,
		},
		{
			name:     "PEM file with .pem extension",
			source:   strings.Replace(testPemFile, "test.pem", "test2.pem", 1),
			password: "",
			wantErr:  true, // File doesn't exist
		},
		{
			name:     "JKS file placeholder",
			source:   "keystore.jks",
			password: "secret",
			wantErr:  false,
		},
		{
			name:     "PKCS12 file placeholder",
			source:   "keystore.p12",
			password: "secret",
			wantErr:  false,
		},
		{
			name:     "file without extension defaults to PEM",
			source:   strings.Replace(testPemFile, ".pem", "", 1),
			password: "",
			wantErr:  true, // File doesn't exist
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handleFileSource(tt.source, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("handleFileSource() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHandlePemFile(t *testing.T) {
	// Create test PEM file
	tempDir := t.TempDir()
	testPemFile := filepath.Join(tempDir, "test.pem")
	
	testCertContent := `-----BEGIN CERTIFICATE-----
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
	
	if err := os.WriteFile(testPemFile, []byte(testCertContent), 0644); err != nil {
		t.Fatalf("Failed to create test PEM file: %v", err)
	}

	tests := []struct {
		name     string
		filepath string
		wantErr  bool
		errContains string
	}{
		{
			name:     "valid PEM file",
			filepath: testPemFile,
			wantErr:  false,
		},
		{
			name:        "non-existent PEM file",
			filepath:    "/nonexistent/file.pem",
			wantErr:     true,
			errContains: "failed to read certificates from PEM file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handlePemFile(tt.filepath)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("handlePemFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("handlePemFile() error = %v, want containing %q", err, tt.errContains)
				}
			}
		})
	}
}

// Integration test for handleDomainSource would require network access
// For now, we'll test error handling with invalid domains
func TestHandleDomainSource_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		domain      string
		wantErr     bool
		errContains string
	}{
		{
			name:        "empty domain",
			domain:      "",
			wantErr:     true,
			errContains: "failed to retrieve certificates",
		},
		{
			name:        "invalid domain",
			domain:      "invalid-domain-12345.invalid",
			wantErr:     true,
			errContains: "failed to retrieve certificates",
		},
		{
			name:        "connection refused",
			domain:      "127.0.0.1:12345",
			wantErr:     true,
			errContains: "failed to retrieve certificates",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handleDomainSource(tt.domain)

			if (err != nil) != tt.wantErr {
				t.Errorf("handleDomainSource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("handleDomainSource() error = %v, want containing %q", err, tt.errContains)
				}
			}
		})
	}
}
