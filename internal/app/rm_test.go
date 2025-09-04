package app

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestNewRmCommand(t *testing.T) {
	cmd := NewRmCommand()

	if cmd.Name() != "rm" {
		t.Errorf("Expected command name to be 'rm', got '%s'", cmd.Name())
	}

	if cmd.Short == "" {
		t.Error("Expected command to have a short description")
	}

	if cmd.Long == "" {
		t.Error("Expected command to have a long description")
	}
}

func TestRmCommandFlags(t *testing.T) {
	cmd := NewRmCommand()

	// Test target flag
	targetFlag := cmd.Flags().Lookup("target")
	if targetFlag == nil {
		t.Error("Expected 'target' flag to be defined")
	}

	// Test password flag
	passwordFlag := cmd.Flags().Lookup("password")
	if passwordFlag == nil {
		t.Error("Expected 'password' flag to be defined")
	}

	// Test target-password flag
	targetPasswordFlag := cmd.Flags().Lookup("target-password")
	if targetPasswordFlag == nil {
		t.Error("Expected 'target-password' flag to be defined")
	}
}

func TestIsRmDomainSource(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected bool
	}{
		{
			name:     "domain without port",
			source:   "example.com",
			expected: true,
		},
		{
			name:     "domain with port",
			source:   "example.com:443",
			expected: true,
		},
		{
			name:     "file with .pem extension",
			source:   "cert.pem",
			expected: false,
		},
		{
			name:     "file with .crt extension",
			source:   "cert.crt",
			expected: false,
		},
		{
			name:     "file with .jks extension",
			source:   "keystore.jks",
			expected: false,
		},
		{
			name:     "file with .p12 extension",
			source:   "keystore.p12",
			expected: false,
		},
		{
			name:     "absolute file path",
			source:   "/path/to/cert.pem",
			expected: false,
		},
		{
			name:     "relative file path",
			source:   "./certs/cert.pem",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRmDomainSource(tt.source)
			if result != tt.expected {
				t.Errorf("isRmDomainSource(%s) = %v; expected %v", tt.source, result, tt.expected)
			}
		})
	}
}

func TestValidateTargetFileExists(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Test with empty path
	err := validateTargetFileExists("")
	if err == nil {
		t.Error("Expected error for empty target path")
	}

	// Test with non-existent file
	nonExistentFile := filepath.Join(tempDir, "nonexistent.pem")
	err = validateTargetFileExists(nonExistentFile)
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	// Create a test file
	testFile := filepath.Join(tempDir, "test.pem")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Test with existing file
	err = validateTargetFileExists(testFile)
	if err != nil {
		t.Errorf("Expected no error for existing file, got: %v", err)
	}

	// Create a directory to test non-regular file
	testDir := filepath.Join(tempDir, "testdir")
	err = os.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Test with directory (should fail)
	err = validateTargetFileExists(testDir)
	if err == nil {
		t.Error("Expected error for directory path")
	}
}

func TestCertificatesEqual(t *testing.T) {
	// Create two identical certificate structures with proper raw bytes
	rawBytes := []byte{0x30, 0x82, 0x01, 0x02} // Minimal DER encoding

	cert1 := &x509.Certificate{
		Raw:          rawBytes,
		SerialNumber: big.NewInt(123),
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		Subject: pkix.Name{
			CommonName: "Test Subject",
		},
	}

	cert2 := &x509.Certificate{
		Raw:          rawBytes, // Same raw bytes
		SerialNumber: big.NewInt(123),
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		Subject: pkix.Name{
			CommonName: "Test Subject",
		},
	}

	// Test equal certificates (same raw content)
	if !certificatesEqual(cert1, cert2) {
		t.Error("Expected certificates with same raw content to be equal")
	}

	// Create a certificate with different raw bytes
	cert3 := &x509.Certificate{
		Raw:          []byte{0x30, 0x82, 0x01, 0x03}, // Different raw bytes
		SerialNumber: big.NewInt(123),
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		Subject: pkix.Name{
			CommonName: "Test Subject",
		},
	}

	// Test unequal certificates (different raw content)
	if certificatesEqual(cert1, cert3) {
		t.Error("Expected certificates with different raw content to be unequal")
	}
}

func TestPrintRemovalSuccessMessage(t *testing.T) {
	// This test mainly ensures the function doesn't panic
	// In a real test, you might want to capture stdout to verify the output
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(123),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
	}

	// Test with different file types
	testCases := []string{
		"test.pem",
		"test.jks",
		"test.p12",
	}

	for _, target := range testCases {
		// This should not panic
		printRemovalSuccessMessage(target, cert)
	}
}
