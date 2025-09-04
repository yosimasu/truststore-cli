package store

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJksHandler_ReadCertificates_Success(t *testing.T) {
	handler := NewJksHandler()

	// Test with password-protected JKS file
	testFile := filepath.Join("testdata", "test.jks")
	certificates, err := handler.ReadCertificates(testFile, "testpass")

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(certificates) == 0 {
		t.Fatal("Expected at least one certificate, got none")
	}

	// Verify certificate properties
	cert := certificates[0]
	if cert.Subject.CommonName != "test-cert" {
		t.Errorf("Expected CN=test-cert, got %s", cert.Subject.CommonName)
	}
}

func TestJksHandler_ReadCertificates_IncorrectPassword(t *testing.T) {
	handler := NewJksHandler()

	testFile := filepath.Join("testdata", "test.jks")
	_, err := handler.ReadCertificates(testFile, "wrongpassword")

	if err == nil {
		t.Fatal("Expected error for incorrect password, got none")
	}

	// Check that error message mentions password or includes our custom message
	errStr := err.Error()
	if !strings.Contains(errStr, "incorrect password") && !strings.Contains(errStr, "provide the correct password") {
		t.Errorf("Expected error message to mention incorrect password, got: %s", errStr)
	}
}

func TestJksHandler_ReadCertificates_FileNotFound(t *testing.T) {
	handler := NewJksHandler()

	_, err := handler.ReadCertificates("nonexistent.jks", "password")

	if err == nil {
		t.Fatal("Expected error for non-existent file, got none")
	}

	// Check that error mentions the file
	errStr := err.Error()
	if !strings.Contains(errStr, "nonexistent.jks") {
		t.Errorf("Expected error message to mention file name, got: %s", errStr)
	}
}

func TestJksHandler_ReadCertificates_InvalidFile(t *testing.T) {
	handler := NewJksHandler()

	// Create a temporary invalid JKS file
	tmpFile, err := os.CreateTemp("", "invalid*.jks")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	// Write invalid content
	_, err = tmpFile.WriteString("invalid jks content")
	if err != nil {
		t.Fatalf("Failed to write invalid content: %v", err)
	}
	_ = tmpFile.Close()

	_, err = handler.ReadCertificates(tmpFile.Name(), "password")

	if err == nil {
		t.Fatal("Expected error for invalid JKS file, got none")
	}
}

// Old test removed - AddCertificate is now implemented

func TestJksHandler_RemoveCertificate(t *testing.T) {
	handler := NewJksHandler()
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.jks")
	password := "testpassword"

	// Test with nil certificate
	err := handler.RemoveCertificate(testFile, nil, password)
	if err == nil || !strings.Contains(err.Error(), "certificate cannot be nil") {
		t.Errorf("RemoveCertificate() should return error for nil certificate, got: %v", err)
	}

	// Test with empty password
	cert := createTestCertificate(t)
	err = handler.RemoveCertificate(testFile, cert, "")
	if err == nil || !strings.Contains(err.Error(), "password required") {
		t.Errorf("RemoveCertificate() should return error for empty password, got: %v", err)
	}

	// Add a certificate first
	err = handler.AddCertificate(testFile, cert, password)
	if err != nil {
		t.Fatalf("Failed to add certificate: %v", err)
	}

	// Test removing the certificate
	err = handler.RemoveCertificate(testFile, cert, password)
	if err != nil {
		t.Errorf("RemoveCertificate() failed: %v", err)
	}

	// Verify certificate was removed by reading the file
	certs, err := handler.ReadCertificates(testFile, password)
	if err != nil {
		// It's okay if there are no certificates found after removal
		if !strings.Contains(err.Error(), "no certificates found") {
			t.Fatalf("Failed to read certificates: %v", err)
		}
	} else if len(certs) != 0 {
		t.Errorf("Expected 0 certificates after removal, got %d", len(certs))
	}

	// Test removing from non-existent file
	nonExistentFile := filepath.Join(tempDir, "nonexistent.jks")
	err = handler.RemoveCertificate(nonExistentFile, cert, password)
	if err == nil {
		t.Error("RemoveCertificate() should return error for non-existent file")
	}
}

func TestIsPasswordError(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected bool
	}{
		{"nil error", "", false},
		{"password error", "incorrect password", true},
		{"decrypt error", "failed to decrypt", true},
		{"invalid error", "invalid keystore", true},
		{"authentication error", "authentication failed", true},
		{"other error", "file not found", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.errMsg != "" {
				err = &testError{msg: tt.errMsg}
			}

			result := isPasswordError(err)
			if result != tt.expected {
				t.Errorf("isPasswordError() = %v, expected %v for error: %s", result, tt.expected, tt.errMsg)
			}
		})
	}
}

// testError is a simple error implementation for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestJksHandler_AddCertificate_NewFile(t *testing.T) {
	handler := NewJksHandler()

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "jks-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Generate a test certificate
	cert := generateTestCert(t)

	// Add certificate to new JKS file
	jksFile := filepath.Join(tempDir, "test.jks")
	password := "testpass"

	err = handler.AddCertificate(jksFile, cert, password)
	if err != nil {
		t.Fatalf("Failed to add certificate to new JKS file: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(jksFile); os.IsNotExist(err) {
		t.Fatal("JKS file was not created")
	}

	// Read back the certificates to verify
	certs, err := handler.ReadCertificates(jksFile, password)
	if err != nil {
		t.Fatalf("Failed to read certificates from JKS file: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(certs))
	}

	// Verify certificate content matches
	if !cert.Equal(certs[0]) {
		t.Error("Certificate content does not match")
	}
}

func TestJksHandler_AddCertificate_ExistingFile(t *testing.T) {
	handler := NewJksHandler()

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "jks-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	jksFile := filepath.Join(tempDir, "test.jks")
	password := "testpass"

	// Add first certificate
	cert1 := generateTestCert(t)
	err = handler.AddCertificate(jksFile, cert1, password)
	if err != nil {
		t.Fatalf("Failed to add first certificate: %v", err)
	}

	// Add second certificate to existing file
	cert2 := generateTestCert(t)
	err = handler.AddCertificate(jksFile, cert2, password)
	if err != nil {
		t.Fatalf("Failed to add second certificate: %v", err)
	}

	// Verify both certificates are present
	certs, err := handler.ReadCertificates(jksFile, password)
	if err != nil {
		t.Fatalf("Failed to read certificates: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("Expected 2 certificates, got %d", len(certs))
	}
}

func TestJksHandler_AddCertificate_IncorrectPassword(t *testing.T) {
	handler := NewJksHandler()

	// Use existing test file
	testFile := filepath.Join("testdata", "test.jks")
	cert := generateTestCert(t)

	// Try to add certificate with wrong password
	err := handler.AddCertificate(testFile, cert, "wrongpassword")
	if err == nil {
		t.Fatal("Expected error for incorrect password, got none")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "incorrect password") {
		t.Errorf("Expected error message to mention incorrect password, got: %s", errStr)
	}
}

func TestJksHandler_AddCertificate_EmptyPassword(t *testing.T) {
	handler := NewJksHandler()

	// Create temporary file path
	tempDir, err := os.MkdirTemp("", "jks-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	jksFile := filepath.Join(tempDir, "test.jks")
	cert := generateTestCert(t)

	// Try to add certificate with empty password
	err = handler.AddCertificate(jksFile, cert, "")
	if err == nil {
		t.Fatal("Expected error for empty password, got none")
	}

	if !strings.Contains(err.Error(), "password required") {
		t.Errorf("Expected error message to mention password required, got: %s", err.Error())
	}
}

func TestGenerateCertificateAlias(t *testing.T) {
	// Generate multiple aliases
	alias1 := generateCertificateAlias()
	time.Sleep(time.Nanosecond) // Ensure different timestamp
	alias2 := generateCertificateAlias()

	// Verify format
	if !strings.HasPrefix(alias1, "cert-") {
		t.Errorf("Expected alias to start with 'cert-', got: %s", alias1)
	}

	// Verify uniqueness (should be different due to timestamp)
	if alias1 == alias2 {
		t.Error("Expected aliases to be unique")
	}
}

// generateTestCert creates a test certificate for testing
func generateTestCert(t *testing.T) *x509.Certificate {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    "test.example.com",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: nil,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}
