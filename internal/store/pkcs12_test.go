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

func TestPkcs12Handler_ReadCertificates_WithPassword(t *testing.T) {
	handler := NewPkcs12Handler()

	// Test with password-protected PKCS12 file
	testFile := filepath.Join("testdata", "test.p12")
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

func TestPkcs12Handler_ReadCertificates_NoPassword(t *testing.T) {
	handler := NewPkcs12Handler()

	// Test with no-password PKCS12 file
	testFile := filepath.Join("testdata", "test-nopass.p12")
	certificates, err := handler.ReadCertificates(testFile, "")

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

func TestPkcs12Handler_ReadCertificates_IncorrectPassword(t *testing.T) {
	handler := NewPkcs12Handler()

	testFile := filepath.Join("testdata", "test.p12")
	_, err := handler.ReadCertificates(testFile, "wrongpassword")

	if err == nil {
		t.Fatal("Expected error for incorrect password, got none")
	}

	// Check that error message mentions password
	errStr := err.Error()
	if !strings.Contains(errStr, "incorrect password") {
		t.Errorf("Expected error message to mention incorrect password, got: %s", errStr)
	}
}

func TestPkcs12Handler_ReadCertificates_FileNotFound(t *testing.T) {
	handler := NewPkcs12Handler()

	_, err := handler.ReadCertificates("nonexistent.p12", "password")

	if err == nil {
		t.Fatal("Expected error for non-existent file, got none")
	}

	// Check that error mentions the file
	errStr := err.Error()
	if !strings.Contains(errStr, "nonexistent.p12") {
		t.Errorf("Expected error message to mention file name, got: %s", errStr)
	}
}

func TestPkcs12Handler_ReadCertificates_InvalidFile(t *testing.T) {
	handler := NewPkcs12Handler()

	// Create a temporary invalid PKCS12 file
	tmpFile, err := os.CreateTemp("", "invalid*.p12")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	// Write invalid content
	_, err = tmpFile.WriteString("invalid pkcs12 content")
	if err != nil {
		t.Fatalf("Failed to write invalid content: %v", err)
	}
	_ = tmpFile.Close()

	_, err = handler.ReadCertificates(tmpFile.Name(), "password")

	if err == nil {
		t.Fatal("Expected error for invalid PKCS12 file, got none")
	}
}

func TestPkcs12Handler_AddCertificate_NewFile(t *testing.T) {
	handler := NewPkcs12Handler()

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "pkcs12-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Generate a test certificate
	cert := generateTestCertForPkcs12(t)

	// Add certificate to new PKCS12 file
	p12File := filepath.Join(tempDir, "test.p12")
	password := "testpass"

	err = handler.AddCertificate(p12File, cert, password)
	if err != nil {
		t.Fatalf("Failed to add certificate to new PKCS12 file: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(p12File); os.IsNotExist(err) {
		t.Fatal("PKCS12 file was not created")
	}

	// Read back the certificates to verify
	certs, err := handler.ReadCertificates(p12File, password)
	if err != nil {
		t.Fatalf("Failed to read certificates from PKCS12 file: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(certs))
	}

	// Verify certificate content matches
	if !cert.Equal(certs[0]) {
		t.Error("Certificate content does not match")
	}
}

func TestPkcs12Handler_AddCertificate_ExistingFile(t *testing.T) {
	handler := NewPkcs12Handler()

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "pkcs12-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	p12File := filepath.Join(tempDir, "test.p12")
	password := "testpass"

	// Add first certificate
	cert1 := generateTestCertForPkcs12(t)
	err = handler.AddCertificate(p12File, cert1, password)
	if err != nil {
		t.Fatalf("Failed to add first certificate: %v", err)
	}

	// Add second certificate to existing file
	cert2 := generateTestCertForPkcs12(t)
	err = handler.AddCertificate(p12File, cert2, password)
	if err != nil {
		t.Fatalf("Failed to add second certificate: %v", err)
	}

	// Verify both certificates are present
	certs, err := handler.ReadCertificates(p12File, password)
	if err != nil {
		t.Fatalf("Failed to read certificates: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("Expected 2 certificates, got %d", len(certs))
	}
}

func TestPkcs12Handler_AddCertificate_EmptyPassword(t *testing.T) {
	handler := NewPkcs12Handler()

	// Create temporary file path
	tempDir, err := os.MkdirTemp("", "pkcs12-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	p12File := filepath.Join(tempDir, "test.p12")
	cert := generateTestCertForPkcs12(t)

	// Try to add certificate with empty password
	err = handler.AddCertificate(p12File, cert, "")
	if err == nil {
		t.Fatal("Expected error for empty password, got none")
	}

	if !strings.Contains(err.Error(), "password required") {
		t.Errorf("Expected error message to mention password required, got: %s", err.Error())
	}
}

func TestPkcs12Handler_RemoveCertificate(t *testing.T) {
	handler := NewPkcs12Handler()
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.p12")
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

	// Verify file was removed (since no certificates remain)
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Error("Expected file to be removed when all certificates are removed")
	}

	// Test removing from non-existent file
	nonExistentFile := filepath.Join(tempDir, "nonexistent.p12")
	err = handler.RemoveCertificate(nonExistentFile, cert, password)
	if err == nil {
		t.Error("RemoveCertificate() should return error for non-existent file")
	}
}

func TestIsPkcs12PasswordError(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected bool
	}{
		{"nil error", "", false},
		{"password error", "incorrect password", true},
		{"decrypt error", "failed to decrypt", true},
		{"invalid error", "invalid p12", true},
		{"mac error", "mac verification failed", true},
		{"integrity error", "integrity check failed", true},
		{"other error", "file not found", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.errMsg != "" {
				err = &testError{msg: tt.errMsg}
			}

			result := isPkcs12PasswordError(err)
			if result != tt.expected {
				t.Errorf("isPkcs12PasswordError() = %v, expected %v for error: %s", result, tt.expected, tt.errMsg)
			}
		})
	}
}

// generateTestCertForPkcs12 creates a test certificate for PKCS12 testing
func generateTestCertForPkcs12(t *testing.T) *x509.Certificate {
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
