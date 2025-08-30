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

func TestNewPemHandler(t *testing.T) {
	handler := NewPemHandler()
	if handler == nil {
		t.Fatal("NewPemHandler() returned nil")
	}
}

func TestPemHandler_ReadCertificates(t *testing.T) {
	handler := NewPemHandler()

	tests := []struct {
		name          string
		filename      string
		password      string
		expectedCount int
		wantErr       bool
		errContains   string
	}{
		{
			name:          "single certificate",
			filename:      "single-cert.pem",
			password:      "",
			expectedCount: 1,
			wantErr:       false,
		},
		{
			name:          "multiple certificates",
			filename:      "multi-cert.pem",
			password:      "",
			expectedCount: 2,
			wantErr:       false,
		},
		{
			name:        "invalid PEM format (no blocks)",
			filename:    "invalid.pem",
			password:    "",
			wantErr:     true,
			errContains: "no valid certificates found",
		},
		{
			name:        "invalid certificate data",
			filename:    "invalid-cert-data.pem",
			password:    "",
			wantErr:     true,
			errContains: "failed to parse certificate",
		},
		{
			name:        "no certificates in file",
			filename:    "no-certs.pem",
			password:    "",
			wantErr:     true,
			errContains: "no valid certificates found",
		},
		{
			name:        "non-existent file",
			filename:    "nonexistent.pem",
			password:    "",
			wantErr:     true,
			errContains: "failed to read PEM file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filepath := filepath.Join("testdata", tt.filename)

			certificates, err := handler.ReadCertificates(filepath, tt.password)

			if (err != nil) != tt.wantErr {
				t.Errorf("ReadCertificates() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ReadCertificates() error = %v, want containing %q", err, tt.errContains)
				}
			}

			if !tt.wantErr {
				if len(certificates) != tt.expectedCount {
					t.Errorf("ReadCertificates() returned %d certificates, want %d", len(certificates), tt.expectedCount)
				}

				// Verify certificate validity
				for i, cert := range certificates {
					if cert.Subject.CommonName == "" && len(cert.Subject.Organization) == 0 {
						t.Errorf("Certificate %d has empty Subject", i)
					}
					if cert.Issuer.CommonName == "" && len(cert.Issuer.Organization) == 0 {
						t.Errorf("Certificate %d has empty Issuer", i)
					}
					if cert.SerialNumber == nil {
						t.Errorf("Certificate %d has nil SerialNumber", i)
					}
				}
			}
		})
	}
}

func TestPemHandler_ReadCertificates_FilePermissions(t *testing.T) {
	handler := NewPemHandler()

	// Create a temporary file with restricted permissions
	tempDir := t.TempDir()
	restrictedFile := filepath.Join(tempDir, "restricted.pem")

	// Create the file first
	if err := os.WriteFile(restrictedFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Make it unreadable
	if err := os.Chmod(restrictedFile, 0000); err != nil {
		t.Fatalf("Failed to change file permissions: %v", err)
	}

	// Restore permissions for cleanup
	defer func() {
		os.Chmod(restrictedFile, 0644)
	}()

	_, err := handler.ReadCertificates(restrictedFile, "")

	if err == nil {
		t.Error("ReadCertificates() should fail with permission denied error")
	}

	if !strings.Contains(err.Error(), "failed to read PEM file") {
		t.Errorf("ReadCertificates() error = %v, want containing 'failed to read PEM file'", err)
	}
}

func TestPemHandler_ReadCertificates_EmptyFile(t *testing.T) {
	handler := NewPemHandler()

	// Create a temporary empty file
	tempDir := t.TempDir()
	emptyFile := filepath.Join(tempDir, "empty.pem")

	if err := os.WriteFile(emptyFile, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to create empty test file: %v", err)
	}

	_, err := handler.ReadCertificates(emptyFile, "")

	if err == nil {
		t.Error("ReadCertificates() should fail with empty file")
	}

	if !strings.Contains(err.Error(), "no valid certificates found") {
		t.Errorf("ReadCertificates() error = %v, want containing 'no valid certificates found'", err)
	}
}

func TestPemHandler_AddCertificate(t *testing.T) {
	handler := NewPemHandler()

	// Test nil certificate
	err := handler.AddCertificate("test.pem", nil, "")
	if err == nil {
		t.Error("AddCertificate() should return error for nil certificate")
	}
	if !strings.Contains(err.Error(), "certificate cannot be nil") {
		t.Errorf("AddCertificate() error = %v, want containing 'certificate cannot be nil'", err)
	}
}

func TestPemHandler_AddCertificateToNewFile(t *testing.T) {
	handler := NewPemHandler()

	// Create test certificate
	testCert := createTestCertificate(t)

	// Create temporary directory
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "new.pem")

	// Add certificate to new file
	err := handler.AddCertificate(testFile, testCert, "")
	if err != nil {
		t.Fatalf("AddCertificate() failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(testFile); err != nil {
		t.Fatalf("File was not created: %v", err)
	}

	// Read back and verify certificate
	certs, err := handler.ReadCertificates(testFile, "")
	if err != nil {
		t.Fatalf("Failed to read back certificate: %v", err)
	}

	if len(certs) != 1 {
		t.Fatalf("Expected 1 certificate, got %d", len(certs))
	}

	if !certs[0].Equal(testCert) {
		t.Error("Read certificate does not match original")
	}
}

func TestPemHandler_AddCertificateToExistingFile(t *testing.T) {
	handler := NewPemHandler()

	// Create first test certificate
	testCert1 := createTestCertificate(t)

	// Create second test certificate (different serial number)
	testCert2 := createTestCertificate(t)
	testCert2.SerialNumber = big.NewInt(2)

	// Create temporary directory and file with first certificate
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "existing.pem")

	// Add first certificate
	err := handler.AddCertificate(testFile, testCert1, "")
	if err != nil {
		t.Fatalf("AddCertificate() failed for first cert: %v", err)
	}

	// Add second certificate
	err = handler.AddCertificate(testFile, testCert2, "")
	if err != nil {
		t.Fatalf("AddCertificate() failed for second cert: %v", err)
	}

	// Read back and verify both certificates
	certs, err := handler.ReadCertificates(testFile, "")
	if err != nil {
		t.Fatalf("Failed to read back certificates: %v", err)
	}

	if len(certs) != 2 {
		t.Fatalf("Expected 2 certificates, got %d", len(certs))
	}

	// Verify certificates (order may vary)
	found1, found2 := false, false
	for _, cert := range certs {
		if cert.Equal(testCert1) {
			found1 = true
		} else if cert.Equal(testCert2) {
			found2 = true
		}
	}

	if !found1 {
		t.Error("First certificate not found in file")
	}
	if !found2 {
		t.Error("Second certificate not found in file")
	}
}

func TestPemHandler_AddDuplicateCertificate(t *testing.T) {
	handler := NewPemHandler()

	// Create test certificate
	testCert := createTestCertificate(t)

	// Create temporary directory and file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "duplicate.pem")

	// Add certificate first time
	err := handler.AddCertificate(testFile, testCert, "")
	if err != nil {
		t.Fatalf("AddCertificate() failed for first add: %v", err)
	}

	// Try to add same certificate again
	err = handler.AddCertificate(testFile, testCert, "")
	if err == nil {
		t.Error("AddCertificate() should fail for duplicate certificate")
	}
	if !strings.Contains(err.Error(), "certificate already exists") {
		t.Errorf("AddCertificate() error = %v, want containing 'certificate already exists'", err)
	}
}

func TestPemHandler_CertificateExists(t *testing.T) {
	handler := NewPemHandler()

	// Create test certificates
	testCert1 := createTestCertificate(t)
	testCert2 := createTestCertificate(t)
	testCert2.SerialNumber = big.NewInt(2)

	// Create temporary directory and file with first certificate
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "exists.pem")

	// Add first certificate
	err := handler.AddCertificate(testFile, testCert1, "")
	if err != nil {
		t.Fatalf("AddCertificate() failed: %v", err)
	}

	// Test certificate exists
	exists, err := handler.certificateExists(testFile, testCert1)
	if err != nil {
		t.Fatalf("certificateExists() failed: %v", err)
	}
	if !exists {
		t.Error("certificateExists() should return true for existing certificate")
	}

	// Test certificate doesn't exist
	exists, err = handler.certificateExists(testFile, testCert2)
	if err != nil {
		t.Fatalf("certificateExists() failed: %v", err)
	}
	if exists {
		t.Error("certificateExists() should return false for non-existing certificate")
	}

	// Test with non-existent file
	nonExistentFile := filepath.Join(tempDir, "nonexistent.pem")
	exists, err = handler.certificateExists(nonExistentFile, testCert1)
	if err == nil {
		t.Error("certificateExists() should fail for non-existent file")
	}
}

// createTestCertificate creates a valid test certificate for testing
func createTestCertificate(t *testing.T) *x509.Certificate {
	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test Certificate", // Self-signed
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Parse the created certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse created certificate: %v", err)
	}

	return cert
}

func TestPemHandler_RemoveCertificate(t *testing.T) {
	handler := NewPemHandler()
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.pem")

	// Test with nil certificate
	err := handler.RemoveCertificate(testFile, nil, "")
	if err == nil || !strings.Contains(err.Error(), "certificate cannot be nil") {
		t.Errorf("RemoveCertificate() should return error for nil certificate, got: %v", err)
	}

	// Create test certificates
	cert1 := createTestCertificate(t)
	cert2 := createTestCertificate(t)
	cert3 := createTestCertificate(t)

	// Add certificates to the file
	err = handler.AddCertificate(testFile, cert1, "")
	if err != nil {
		t.Fatalf("Failed to add cert1: %v", err)
	}
	err = handler.AddCertificate(testFile, cert2, "")
	if err != nil {
		t.Fatalf("Failed to add cert2: %v", err)
	}
	err = handler.AddCertificate(testFile, cert3, "")
	if err != nil {
		t.Fatalf("Failed to add cert3: %v", err)
	}

	// Test removing a certificate that exists
	err = handler.RemoveCertificate(testFile, cert2, "")
	if err != nil {
		t.Errorf("RemoveCertificate() failed: %v", err)
	}

	// Verify certificate was removed
	certs, err := handler.ReadCertificates(testFile, "")
	if err != nil {
		t.Fatalf("Failed to read certificates: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("Expected 2 certificates after removal, got %d", len(certs))
	}

	// Verify cert2 is not in the remaining certificates
	for _, cert := range certs {
		if cert.Equal(cert2) {
			t.Error("Certificate should have been removed but was found")
		}
	}

	// Test removing a certificate that doesn't exist
	err = handler.RemoveCertificate(testFile, cert2, "")
	if err == nil || !strings.Contains(err.Error(), "certificate not found") {
		t.Errorf("RemoveCertificate() should return error for non-existent certificate, got: %v", err)
	}

	// Test removing from non-existent file
	nonExistentFile := filepath.Join(tempDir, "nonexistent.pem")
	err = handler.RemoveCertificate(nonExistentFile, cert1, "")
	if err == nil {
		t.Error("RemoveCertificate() should return error for non-existent file")
	}
}

func TestPemHandler_ImplementsTruststoreInterface(t *testing.T) {
	var _ Truststore = (*PemHandler)(nil)
}
