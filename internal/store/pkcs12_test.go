package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	defer os.Remove(tmpFile.Name())

	// Write invalid content
	_, err = tmpFile.WriteString("invalid pkcs12 content")
	if err != nil {
		t.Fatalf("Failed to write invalid content: %v", err)
	}
	tmpFile.Close()

	_, err = handler.ReadCertificates(tmpFile.Name(), "password")

	if err == nil {
		t.Fatal("Expected error for invalid PKCS12 file, got none")
	}
}

func TestPkcs12Handler_AddCertificate_NotImplemented(t *testing.T) {
	handler := NewPkcs12Handler()

	err := handler.AddCertificate("test.p12", nil, "password")

	if err == nil {
		t.Fatal("Expected not implemented error, got none")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "not implemented") {
		t.Errorf("Expected 'not implemented' in error message, got: %s", errStr)
	}
}

func TestPkcs12Handler_RemoveCertificate_NotImplemented(t *testing.T) {
	handler := NewPkcs12Handler()

	err := handler.RemoveCertificate("test.p12", nil, "password")

	if err == nil {
		t.Fatal("Expected not implemented error, got none")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "not implemented") {
		t.Errorf("Expected 'not implemented' in error message, got: %s", errStr)
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
