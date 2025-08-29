package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	defer os.Remove(tmpFile.Name())

	// Write invalid content
	_, err = tmpFile.WriteString("invalid jks content")
	if err != nil {
		t.Fatalf("Failed to write invalid content: %v", err)
	}
	tmpFile.Close()

	_, err = handler.ReadCertificates(tmpFile.Name(), "password")

	if err == nil {
		t.Fatal("Expected error for invalid JKS file, got none")
	}
}

func TestJksHandler_AddCertificate_NotImplemented(t *testing.T) {
	handler := NewJksHandler()

	err := handler.AddCertificate("test.jks", nil, "password")

	if err == nil {
		t.Fatal("Expected not implemented error, got none")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "not implemented") {
		t.Errorf("Expected 'not implemented' in error message, got: %s", errStr)
	}
}

func TestJksHandler_RemoveCertificate_NotImplemented(t *testing.T) {
	handler := NewJksHandler()

	err := handler.RemoveCertificate("test.jks", nil, "password")

	if err == nil {
		t.Fatal("Expected not implemented error, got none")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "not implemented") {
		t.Errorf("Expected 'not implemented' in error message, got: %s", errStr)
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
