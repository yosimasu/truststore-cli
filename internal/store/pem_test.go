package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

	err := handler.AddCertificate("test.pem", nil, "")

	if err == nil {
		t.Error("AddCertificate() should return error for unimplemented method")
	}

	if !strings.Contains(err.Error(), "AddCertificate not implemented") {
		t.Errorf("AddCertificate() error = %v, want containing 'AddCertificate not implemented'", err)
	}
}

func TestPemHandler_RemoveCertificate(t *testing.T) {
	handler := NewPemHandler()

	err := handler.RemoveCertificate("test.pem", nil, "")

	if err == nil {
		t.Error("RemoveCertificate() should return error for unimplemented method")
	}

	if !strings.Contains(err.Error(), "RemoveCertificate not implemented") {
		t.Errorf("RemoveCertificate() error = %v, want containing 'RemoveCertificate not implemented'", err)
	}
}

func TestPemHandler_ImplementsTruststoreInterface(t *testing.T) {
	var _ Truststore = (*PemHandler)(nil)
}
