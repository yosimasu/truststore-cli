package store

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// Pkcs12Handler implements the Truststore interface for PKCS12 files
type Pkcs12Handler struct{}

// NewPkcs12Handler creates a new PKCS12 file handler
func NewPkcs12Handler() *Pkcs12Handler {
	return &Pkcs12Handler{}
}

// ReadCertificates reads and parses certificates from a PKCS12 file
func (h *Pkcs12Handler) ReadCertificates(filepath string, password string) ([]*x509.Certificate, error) {
	// Read the PKCS12 file
	pkcs12Data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read PKCS12 file %s: %w", filepath, err)
	}

	// Handle empty password case
	var passwordBytes []byte
	if password != "" {
		passwordBytes = []byte(password)
	}

	// Parse the PKCS12 data
	privateKey, certificate, caCerts, err := pkcs12.DecodeChain(pkcs12Data, string(passwordBytes))
	if err != nil {
		// Handle incorrect password error specifically
		if isPkcs12PasswordError(err) {
			return nil, fmt.Errorf("incorrect password for PKCS12 file %s: provide the correct password using --password flag", filepath)
		}
		return nil, fmt.Errorf("failed to parse PKCS12 file %s: %w", filepath, err)
	}

	var certificates []*x509.Certificate

	// Add the main certificate if present
	if certificate != nil {
		certificates = append(certificates, certificate)
	}

	// Add CA certificates from the chain
	if caCerts != nil {
		certificates = append(certificates, caCerts...)
	}

	// Verify we have at least certificates (we don't need private key for listing)
	_ = privateKey // We don't use the private key for certificate listing

	// Check if we found any certificates
	if len(certificates) == 0 {
		return nil, fmt.Errorf("no certificates found in PKCS12 file %s", filepath)
	}

	return certificates, nil
}

// AddCertificate adds a certificate to the PKCS12 file (placeholder for future stories)
func (h *Pkcs12Handler) AddCertificate(filepath string, cert *x509.Certificate, password string) error {
	return fmt.Errorf("AddCertificate not implemented for PKCS12 files - will be added in future stories")
}

// RemoveCertificate removes a certificate from the PKCS12 file (placeholder for future stories)
func (h *Pkcs12Handler) RemoveCertificate(filepath string, cert *x509.Certificate, password string) error {
	return fmt.Errorf("RemoveCertificate not implemented for PKCS12 files - will be added in future stories")
}

// isPkcs12PasswordError checks if the error is related to incorrect password
func isPkcs12PasswordError(err error) bool {
	if err == nil {
		return false
	}
	// The PKCS12 library returns various errors for password issues
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "password") ||
		strings.Contains(errStr, "incorrect") ||
		strings.Contains(errStr, "decrypt") ||
		strings.Contains(errStr, "invalid") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "mac") ||
		strings.Contains(errStr, "integrity")
}
