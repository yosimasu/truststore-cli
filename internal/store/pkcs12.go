package store

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
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

// AddCertificate adds a certificate to the PKCS12 file
func (h *Pkcs12Handler) AddCertificate(filepath string, cert *x509.Certificate, password string) error {
	if password == "" {
		return fmt.Errorf("password required for PKCS12 file operations")
	}

	var existingCerts []*x509.Certificate

	// Check if file exists and load existing certificates
	if _, err := os.Stat(filepath); !os.IsNotExist(err) {
		// File exists, load existing certificates
		pkcs12Data, err := os.ReadFile(filepath)
		if err != nil {
			return fmt.Errorf("failed to read PKCS12 file %s: %w", filepath, err)
		}

		// Try to decode existing PKCS12 data
		_, certificate, caCerts, err := pkcs12.DecodeChain(pkcs12Data, password)
		if err != nil {
			if isPkcs12PasswordError(err) {
				return fmt.Errorf("incorrect password for PKCS12 file %s: provide the correct password", filepath)
			}
			return fmt.Errorf("failed to decode PKCS12 file %s: %w", filepath, err)
		}

		// Collect existing certificates
		if certificate != nil {
			existingCerts = append(existingCerts, certificate)
		}
		if caCerts != nil {
			existingCerts = append(existingCerts, caCerts...)
		}
	}

	// Add the new certificate to the collection
	existingCerts = append(existingCerts, cert)

	// Create new PKCS12 data with all certificates
	// Use the last certificate as the main certificate, others as CA certs
	var mainCert *x509.Certificate
	var caCerts []*x509.Certificate

	if len(existingCerts) > 0 {
		mainCert = existingCerts[len(existingCerts)-1]
		if len(existingCerts) > 1 {
			caCerts = existingCerts[:len(existingCerts)-1]
		}
	}

	// For truststore-only operations, we need to create a dummy private key
	// since PKCS12 format requires a private key in the structure
	dummyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate dummy private key: %w", err)
	}

	// Create PKCS12 data with dummy key and certificates
	pkcs12Data, err := pkcs12.Legacy.Encode(dummyKey, mainCert, caCerts, password)
	if err != nil {
		return fmt.Errorf("failed to encode PKCS12 data: %w", err)
	}

	// Write to file
	err = os.WriteFile(filepath, pkcs12Data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write PKCS12 file %s: %w", filepath, err)
	}

	return nil
}

// RemoveCertificate removes a certificate from the PKCS12 file
func (h *Pkcs12Handler) RemoveCertificate(filepath string, cert *x509.Certificate, password string) error {
	if password == "" {
		return fmt.Errorf("password required for PKCS12 file operations")
	}

	if cert == nil {
		return fmt.Errorf("certificate cannot be nil")
	}

	// Read and decode existing PKCS12 data
	pkcs12Data, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read PKCS12 file %s: %w", filepath, err)
	}

	// Decode the PKCS12 data
	privateKey, certificate, caCerts, err := pkcs12.DecodeChain(pkcs12Data, password)
	if err != nil {
		if isPkcs12PasswordError(err) {
			return fmt.Errorf("incorrect password for PKCS12 file %s: provide the correct password", filepath)
		}
		return fmt.Errorf("failed to decode PKCS12 file %s: %w", filepath, err)
	}

	// Collect all existing certificates
	var existingCerts []*x509.Certificate
	if certificate != nil {
		existingCerts = append(existingCerts, certificate)
	}
	if caCerts != nil {
		existingCerts = append(existingCerts, caCerts...)
	}

	// Find and remove the matching certificate
	var remainingCerts []*x509.Certificate
	found := false

	for _, existing := range existingCerts {
		if cert.Equal(existing) {
			found = true
			// Skip this certificate (don't add to remaining)
		} else {
			remainingCerts = append(remainingCerts, existing)
		}
	}

	if !found {
		return fmt.Errorf("certificate not found in PKCS12 file %s", filepath)
	}

	// If no certificates remain, remove the file
	if len(remainingCerts) == 0 {
		err = os.Remove(filepath)
		if err != nil {
			return fmt.Errorf("failed to remove empty PKCS12 file %s: %w", filepath, err)
		}
		return nil
	}

	// Recreate PKCS12 with remaining certificates
	var mainCert *x509.Certificate
	var newCaCerts []*x509.Certificate

	if len(remainingCerts) > 0 {
		// Use the first certificate as main, others as CA certs
		mainCert = remainingCerts[0]
		if len(remainingCerts) > 1 {
			newCaCerts = remainingCerts[1:]
		}
	}

	// Use the original private key if available, otherwise generate dummy key
	if privateKey == nil {
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate dummy private key: %w", err)
		}
	}

	// Create new PKCS12 data
	newPkcs12Data, err := pkcs12.Legacy.Encode(privateKey, mainCert, newCaCerts, password)
	if err != nil {
		return fmt.Errorf("failed to encode PKCS12 data: %w", err)
	}

	// Write to file
	err = os.WriteFile(filepath, newPkcs12Data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write PKCS12 file %s: %w", filepath, err)
	}

	return nil
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
