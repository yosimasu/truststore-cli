package store

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// PemHandler implements the Truststore interface for PEM files
type PemHandler struct{}

// NewPemHandler creates a new PEM file handler
func NewPemHandler() *PemHandler {
	return &PemHandler{}
}

// ReadCertificates reads and parses certificates from a PEM file
func (h *PemHandler) ReadCertificates(filepath string, password string) ([]*x509.Certificate, error) {
	// Read the PEM file
	pemData, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file %s: %w", filepath, err)
	}

	var certificates []*x509.Certificate
	var parseErrors []string

	// Parse all PEM blocks in the file
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}

		// Only process CERTIFICATE blocks
		if block.Type != "CERTIFICATE" {
			continue
		}

		// Parse the certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			parseErrors = append(parseErrors, err.Error())
			continue
		}

		certificates = append(certificates, cert)
	}

	// Check if we found any certificates
	if len(certificates) == 0 {
		if len(parseErrors) > 0 {
			return nil, fmt.Errorf("failed to parse certificate in PEM file %s: %s", filepath, parseErrors[0])
		}
		return nil, fmt.Errorf("no valid certificates found in PEM file %s", filepath)
	}

	return certificates, nil
}

// AddCertificate adds a certificate to the PEM file
func (h *PemHandler) AddCertificate(filepath string, cert *x509.Certificate, password string) error {
	if cert == nil {
		return fmt.Errorf("certificate cannot be nil")
	}

	// Check if certificate already exists in file
	if _, err := os.Stat(filepath); err == nil {
		exists, err := h.certificateExists(filepath, cert)
		if err != nil {
			return fmt.Errorf("failed to check if certificate exists: %w", err)
		}
		if exists {
			return fmt.Errorf("certificate already exists in %s", filepath)
		}
	}

	// Encode certificate as PEM
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	pemData := pem.EncodeToMemory(pemBlock)
	if pemData == nil {
		return fmt.Errorf("failed to encode certificate as PEM")
	}

	// Open file for appending (create if doesn't exist)
	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", filepath, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Log file close error but don't fail the operation
			_ = err
		}
	}()

	// Write PEM data to file
	_, err = file.Write(pemData)
	if err != nil {
		return fmt.Errorf("failed to write certificate to file %s: %w", filepath, err)
	}

	return nil
}

// certificateExists checks if a certificate already exists in the PEM file
func (h *PemHandler) certificateExists(filepath string, cert *x509.Certificate) (bool, error) {
	existingCerts, err := h.ReadCertificates(filepath, "")
	if err != nil {
		return false, err
	}

	// Compare with each existing certificate
	for _, existing := range existingCerts {
		if cert.Equal(existing) {
			return true, nil
		}
	}

	return false, nil
}

// RemoveCertificate removes a certificate from the PEM file
func (h *PemHandler) RemoveCertificate(filepath string, cert *x509.Certificate, password string) error {
	if cert == nil {
		return fmt.Errorf("certificate cannot be nil")
	}

	// Read existing certificates from file
	existingCerts, err := h.ReadCertificates(filepath, "")
	if err != nil {
		return fmt.Errorf("failed to read existing certificates: %w", err)
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
		return fmt.Errorf("certificate not found in %s", filepath)
	}

	// Write remaining certificates back to file
	return h.writeCertificatesToFile(filepath, remainingCerts)
}

// writeCertificatesToFile writes a slice of certificates to a PEM file, replacing existing content
func (h *PemHandler) writeCertificatesToFile(filepath string, certs []*x509.Certificate) error {
	// Create or truncate the file
	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", filepath, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Log file close error but don't fail the operation
			_ = err
		}
	}()

	// Write each certificate as a PEM block
	for _, cert := range certs {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		pemData := pem.EncodeToMemory(pemBlock)
		if pemData == nil {
			return fmt.Errorf("failed to encode certificate as PEM")
		}

		_, err = file.Write(pemData)
		if err != nil {
			return fmt.Errorf("failed to write certificate to file %s: %w", filepath, err)
		}
	}

	return nil
}
