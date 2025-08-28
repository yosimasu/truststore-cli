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

// AddCertificate adds a certificate to the PEM file (placeholder for future stories)
func (h *PemHandler) AddCertificate(filepath string, cert *x509.Certificate, password string) error {
	return fmt.Errorf("AddCertificate not implemented for PEM files - will be added in future stories")
}

// RemoveCertificate removes a certificate from the PEM file (placeholder for future stories)
func (h *PemHandler) RemoveCertificate(filepath string, cert *x509.Certificate, password string) error {
	return fmt.Errorf("RemoveCertificate not implemented for PEM files - will be added in future stories")
}