package store

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

// JksHandler implements the Truststore interface for JKS files
type JksHandler struct{}

// NewJksHandler creates a new JKS file handler
func NewJksHandler() *JksHandler {
	return &JksHandler{}
}

// ReadCertificates reads and parses certificates from a JKS file
func (h *JksHandler) ReadCertificates(filepath string, password string) ([]*x509.Certificate, error) {
	// Open the JKS file
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open JKS file %s: %w", filepath, err)
	}
	defer file.Close()

	// Create keystore and load from file
	ks := keystore.New()
	err = ks.Load(file, []byte(password))
	if err != nil {
		// Handle incorrect password error specifically
		if isPasswordError(err) {
			return nil, fmt.Errorf("incorrect password for JKS file %s: provide the correct password using --password flag", filepath)
		}
		return nil, fmt.Errorf("failed to parse JKS file %s: %w", filepath, err)
	}

	var certificates []*x509.Certificate

	// Extract certificates from all entries
	for _, alias := range ks.Aliases() {
		if ks.IsPrivateKeyEntry(alias) {
			// Get private key entry which contains the certificate chain
			privateKeyEntry, err := ks.GetPrivateKeyEntry(alias, []byte(password))
			if err != nil {
				continue // Skip entries we can't read
			}

			// Add certificate chain - parse raw bytes to x509.Certificate
			for _, cert := range privateKeyEntry.CertificateChain {
				parsedCert, err := x509.ParseCertificate(cert.Content)
				if err != nil {
					continue // Skip certificates we can't parse
				}
				certificates = append(certificates, parsedCert)
			}
		} else if ks.IsTrustedCertificateEntry(alias) {
			// Get trusted certificate entry
			trustedCertEntry, err := ks.GetTrustedCertificateEntry(alias)
			if err != nil {
				continue // Skip entries we can't read
			}

			// Parse raw certificate bytes to x509.Certificate
			parsedCert, err := x509.ParseCertificate(trustedCertEntry.Certificate.Content)
			if err != nil {
				continue // Skip certificates we can't parse
			}
			certificates = append(certificates, parsedCert)
		}
	}

	// Check if we found any certificates
	if len(certificates) == 0 {
		return nil, fmt.Errorf("no certificates found in JKS file %s", filepath)
	}

	return certificates, nil
}

// AddCertificate adds a certificate to the JKS file (placeholder for future stories)
func (h *JksHandler) AddCertificate(filepath string, cert *x509.Certificate, password string) error {
	return fmt.Errorf("AddCertificate not implemented for JKS files - will be added in future stories")
}

// RemoveCertificate removes a certificate from the JKS file (placeholder for future stories)
func (h *JksHandler) RemoveCertificate(filepath string, cert *x509.Certificate, password string) error {
	return fmt.Errorf("RemoveCertificate not implemented for JKS files - will be added in future stories")
}

// isPasswordError checks if the error is related to incorrect password
func isPasswordError(err error) bool {
	if err == nil {
		return false
	}
	// The keystore library returns various errors for password issues
	errStr := err.Error()
	// Be more specific about password errors to avoid false positives
	errStrLower := strings.ToLower(errStr)
	return strings.Contains(errStrLower, "password") ||
		strings.Contains(errStrLower, "authentication") ||
		strings.Contains(errStrLower, "mac verify") ||
		strings.Contains(errStrLower, "invalid digest") ||
		strings.Contains(errStrLower, "decrypt") ||
		strings.Contains(errStrLower, "invalid")
}
