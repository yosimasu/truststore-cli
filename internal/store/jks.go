package store

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
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

// AddCertificate adds a certificate to the JKS file
func (h *JksHandler) AddCertificate(filepath string, cert *x509.Certificate, password string) error {
	if password == "" {
		return fmt.Errorf("password required for JKS file operations")
	}

	// Generate alias for the certificate
	alias := generateCertificateAlias()

	// Check if file exists
	var ks keystore.KeyStore
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		// Create new keystore
		ks = keystore.New()
	} else {
		// Load existing keystore
		ks = keystore.New()
		file, err := os.Open(filepath)
		if err != nil {
			return fmt.Errorf("failed to open JKS file %s: %w", filepath, err)
		}
		
		err = ks.Load(file, []byte(password))
		file.Close()
		if err != nil {
			if isPasswordError(err) {
				return fmt.Errorf("incorrect password for JKS file %s: provide the correct password", filepath)
			}
			return fmt.Errorf("failed to load JKS file %s: %w", filepath, err)
		}
	}

	// Create trusted certificate entry
	certEntry := keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate: keystore.Certificate{
			Type:    "X509",
			Content: cert.Raw,
		},
	}

	// Add certificate to keystore
	err := ks.SetTrustedCertificateEntry(alias, certEntry)
	if err != nil {
		return fmt.Errorf("failed to add certificate to keystore: %w", err)
	}

	// Save keystore to file
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create JKS file %s: %w", filepath, err)
	}
	defer file.Close()

	err = ks.Store(file, []byte(password))
	if err != nil {
		return fmt.Errorf("failed to save JKS file %s: %w", filepath, err)
	}

	return nil
}

// RemoveCertificate removes a certificate from the JKS file (placeholder for future stories)
func (h *JksHandler) RemoveCertificate(filepath string, cert *x509.Certificate, password string) error {
	return fmt.Errorf("RemoveCertificate not implemented for JKS files - will be added in future stories")
}

// generateCertificateAlias creates a unique alias for a certificate
func generateCertificateAlias() string {
	return fmt.Sprintf("cert-%d", time.Now().UnixNano())
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
