package store

import "crypto/x509"

// Truststore defines the interface for certificate container operations
// regardless of file format (PEM, JKS, PKCS12).
type Truststore interface {
	// ReadCertificates reads and parses certificates from the truststore.
	// Returns a slice of x509.Certificate objects and any parsing error.
	ReadCertificates(filepath string, password string) ([]*x509.Certificate, error)
	
	// AddCertificate adds a certificate to the truststore.
	// This will be implemented in future stories for write operations.
	AddCertificate(filepath string, cert *x509.Certificate, password string) error
	
	// RemoveCertificate removes a certificate from the truststore.
	// This will be implemented in future stories for write operations.
	RemoveCertificate(filepath string, cert *x509.Certificate, password string) error
}