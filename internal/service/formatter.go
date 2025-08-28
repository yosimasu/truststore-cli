package service

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"time"
)

// CertificateFormatter handles formatting certificates for display
type CertificateFormatter interface {
	FormatCertificateChain(certs []*x509.Certificate, source string) string
}

// certificateFormatter implements CertificateFormatter
type certificateFormatter struct{}

// NewCertificateFormatter creates a new certificate formatter
func NewCertificateFormatter() CertificateFormatter {
	return &certificateFormatter{}
}

// FormatCertificateChain formats a certificate chain for human-readable display
func (f *certificateFormatter) FormatCertificateChain(certs []*x509.Certificate, source string) string {
	if len(certs) == 0 {
		return fmt.Sprintf("No certificates found for %s\n", source)
	}

	var result strings.Builder

	// Header
	result.WriteString(fmt.Sprintf("🔒 Certificate chain for %s:\n\n", source))

	// Format each certificate in the chain
	for i, cert := range certs {
		result.WriteString(f.formatSingleCertificate(cert, i+1, len(certs)))
		if i < len(certs)-1 {
			result.WriteString("\n")
		}
	}

	return result.String()
}

// formatSingleCertificate formats a single certificate
func (f *certificateFormatter) formatSingleCertificate(cert *x509.Certificate, index, total int) string {
	var result strings.Builder

	// Certificate header
	if total == 1 {
		result.WriteString("📜 Certificate:\n")
	} else {
		result.WriteString(fmt.Sprintf("📜 Certificate %d of %d:\n", index, total))
	}

	// Subject
	subject := f.formatName(cert.Subject)
	result.WriteString(fmt.Sprintf("   Subject: %s\n", subject))

	// Issuer
	issuer := f.formatName(cert.Issuer)
	result.WriteString(fmt.Sprintf("   Issuer:  %s\n", issuer))

	// Serial Number
	result.WriteString(fmt.Sprintf("   Serial:  %s\n", f.formatSerialNumber(cert.SerialNumber.String())))

	// Validity period
	result.WriteString(fmt.Sprintf("   Valid:   %s to %s\n",
		f.formatDate(cert.NotBefore),
		f.formatDate(cert.NotAfter)))

	// Validity status
	now := time.Now()
	if now.Before(cert.NotBefore) {
		result.WriteString("   Status:  ⚠️  Not yet valid\n")
	} else if now.After(cert.NotAfter) {
		result.WriteString("   Status:  ❌ Expired\n")
	} else {
		result.WriteString("   Status:  ✅ Valid\n")
	}

	// Algorithm information
	result.WriteString(fmt.Sprintf("   Algorithm: %s\n", cert.SignatureAlgorithm.String()))

	return result.String()
}

// formatName formats a pkix.Name into a readable string
func (f *certificateFormatter) formatName(name pkix.Name) string {
	var parts []string

	if name.CommonName != "" {
		parts = append(parts, fmt.Sprintf("CN=%s", name.CommonName))
	}

	for _, ou := range name.OrganizationalUnit {
		parts = append(parts, fmt.Sprintf("OU=%s", ou))
	}

	for _, o := range name.Organization {
		parts = append(parts, fmt.Sprintf("O=%s", o))
	}

	for _, l := range name.Locality {
		parts = append(parts, fmt.Sprintf("L=%s", l))
	}

	for _, s := range name.Province {
		parts = append(parts, fmt.Sprintf("ST=%s", s))
	}

	for _, c := range name.Country {
		parts = append(parts, fmt.Sprintf("C=%s", c))
	}

	if len(parts) == 0 {
		return "<empty>"
	}

	return strings.Join(parts, ", ")
}

// formatSerialNumber formats a serial number for display
func (f *certificateFormatter) formatSerialNumber(serial string) string {
	// Truncate very long serial numbers for readability
	if len(serial) > 32 {
		return serial[:32] + "..."
	}
	return serial
}

// formatDate formats a time for certificate validity display
func (f *certificateFormatter) formatDate(t time.Time) string {
	return t.Format("2006-01-02 15:04:05 MST")
}
