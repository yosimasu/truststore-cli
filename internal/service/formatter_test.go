package service

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestNewCertificateFormatter(t *testing.T) {
	formatter := NewCertificateFormatter()
	if formatter == nil {
		t.Fatal("Expected formatter to be non-nil")
	}

	// Verify it implements the interface
	var _ CertificateFormatter = formatter
}

func TestFormatCertificateChain(t *testing.T) {
	formatter := NewCertificateFormatter()

	// Create test certificates
	now := time.Now()
	cert1 := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "example.org",
			Organization: []string{"Example Corp"},
			Country:      []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName:   "Example CA",
			Organization: []string{"Example CA Corp"},
			Country:      []string{"US"},
		},
		SerialNumber:       big.NewInt(12345),
		NotBefore:          now.Add(-24 * time.Hour),
		NotAfter:           now.Add(365 * 24 * time.Hour),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	cert2 := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "Example CA",
			Organization: []string{"Example CA Corp"},
			Country:      []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName:   "Root CA",
			Organization: []string{"Root CA Corp"},
			Country:      []string{"US"},
		},
		SerialNumber:       big.NewInt(67890),
		NotBefore:          now.Add(-365 * 24 * time.Hour),
		NotAfter:           now.Add(2 * 365 * 24 * time.Hour),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	tests := []struct {
		name     string
		certs    []*x509.Certificate
		source   string
		contains []string
	}{
		{
			name:   "empty certificate chain",
			certs:  []*x509.Certificate{},
			source: "example.org",
			contains: []string{
				"No certificates found for example.org",
			},
		},
		{
			name:   "single certificate",
			certs:  []*x509.Certificate{cert1},
			source: "example.org",
			contains: []string{
				"🔒 Certificate chain for example.org:",
				"📜 Certificate:",
				"Subject: CN=example.org, O=Example Corp, C=US",
				"Issuer:  CN=Example CA, O=Example CA Corp, C=US",
				"Serial:  12345",
				"✅ Valid",
				"Algorithm: SHA256-RSA",
			},
		},
		{
			name:   "certificate chain",
			certs:  []*x509.Certificate{cert1, cert2},
			source: "example.org:443",
			contains: []string{
				"🔒 Certificate chain for example.org:443:",
				"📜 Certificate 1 of 2:",
				"📜 Certificate 2 of 2:",
				"Subject: CN=example.org, O=Example Corp, C=US",
				"Subject: CN=Example CA, O=Example CA Corp, C=US",
				"Issuer:  CN=Root CA, O=Root CA Corp, C=US",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatter.FormatCertificateChain(tt.certs, tt.source)

			for _, expected := range tt.contains {
				if !strings.Contains(result, expected) {
					t.Errorf("FormatCertificateChain() result missing %q\nGot: %s", expected, result)
				}
			}
		})
	}
}

func TestFormatName(t *testing.T) {
	formatter := &certificateFormatter{}

	tests := []struct {
		name     string
		subject  pkix.Name
		expected string
	}{
		{
			name: "full name",
			subject: pkix.Name{
				CommonName:         "example.org",
				OrganizationalUnit: []string{"IT Department"},
				Organization:       []string{"Example Corp"},
				Locality:           []string{"San Francisco"},
				Province:           []string{"California"},
				Country:            []string{"US"},
			},
			expected: "CN=example.org, OU=IT Department, O=Example Corp, L=San Francisco, ST=California, C=US",
		},
		{
			name: "common name only",
			subject: pkix.Name{
				CommonName: "example.org",
			},
			expected: "CN=example.org",
		},
		{
			name:     "empty name",
			subject:  pkix.Name{},
			expected: "<empty>",
		},
		{
			name: "multiple organizations",
			subject: pkix.Name{
				CommonName:   "example.org",
				Organization: []string{"Example Corp", "Subsidiary"},
			},
			expected: "CN=example.org, O=Example Corp, O=Subsidiary",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatter.formatName(tt.subject)
			if result != tt.expected {
				t.Errorf("formatName() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestFormatSerialNumber(t *testing.T) {
	formatter := &certificateFormatter{}

	tests := []struct {
		name     string
		serial   string
		expected string
	}{
		{
			name:     "short serial",
			serial:   "12345",
			expected: "12345",
		},
		{
			name:     "long serial gets truncated",
			serial:   "123456789012345678901234567890123456789012345678901234567890",
			expected: "12345678901234567890123456789012...",
		},
		{
			name:     "exact 32 character serial",
			serial:   "12345678901234567890123456789012",
			expected: "12345678901234567890123456789012",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatter.formatSerialNumber(tt.serial)
			if result != tt.expected {
				t.Errorf("formatSerialNumber() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestFormatDate(t *testing.T) {
	formatter := &certificateFormatter{}

	// Test with a known date
	testTime := time.Date(2024, 12, 25, 15, 30, 45, 0, time.UTC)
	result := formatter.formatDate(testTime)

	expected := "2024-12-25 15:30:45 UTC"
	if result != expected {
		t.Errorf("formatDate() = %q, want %q", result, expected)
	}
}

func TestCertificateValidityStatus(t *testing.T) {
	formatter := &certificateFormatter{}
	now := time.Now()

	tests := []struct {
		name       string
		notBefore  time.Time
		notAfter   time.Time
		wantStatus string
	}{
		{
			name:       "valid certificate",
			notBefore:  now.Add(-24 * time.Hour),
			notAfter:   now.Add(365 * 24 * time.Hour),
			wantStatus: "✅ Valid",
		},
		{
			name:       "expired certificate",
			notBefore:  now.Add(-365 * 24 * time.Hour),
			notAfter:   now.Add(-24 * time.Hour),
			wantStatus: "❌ Expired",
		},
		{
			name:       "not yet valid certificate",
			notBefore:  now.Add(24 * time.Hour),
			notAfter:   now.Add(365 * 24 * time.Hour),
			wantStatus: "⚠️  Not yet valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				Subject:            pkix.Name{CommonName: "test.example.org"},
				Issuer:             pkix.Name{CommonName: "Test CA"},
				SerialNumber:       big.NewInt(123),
				NotBefore:          tt.notBefore,
				NotAfter:           tt.notAfter,
				SignatureAlgorithm: x509.SHA256WithRSA,
			}

			result := formatter.formatSingleCertificate(cert, 1, 1)

			if !strings.Contains(result, tt.wantStatus) {
				t.Errorf("formatSingleCertificate() result missing %q\nGot: %s", tt.wantStatus, result)
			}
		})
	}
}
