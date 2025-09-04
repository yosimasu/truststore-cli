package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/truststore/cli/internal/client"
)

// mockCTLogClient implements client.CTLogClient for testing
type mockCTLogClient struct {
	searchResults map[string][]client.CTLogEntry
	certificates  map[int]*x509.Certificate
	searchError   error
	downloadError error
}

func (m *mockCTLogClient) SearchCertificatesByIssuer(issuerName string) ([]client.CTLogEntry, error) {
	if m.searchError != nil {
		return nil, m.searchError
	}

	entries, exists := m.searchResults[issuerName]
	if !exists {
		return []client.CTLogEntry{}, nil
	}

	return entries, nil
}

func (m *mockCTLogClient) DownloadCertificate(id int) (*x509.Certificate, error) {
	if m.downloadError != nil {
		return nil, m.downloadError
	}

	cert, exists := m.certificates[id]
	if !exists {
		return nil, fmt.Errorf("certificate with ID %d not found", id)
	}

	return cert, nil
}

// Helper function to create a test certificate
func createTestCertificate(subject, issuer pkix.Name, isCA bool, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      subject,
		Issuer:       issuer,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		IsCA:         isCA,
	}

	if isCA {
		template.BasicConstraintsValid = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	// Self-signed if no parent provided
	signingCert := &template
	signingKey := privateKey
	if parent != nil && parentKey != nil {
		signingCert = parent
		signingKey = parentKey
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, signingCert, &privateKey.PublicKey, signingKey)
	if err != nil {
		return nil, nil, err
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, privateKey, nil
}

func TestNewChainService(t *testing.T) {
	mockClient := &mockCTLogClient{}
	service := NewChainService(mockClient)

	if service == nil {
		t.Fatal("NewChainService returned nil")
	}
}

func TestCompleteCertificateChain_NilCertificate(t *testing.T) {
	mockClient := &mockCTLogClient{}
	service := NewChainService(mockClient)

	_, err := service.CompleteCertificateChain(nil)
	if err == nil {
		t.Error("Expected error for nil certificate")
	}
	if err.Error() != "certificate cannot be nil" {
		t.Errorf("Expected 'certificate cannot be nil', got %v", err)
	}
}

func TestCompleteCertificateChain_SelfSignedCertificate(t *testing.T) {
	// Create a self-signed certificate
	subject := pkix.Name{CommonName: "Root CA"}
	rootCert, _, err := createTestCertificate(subject, subject, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create test certificate: %v", err)
	}

	mockClient := &mockCTLogClient{}
	service := NewChainService(mockClient)

	chain, err := service.CompleteCertificateChain(rootCert)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(chain) != 1 {
		t.Errorf("Expected chain length 1 for self-signed cert, got %d", len(chain))
	}

	if chain[0] != rootCert {
		t.Error("Chain should contain only the original certificate")
	}
}

func TestCompleteCertificateChain_CompleteChain(t *testing.T) {
	// Create a certificate chain: Root -> Intermediate -> Leaf
	rootSubject := pkix.Name{CommonName: "Root CA"}
	rootCert, rootKey, err := createTestCertificate(rootSubject, rootSubject, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}

	intermSubject := pkix.Name{CommonName: "Intermediate CA"}
	intermCert, intermKey, err := createTestCertificate(intermSubject, rootSubject, true, rootCert, rootKey)
	if err != nil {
		t.Fatalf("Failed to create intermediate certificate: %v", err)
	}

	leafSubject := pkix.Name{CommonName: "example.com"}
	leafCert, _, err := createTestCertificate(leafSubject, intermSubject, false, intermCert, intermKey)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}

	// Set up mock client
	mockClient := &mockCTLogClient{
		searchResults: map[string][]client.CTLogEntry{
			"Intermediate CA": {{ID: 2, CommonName: "Intermediate CA"}},
			"Root CA":         {{ID: 1, CommonName: "Root CA"}},
		},
		certificates: map[int]*x509.Certificate{
			1: rootCert,
			2: intermCert,
		},
	}

	service := NewChainService(mockClient)

	// Start with leaf certificate
	chain, err := service.CompleteCertificateChain(leafCert)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should have leaf -> intermediate -> root
	if len(chain) != 3 {
		t.Errorf("Expected chain length 3, got %d", len(chain))
	}

	if chain[0] != leafCert {
		t.Error("First certificate should be the leaf")
	}

	if chain[1].Subject.CommonName != "Intermediate CA" {
		t.Errorf("Second certificate should be intermediate, got %s", chain[1].Subject.CommonName)
	}

	if chain[2].Subject.CommonName != "Root CA" {
		t.Errorf("Third certificate should be root, got %s", chain[2].Subject.CommonName)
	}
}

func TestCompleteCertificateChain_PartialChain(t *testing.T) {
	// Create only a leaf certificate
	leafSubject := pkix.Name{CommonName: "example.com"}
	leafIssuer := pkix.Name{CommonName: "Missing CA"}
	leafCert, _, err := createTestCertificate(leafSubject, leafIssuer, false, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}

	// Mock client with no results
	mockClient := &mockCTLogClient{
		searchResults: map[string][]client.CTLogEntry{},
		certificates:  map[int]*x509.Certificate{},
	}

	service := NewChainService(mockClient)

	chain, err := service.CompleteCertificateChain(leafCert)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should have only the original certificate
	if len(chain) != 1 {
		t.Errorf("Expected chain length 1, got %d", len(chain))
	}

	if chain[0] != leafCert {
		t.Error("Chain should contain only the original certificate")
	}
}

func TestCompleteCertificateChain_SearchError(t *testing.T) {
	leafSubject := pkix.Name{CommonName: "example.com"}
	leafIssuer := pkix.Name{CommonName: "Test CA"}
	leafCert, _, err := createTestCertificate(leafSubject, leafIssuer, false, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}

	// Mock client that returns search error
	mockClient := &mockCTLogClient{
		searchError: err,
	}

	service := NewChainService(mockClient)

	chain, err := service.CompleteCertificateChain(leafCert)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should return partial chain (just the original certificate)
	if len(chain) != 1 {
		t.Errorf("Expected chain length 1, got %d", len(chain))
	}
}

func TestIsSelfSigned(t *testing.T) {
	service := &chainService{}

	// Create self-signed certificate
	subject := pkix.Name{CommonName: "Root CA"}
	selfSigned, _, err := createTestCertificate(subject, subject, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create self-signed certificate: %v", err)
	}

	if !service.IsSelfSigned(selfSigned) {
		t.Error("Expected true for self-signed certificate")
	}

	// Create non-self-signed certificate (signed by root)
	leafSubject := pkix.Name{CommonName: "example.com"}
	rootSubject := pkix.Name{CommonName: "Root CA"}
	rootCert, rootKey, err := createTestCertificate(rootSubject, rootSubject, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}

	nonSelfSigned, _, err := createTestCertificate(leafSubject, rootSubject, false, rootCert, rootKey)
	if err != nil {
		t.Fatalf("Failed to create non-self-signed certificate: %v", err)
	}

	if service.IsSelfSigned(nonSelfSigned) {
		t.Error("Expected false for non-self-signed certificate")
	}
}

func TestCanVerifyCertificate(t *testing.T) {
	service := &chainService{}

	// Create certificate chain
	rootSubject := pkix.Name{CommonName: "Root CA"}
	rootCert, rootKey, err := createTestCertificate(rootSubject, rootSubject, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}

	leafSubject := pkix.Name{CommonName: "example.com"}
	leafCert, _, err := createTestCertificate(leafSubject, rootSubject, false, rootCert, rootKey)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}

	// Root should be able to verify leaf
	if !service.canVerifyCertificate(leafCert, rootCert) {
		t.Error("Root certificate should be able to verify leaf certificate")
	}

	// Leaf should not be able to verify root
	if service.canVerifyCertificate(rootCert, leafCert) {
		t.Error("Leaf certificate should not be able to verify root certificate")
	}
}

func TestNormalizeDN(t *testing.T) {
	service := &chainService{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "basic normalization",
			input:    "CN=Test CA, O=Test Org",
			expected: "cn=test ca,o=test org",
		},
		{
			name:     "extra spaces",
			input:    "CN = Test CA , O = Test Org",
			expected: "cn=test ca,o=test org",
		},
		{
			name:     "mixed case",
			input:    "cn=TEST ca,o=test ORG",
			expected: "cn=test ca,o=test org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.normalizeDN(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeDN(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDetectCertificateType(t *testing.T) {
	service := &chainService{}

	t.Run("nil certificate returns UNKNOWN", func(t *testing.T) {
		certType := service.DetectCertificateType(nil)
		if certType != UNKNOWN {
			t.Errorf("Expected UNKNOWN for nil certificate, got %s", certType)
		}
	})

	t.Run("self-signed certificate returns SELF_SIGNED", func(t *testing.T) {
		// Create self-signed certificate
		subject := pkix.Name{CommonName: "Root CA"}
		selfSigned, _, err := createTestCertificate(subject, subject, true, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create self-signed certificate: %v", err)
		}

		certType := service.DetectCertificateType(selfSigned)
		if certType != SELF_SIGNED {
			t.Errorf("Expected SELF_SIGNED for self-signed certificate, got %s", certType)
		}
	})

	t.Run("CA-signed certificate returns CA_SIGNED", func(t *testing.T) {
		// Create certificate chain: Root -> Leaf
		rootSubject := pkix.Name{CommonName: "Root CA"}
		rootCert, rootKey, err := createTestCertificate(rootSubject, rootSubject, true, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create root certificate: %v", err)
		}

		leafSubject := pkix.Name{CommonName: "example.com"}
		leafCert, _, err := createTestCertificate(leafSubject, rootSubject, false, rootCert, rootKey)
		if err != nil {
			t.Fatalf("Failed to create leaf certificate: %v", err)
		}

		certType := service.DetectCertificateType(leafCert)
		if certType != CA_SIGNED {
			t.Errorf("Expected CA_SIGNED for CA-signed certificate, got %s", certType)
		}
	})

	t.Run("intermediate CA certificate returns CA_SIGNED", func(t *testing.T) {
		// Create certificate chain: Root -> Intermediate -> Leaf
		rootSubject := pkix.Name{CommonName: "Root CA"}
		rootCert, rootKey, err := createTestCertificate(rootSubject, rootSubject, true, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create root certificate: %v", err)
		}

		intermSubject := pkix.Name{CommonName: "Intermediate CA"}
		intermCert, _, err := createTestCertificate(intermSubject, rootSubject, true, rootCert, rootKey)
		if err != nil {
			t.Fatalf("Failed to create intermediate certificate: %v", err)
		}

		certType := service.DetectCertificateType(intermCert)
		if certType != CA_SIGNED {
			t.Errorf("Expected CA_SIGNED for intermediate CA certificate, got %s", certType)
		}
	})

	t.Run("cross-signed certificate returns CA_SIGNED", func(t *testing.T) {
		// Create two root CAs
		rootSubject1 := pkix.Name{CommonName: "Root CA 1"}
		_, _, err := createTestCertificate(rootSubject1, rootSubject1, true, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create root certificate 1: %v", err)
		}

		rootSubject2 := pkix.Name{CommonName: "Root CA 2"}
		rootCert2, rootKey2, err := createTestCertificate(rootSubject2, rootSubject2, true, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create root certificate 2: %v", err)
		}

		// Create cross-signed certificate: Root CA 1 signed by Root CA 2's key
		crossSigned, _, err := createTestCertificate(rootSubject1, rootSubject2, true, rootCert2, rootKey2)
		if err != nil {
			t.Fatalf("Failed to create cross-signed certificate: %v", err)
		}

		certType := service.DetectCertificateType(crossSigned)
		if certType != CA_SIGNED {
			t.Errorf("Expected CA_SIGNED for cross-signed certificate, got %s", certType)
		}
	})
}

func TestCertificateType_String(t *testing.T) {
	tests := []struct {
		certType CertificateType
		expected string
	}{
		{SELF_SIGNED, "SELF_SIGNED"},
		{CA_SIGNED, "CA_SIGNED"},
		{UNKNOWN, "UNKNOWN"},
		{CertificateType(999), "UNKNOWN"}, // Invalid type should return UNKNOWN
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.certType.String()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestCompleteCertificateChain_SelfSignedOptimization(t *testing.T) {
	// Create a self-signed certificate
	subject := pkix.Name{CommonName: "Root CA"}
	rootCert, _, err := createTestCertificate(subject, subject, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create test certificate: %v", err)
	}

	// Create a mock client that would fail if called (to verify CT log calls are skipped)
	mockClient := &mockCTLogClient{
		searchError: fmt.Errorf("CT log should not be called for self-signed certificates"),
	}
	service := NewChainService(mockClient)

	chain, err := service.CompleteCertificateChain(rootCert)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(chain) != 1 {
		t.Errorf("Expected chain length 1 for self-signed cert, got %d", len(chain))
	}

	if chain[0] != rootCert {
		t.Error("Chain should contain only the original certificate")
	}
}

func TestCompleteCertificateChain_BackwardCompatibility(t *testing.T) {
	// This test ensures that existing IsSelfSigned behavior is preserved
	service := &chainService{}

	// Create self-signed certificate
	subject := pkix.Name{CommonName: "Root CA"}
	selfSigned, _, err := createTestCertificate(subject, subject, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create self-signed certificate: %v", err)
	}

	// Test that IsSelfSigned still works as before
	if !service.IsSelfSigned(selfSigned) {
		t.Error("IsSelfSigned should return true for self-signed certificate")
	}

	// Test that detection result matches IsSelfSigned result
	certType := service.DetectCertificateType(selfSigned)
	isSelfSigned := service.IsSelfSigned(selfSigned)

	if (certType == SELF_SIGNED) != isSelfSigned {
		t.Errorf("DetectCertificateType and IsSelfSigned results should be consistent")
	}
}

// Helper function to create malformed certificate for testing
func createMalformedCertificate() *x509.Certificate {
	// Create a certificate with invalid signature to test edge cases
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Malformed Cert"},
		Issuer:       pkix.Name{CommonName: "Malformed Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	// This creates a certificate without proper signature validation
	return &template
}

func TestDetectCertificateType_EdgeCases(t *testing.T) {
	service := &chainService{}

	t.Run("certificate with matching subject/issuer but invalid signature", func(t *testing.T) {
		malformed := createMalformedCertificate()

		certType := service.DetectCertificateType(malformed)
		// Should be CA_SIGNED because signature validation fails
		if certType != CA_SIGNED {
			t.Errorf("Expected CA_SIGNED for certificate with invalid signature, got %s", certType)
		}
	})

	t.Run("certificate with empty subject and issuer", func(t *testing.T) {
		// Create certificate with empty names - this needs to be self-signed to work properly
		emptyName := pkix.Name{}
		cert, _, err := createTestCertificate(emptyName, emptyName, true, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create certificate with empty names: %v", err)
		}

		certType := service.DetectCertificateType(cert)
		// Should be SELF_SIGNED because subject equals issuer (both empty) and signature validates
		if certType != SELF_SIGNED {
			t.Errorf("Expected SELF_SIGNED for certificate with empty matching names, got %s", certType)
		}
	})
}

// Benchmark tests to ensure detection adds minimal overhead (<10ms requirement)
func BenchmarkDetectCertificateType_SelfSigned(b *testing.B) {
	service := &chainService{}
	subject := pkix.Name{CommonName: "Root CA"}
	cert, _, err := createTestCertificate(subject, subject, true, nil, nil)
	if err != nil {
		b.Fatalf("Failed to create test certificate: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.DetectCertificateType(cert)
	}
}

func BenchmarkDetectCertificateType_CASigned(b *testing.B) {
	service := &chainService{}

	// Create certificate chain: Root -> Leaf
	rootSubject := pkix.Name{CommonName: "Root CA"}
	rootCert, rootKey, err := createTestCertificate(rootSubject, rootSubject, true, nil, nil)
	if err != nil {
		b.Fatalf("Failed to create root certificate: %v", err)
	}

	leafSubject := pkix.Name{CommonName: "example.com"}
	leafCert, _, err := createTestCertificate(leafSubject, rootSubject, false, rootCert, rootKey)
	if err != nil {
		b.Fatalf("Failed to create leaf certificate: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.DetectCertificateType(leafCert)
	}
}

func BenchmarkCompleteCertificateChain_SelfSignedOptimization(b *testing.B) {
	// Create a self-signed certificate
	subject := pkix.Name{CommonName: "Root CA"}
	rootCert, _, err := createTestCertificate(subject, subject, true, nil, nil)
	if err != nil {
		b.Fatalf("Failed to create test certificate: %v", err)
	}

	// Mock client (should not be called for self-signed)
	mockClient := &mockCTLogClient{}
	service := NewChainService(mockClient)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.CompleteCertificateChain(rootCert)
	}
}

func TestCompleteCertificateChain_CycleDetection(t *testing.T) {
	// Create certificates that would form a cycle
	cert1Subject := pkix.Name{CommonName: "Cert1"}
	cert2Subject := pkix.Name{CommonName: "Cert2"}
	
	cert1, cert1Key, err := createTestCertificate(cert1Subject, cert2Subject, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create cert1: %v", err)
	}

	cert2, _, err := createTestCertificate(cert2Subject, cert1Subject, true, cert1, cert1Key)
	if err != nil {
		t.Fatalf("Failed to create cert2: %v", err)
	}

	// Mock client that creates a cycle
	mockClient := &mockCTLogClient{
		searchResults: map[string][]client.CTLogEntry{
			"Cert2": {{ID: 2, CommonName: "Cert2"}},
			"Cert1": {{ID: 1, CommonName: "Cert1"}},
		},
		certificates: map[int]*x509.Certificate{
			1: cert1,
			2: cert2,
		},
	}

	service := NewChainService(mockClient)
	
	// This should not hang due to cycle detection
	chain, err := service.CompleteCertificateChain(cert1)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	
	// Should stop when cycle is detected
	if len(chain) > 10 {
		t.Errorf("Chain too long, cycle detection may have failed: %d", len(chain))
	}
}

// Tests for FindRootCertificate function
func TestFindRootCertificate_EmptyChain(t *testing.T) {
	service := &chainService{}
	
	result := service.FindRootCertificate([]*x509.Certificate{})
	if result != nil {
		t.Error("Expected nil for empty chain")
	}
}

func TestFindRootCertificate_SingleCertificate(t *testing.T) {
	service := &chainService{}
	
	// Create a single certificate
	subject := pkix.Name{CommonName: "Test Cert"}
	cert, _, err := createTestCertificate(subject, subject, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create test certificate: %v", err)
	}
	
	chain := []*x509.Certificate{cert}
	result := service.FindRootCertificate(chain)
	
	if result != cert {
		t.Error("Expected the single certificate to be returned")
	}
}

func TestFindRootCertificate_SelfSignedRoot(t *testing.T) {
	service := &chainService{}
	
	// Create a chain: Root -> Intermediate -> Leaf
	rootSubject := pkix.Name{CommonName: "Root CA"}
	rootCert, rootKey, err := createTestCertificate(rootSubject, rootSubject, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}
	
	intermSubject := pkix.Name{CommonName: "Intermediate CA"}
	intermCert, intermKey, err := createTestCertificate(intermSubject, rootSubject, true, rootCert, rootKey)
	if err != nil {
		t.Fatalf("Failed to create intermediate certificate: %v", err)
	}
	
	leafSubject := pkix.Name{CommonName: "example.com"}
	leafCert, _, err := createTestCertificate(leafSubject, intermSubject, false, intermCert, intermKey)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}
	
	chain := []*x509.Certificate{leafCert, intermCert, rootCert}
	result := service.FindRootCertificate(chain)
	
	if result != rootCert {
		t.Errorf("Expected root certificate to be selected, got %s", result.Subject.CommonName)
	}
}

func TestFindRootCertificate_NoSelfSignedFallback(t *testing.T) {
	service := &chainService{}
	
	// Create a chain with no self-signed certificates (incomplete chain)
	// All certificates are CA-signed but the actual root is missing
	rootSubject := pkix.Name{CommonName: "Missing Root CA"}
	rootCert, rootKey, err := createTestCertificate(rootSubject, rootSubject, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}
	
	// Create intermediate signed by the root
	intermSubject := pkix.Name{CommonName: "Intermediate CA"}
	intermCert, intermKey, err := createTestCertificate(intermSubject, rootSubject, true, rootCert, rootKey)
	if err != nil {
		t.Fatalf("Failed to create intermediate certificate: %v", err)
	}
	
	// Create leaf signed by intermediate
	leafSubject := pkix.Name{CommonName: "example.com"}
	leafCert, _, err := createTestCertificate(leafSubject, intermSubject, false, intermCert, intermKey)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}
	
	// Only include intermediate and leaf in chain (missing root)
	chain := []*x509.Certificate{leafCert, intermCert}
	result := service.FindRootCertificate(chain)
	
	// Should select intermediate CA as it can verify the leaf and has CA capabilities
	if result != intermCert {
		t.Errorf("Expected intermediate certificate to be selected as fallback root, got %s", result.Subject.CommonName)
	}
}

func TestFindRootCertificate_MultipleSelfSigned(t *testing.T) {
	service := &chainService{}
	
	// Create two self-signed certificates with different validity periods
	subject1 := pkix.Name{CommonName: "Root CA 1"}
	shortValidityCert, _, err := createTestCertificate(subject1, subject1, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create short validity certificate: %v", err)
	}
	
	// Modify the certificate to have a longer validity period
	subject2 := pkix.Name{CommonName: "Root CA 2"}
	longValidityCert, _, err := createLongValidityCertificate(subject2, subject2, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create long validity certificate: %v", err)
	}
	
	chain := []*x509.Certificate{shortValidityCert, longValidityCert}
	result := service.FindRootCertificate(chain)
	
	// Should select the one with longer validity period as tie-breaker
	if result != longValidityCert {
		t.Errorf("Expected certificate with longer validity to be selected, got %s", result.Subject.CommonName)
	}
}

func TestFindRootCertificate_VerificationCount(t *testing.T) {
	service := &chainService{}
	
	// Create a complex chain with cross-signing
	rootSubject1 := pkix.Name{CommonName: "Root CA 1"}
	rootCert1, rootKey1, err := createTestCertificate(rootSubject1, rootSubject1, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create root certificate 1: %v", err)
	}
	
	rootSubject2 := pkix.Name{CommonName: "Root CA 2"}
	rootCert2, _, err := createTestCertificate(rootSubject2, rootSubject2, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create root certificate 2: %v", err)
	}
	
	// Create intermediate signed by root1
	intermSubject := pkix.Name{CommonName: "Intermediate CA"}
	intermCert, intermKey, err := createTestCertificate(intermSubject, rootSubject1, true, rootCert1, rootKey1)
	if err != nil {
		t.Fatalf("Failed to create intermediate certificate: %v", err)
	}
	
	// Create leaf signed by intermediate
	leafSubject := pkix.Name{CommonName: "example.com"}
	leafCert, _, err := createTestCertificate(leafSubject, intermSubject, false, intermCert, intermKey)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}
	
	// Root1 can verify intermediate, intermediate can verify leaf
	// Root2 is isolated and can't verify anything in this chain
	chain := []*x509.Certificate{leafCert, intermCert, rootCert1, rootCert2}
	result := service.FindRootCertificate(chain)
	
	// Should select rootCert1 as it can verify more certificates in the chain
	if result != rootCert1 {
		t.Errorf("Expected root certificate 1 to be selected (can verify more certs), got %s", result.Subject.CommonName)
	}
}

func TestCountVerifiableCertificates(t *testing.T) {
	service := &chainService{}
	
	// Create a simple chain: Root -> Intermediate -> Leaf
	rootSubject := pkix.Name{CommonName: "Root CA"}
	rootCert, rootKey, err := createTestCertificate(rootSubject, rootSubject, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}
	
	intermSubject := pkix.Name{CommonName: "Intermediate CA"}
	intermCert, intermKey, err := createTestCertificate(intermSubject, rootSubject, true, rootCert, rootKey)
	if err != nil {
		t.Fatalf("Failed to create intermediate certificate: %v", err)
	}
	
	leafSubject := pkix.Name{CommonName: "example.com"}
	leafCert, _, err := createTestCertificate(leafSubject, intermSubject, false, intermCert, intermKey)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}
	
	chain := []*x509.Certificate{leafCert, intermCert, rootCert}
	
	// Root should be able to verify intermediate (1 cert)
	rootCount := service.countVerifiableCertificates(rootCert, chain)
	if rootCount != 1 {
		t.Errorf("Expected root to verify 1 certificate, got %d", rootCount)
	}
	
	// Intermediate should be able to verify leaf (1 cert)
	intermCount := service.countVerifiableCertificates(intermCert, chain)
	if intermCount != 1 {
		t.Errorf("Expected intermediate to verify 1 certificate, got %d", intermCount)
	}
	
	// Leaf should not be able to verify any certificates (0 certs)
	leafCount := service.countVerifiableCertificates(leafCert, chain)
	if leafCount != 0 {
		t.Errorf("Expected leaf to verify 0 certificates, got %d", leafCount)
	}
}

// Helper function to create test certificate with longer validity period
func createLongValidityCertificate(subject, issuer pkix.Name, isCA bool, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template with longer validity (2 years instead of 1)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      subject,
		Issuer:       issuer,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(2 * 365 * 24 * time.Hour), // 2 years
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		IsCA:         isCA,
	}

	if isCA {
		template.BasicConstraintsValid = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	// Self-signed if no parent provided
	signingCert := &template
	signingKey := privateKey
	if parent != nil && parentKey != nil {
		signingCert = parent
		signingKey = parentKey
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, signingCert, &privateKey.PublicKey, signingKey)
	if err != nil {
		return nil, nil, err
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, privateKey, nil
}
