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